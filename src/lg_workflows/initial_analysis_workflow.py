"""
Initial Incident and CVE Analysis Workflow

LangGraph workflow for the initial incident and CVE analysis stage.
Takes an IncidentVulnerabilityReport and performs additional investigation
using available tools before submitting a structured analysis.
"""

from copy import deepcopy
import logging
from typing import Dict, Any, List, Optional, TypedDict, Annotated
from datetime import datetime
import json

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import BaseTool

from src.models.incident import IncidentData
from src.tools.lc_tools.tool_manager import get_tool, get_tool_function

from ..models.application_config import ApplicationConfig
from ..models.stage_config import Stage, StageConfig
from ..tools.nvd_tool import IncidentVulnerabilityReport
from ..tools.lc_tools.initial_analysis_stage_tools import initial_analysis_stage_tools
from ..tools.mcp_client_manager import MCPClientManager
from ..prompts.initial_analysis_system_prompt import INITIAL_ANALYSIS_SYSTEM_PROMPT
from ..prompts.initial_analysis_user_prompt import INITIAL_ANALYSIS_USER_PROMPT
from ..core.llm_factory import LLMFactory

logger = logging.getLogger(__name__)


class InitialAnalysisState(TypedDict):
    """State for the initial analysis workflow"""

    # Input data
    incident_vulnerability_report: IncidentVulnerabilityReport

    # Workflow state
    messages: Annotated[List, "Messages in the conversation"]
    iteration_count: int
    max_iterations: int

    # Tools and configuration
    available_tools: List[BaseTool]
    llm_config: Dict[str, Any]

    # Results
    analysis_complete: bool
    final_analysis: Optional[Dict[str, Any]]
    error_message: Optional[str]

    # Workflow control flags
    force_final_mode: bool  # When True, only final answer tool is available
    pending_tool_execution: bool  # When True, need to execute tools before forcing final
    retry_count: int  # Track retries for non-tool responses
    max_retries: int  # Maximum retries for non-tool responses


class InitialAnalysisWorkflow:
    """LangGraph workflow for initial incident and CVE analysis"""

    def __init__(self, config: ApplicationConfig, mcp_client_manager: MCPClientManager):
        self.config = config
        self.mcp_client_manager = mcp_client_manager
        self.stage_config = config.get_stage_config(
            Stage.INITIAL_INCIDENT_AND_CVE_ANALYSIS
        )

        if not self.stage_config:
            raise ValueError("Initial incident and CVE analysis stage not configured")

        self.llm_factory = LLMFactory()
        self.logger = logging.getLogger(__name__)

        # Build the workflow graph
        self.graph = self._build_graph()

    def _build_graph(self):
        """Build the LangGraph workflow"""

        # Create the state graph
        workflow = StateGraph(InitialAnalysisState)

        # Add nodes
        workflow.add_node("initialize", self._initialize_analysis)
        workflow.add_node("agent", self._run_agent)
        workflow.add_node("tools", self._create_tool_node())
        workflow.add_node("prepare_final_mode", self._prepare_final_mode)
        workflow.add_node("force_final_analysis", self._force_final_analysis)
        workflow.add_node("retry_agent", self._retry_agent)
        workflow.add_node("finalize", self._finalize_analysis)

        # Add edges
        workflow.set_entry_point("initialize")
        workflow.add_edge("initialize", "agent")
        workflow.add_conditional_edges(
            "agent",
            self._should_continue,
            {
                "continue": "tools",
                "end": "finalize",
                "error": "finalize",
                "force_final": "prepare_final_mode",
                "retry": "retry_agent",
            },
        )
        workflow.add_edge("tools", "agent")
        workflow.add_edge("prepare_final_mode", "force_final_analysis")
        workflow.add_edge("force_final_analysis", "tools")
        workflow.add_edge("retry_agent", "agent")
        workflow.add_edge("finalize", END)

        return workflow.compile()

    async def _initialize_analysis(
        self, state: InitialAnalysisState
    ) -> InitialAnalysisState:
        """Initialize the analysis workflow"""
        self.logger.info("Initializing initial analysis workflow")

        # Get available tools
        available_tools = []

        # Add available tools by config
        if self.stage_config.available_tools:
            for tool_name in self.stage_config.available_tools:
                tool = get_tool(tool_name)
                if tool:
                    available_tools.append(tool)
                    self.logger.info(f"Added tool: {tool.name}")
                else:
                    self.logger.warning(f"Tool {tool_name} not found in config")

        # Add MCP tools if available
        if self.stage_config.available_mcp_servers:
            for server_name in self.stage_config.available_mcp_servers:
                try:
                    mcp_tools = await self.mcp_client_manager.get_langchain_tools(
                        server_name
                    )
                    available_tools.extend(mcp_tools)
                    self.logger.info(
                        f"Added {len(mcp_tools)} tools from MCP server: {server_name}"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to get tools from MCP server {server_name}: {e}"
                    )

        # Verify final answer tool is available
        final_answer_tool_found = any(
            tool.name == "submit_initial_analysis_final_answer" 
            for tool in available_tools
        )
        if not final_answer_tool_found:
            raise ValueError("submit_initial_analysis_final_answer tool not found in available tools")

        # Format the incident data for the prompt
        report = state["incident_vulnerability_report"]

        # Format affected assets
        affected_assets_info = []
        for software_report in report.software_reports:
            software = software_report.software
            affected_assets_info.append(
                f"- **{software.name} {software.version}**: "
                f"{software_report.total_count} vulnerabilities "
                f"(Critical: {software_report.critical_count}, "
                f"High: {software_report.high_count}, "
                f"Medium: {software_report.medium_count}, "
                f"Low: {software_report.low_count})"
            )

        # Create a simplified vulnerability report for the prompt
        vulnerability_summary = {
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_vulnerabilities": report.critical_vulnerabilities,
            "high_vulnerabilities": report.high_vulnerabilities,
            "medium_vulnerabilities": report.medium_vulnerabilities,
            "low_vulnerabilities": report.low_vulnerabilities,
            "most_vulnerable_software": (
                {
                    "name": report.most_vulnerable_software.name,
                    "version": report.most_vulnerable_software.version,
                }
                if report.most_vulnerable_software
                else None
            ),
            "software_summary": affected_assets_info,
            "recommendations": report.recommendations,
        }

        # Create initial messages
        system_message = SystemMessage(content=INITIAL_ANALYSIS_SYSTEM_PROMPT)

        user_prompt = INITIAL_ANALYSIS_USER_PROMPT.format(
            incident_id=report.incident_id,
            timestamp=datetime.now().isoformat(),
            title="Security Incident Analysis",  # We don't have this in the report
            description="Incident requiring vulnerability analysis",  # We don't have this in the report
            initial_findings="Pre-processed vulnerability data available",
            affected_assets_info="\n".join(affected_assets_info),
            observed_ttps_info="See incident data for TTP details",  # We don't have this in the report
            indicators_info="See incident data for IOC details",  # We don't have this in the report
            vulnerability_report=json.dumps(vulnerability_summary, indent=2),
        )

        user_message = HumanMessage(content=user_prompt)

        # Update state
        state.update(
            {
                "messages": [system_message, user_message],
                "iteration_count": 0,
                "max_iterations": self.stage_config.max_iterations or 5,
                "available_tools": available_tools,
                "llm_config": self.stage_config.llm_config.model_dump(),
                "analysis_complete": False,
                "final_analysis": None,
                "error_message": None,
                "force_final_mode": False,
                "pending_tool_execution": False,
                "retry_count": 0,
                "max_retries": 3,
            }
        )

        self.logger.info(
            f"Initialized with {len(available_tools)} tools, max iterations: {state['max_iterations']}"
        )
        return state

    async def _run_agent(self, state: InitialAnalysisState) -> InitialAnalysisState:
        """Run the LLM agent"""
        self.logger.info(f"Running agent (iteration {state['iteration_count']})")

        try:
            # Create LLM instance
            llm = self.llm_factory.create_llm(self.stage_config.llm_config)

            # Bind tools to LLM
            llm_with_tools = llm.bind_tools(state["available_tools"])

            # Get response from LLM
            response = await llm_with_tools.ainvoke(state["messages"])

            # Add response to messages
            state["messages"].append(response)

            # Increment iteration count
            state["iteration_count"] += 1

            self.logger.info(
                f"Agent response received, iteration {state['iteration_count']}"
            )

        except Exception as e:
            self.logger.error(f"Error running agent: {e}")
            state["error_message"] = f"Agent error: {str(e)}"
            state["analysis_complete"] = True

        return state
    
    async def _retry_agent(self, state: InitialAnalysisState) -> InitialAnalysisState:
        """Retry the agent when it fails to call tools"""
        state["retry_count"] += 1

        # Check if we've exceeded max iterations during retries
        if state["iteration_count"] >= state["max_iterations"]:
            self.logger.warning("Cannot retry - already at max iterations")
            return state

        self.logger.info(f"Retrying agent due to missing tool calls (attempt {state['retry_count']})")

        # Add a system message to enforce tool calling
        if state.get("force_final_mode"):
            retry_message = SystemMessage(
                content="""You MUST call the submit_initial_analysis_final_answer tool. 
                You cannot respond with text only. Please call the tool with your final analysis."""
            )
        else:
            retry_message = SystemMessage(
                content="""You must call one of the available tools. You cannot respond with text only. 
                Please select an appropriate tool to continue your analysis or call the submit_initial_analysis_final_answer tool if you are ready to conclude."""
            )

        state["messages"].append(retry_message)

        return state

    def _should_continue(self, state: InitialAnalysisState) -> str:
        """Determine whether to continue with tools or end"""

        # Check for errors
        if state.get("error_message"):
            return "error"

        # Check if analysis is complete
        if state.get("analysis_complete"):
            return "end"

        # Check iteration limit
        if state["iteration_count"] >= state["max_iterations"]:
            self.logger.warning(
                f"Reached maximum iterations ({state['max_iterations']})"
            )
            # Check if there are pending tool calls to execute first
            last_message = state["messages"][-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                # Check if we've already executed tools for this max iteration
                if not state.get("pending_tool_execution"):
                    state["pending_tool_execution"] = True
                    return "continue"  # Execute pending tools first
                else:
                    # We've already executed tools, now force final
                    return "force_final"
            else:
                return "force_final"

        # Check if the last message has tool calls
        last_message = state["messages"][-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            # Check if it's the final answer tool
            for tool_call in last_message.tool_calls:
                if tool_call["name"] == "submit_initial_analysis_final_answer":
                    # Don't immediately return "end" - let tool execution happen first
                    # The tool executor will set analysis_complete if successful
                    return "continue"  
            return "continue"
        else:
            # AI responded without tool calls - this is not allowed
            if state["retry_count"] >= state["max_retries"]:
                self.logger.error(
                    f"AI failed to call tools after {state['max_retries']} retries"
                )
                state["error_message"] = "AI consistently failed to call required tools"
                return "error"
            else:
                self.logger.warning(
                    f"AI responded without tool calls (retry {state['retry_count'] + 1}/{state['max_retries']})"
                )
                return "retry"
            
    async def _prepare_final_mode(
        self, state: InitialAnalysisState
    ) -> InitialAnalysisState:
        """Prepare for final mode by removing all tools except final answer tool"""
        self.logger.info("Preparing final mode - removing all tools except final answer tool")

        # Find the final answer tool
        final_answer_tool = None
        for tool in state["available_tools"]:
            if tool.name == "submit_initial_analysis_final_answer":
                final_answer_tool = tool
                break

        if not final_answer_tool:
            self.logger.error("submit_initial_analysis_final_answer tool not found")
            state["error_message"] = "Final answer tool not available"
            return state

        # Update state for final mode
        state["available_tools"] = [final_answer_tool]
        state["force_final_mode"] = True

        self.logger.info("Final mode prepared - only final answer tool available")
        return state

    def _create_tool_node(self):
        """Create the tool execution node"""

        async def tool_executor(state: InitialAnalysisState) -> InitialAnalysisState:
            """Execute tools and handle results"""
            last_message = state["messages"][-1]

            if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
                return state

            tool_results = []

            for tool_call in last_message.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]

                # Check if this is an MCP tool
                is_mcp_tool = False
                mcp_server = None

                # Find if this tool belongs to an MCP server
                for server_name in self.stage_config.available_mcp_servers or []:
                    try:
                        server_tools = await self.mcp_client_manager.list_tools(
                            server_name
                        )
                        if any(tool["name"] == tool_name for tool in server_tools):
                            is_mcp_tool = True
                            mcp_server = server_name
                            break
                    except Exception:
                        continue

                if is_mcp_tool and mcp_server:
                    # Use MCP client manager to call the tool
                    try:
                        result = await self.mcp_client_manager.call_tool(
                            mcp_server, tool_name, tool_args
                        )
                    except Exception as e:
                        result = f"Error executing MCP tool '{tool_name}': {str(e)}"
                else:
                    try:
                        self.logger.info(f"Executing tool: {tool_name}")

                        # Find the tool
                        tool = None
                        for available_tool in state["available_tools"]:
                            if available_tool.name == tool_name:
                                tool = available_tool
                                break

                        if not tool:
                            result = f"Error: Tool '{tool_name}' not found"
                        else:
                            # Regular langchain tool execution
                            # Add injected tool args
                            tool_args = self._inject_tool_args(tool_args, state["incident_vulnerability_report"])
                            # Execute the tool - support both sync and async
                            if hasattr(tool, "ainvoke"):
                                # Try async invoke first
                                try:
                                    result = await tool.ainvoke(tool_args)
                                except Exception:
                                    # Fallback to sync invoke if async fails
                                    result = tool.invoke(tool_args)
                            else:
                                # Use sync invoke if no async method available
                                result = tool.invoke(tool_args)

                            # Check if this is the final answer tool
                            if tool_name == "submit_initial_analysis_final_answer":
                                try:
                                    parsed_result = json.loads(result)
                                    state["analysis_complete"] = True
                                    state["final_analysis"] = parsed_result
                                    self.logger.info("Final analysis submitted successfully")
                                except json.JSONDecodeError as e:
                                    self.logger.error(f"Failed to parse final analysis JSON: {e}")
                                    state["error_message"] = f"Invalid JSON in final analysis: {str(e)}"
                                    # Don't set analysis_complete to True if parsing fails

                    except Exception as e:
                        result = f"Error executing tool '{tool_name}': {str(e)}"
                        self.logger.error(result)

                tool_results.append(
                    {"tool_call_id": tool_call["id"], "content": result}
                )

            # Add tool results to messages
            from langchain_core.messages import ToolMessage

            for tool_result in tool_results:
                state["messages"].append(
                    ToolMessage(
                        content=tool_result["content"],
                        tool_call_id=tool_result["tool_call_id"],
                    )
                )

            return state

        return tool_executor
    
    def _inject_tool_args(self, tool_args, incident_vulnerability_report:IncidentVulnerabilityReport):
        """Inject incident data into tool call arguments.

        Args:
            tool_call: The tool call to inject arguments into

        Returns:
            dict: The modified tool call with injected incident data
        """
        try:    
            
            tool_args_copy =  deepcopy(tool_args)

            tool_args_copy["incident_vulnerability_report"] = incident_vulnerability_report.model_dump(mode="json")
            
            return tool_args_copy

        except Exception as e:
            logger.error(f"Error in inject_tool_args: {str(e)}")
            raise

    async def _force_final_analysis(
        self, state: InitialAnalysisState
    ) -> InitialAnalysisState:
        """Force the agent to provide final analysis when max iterations reached"""
        self.logger.info("Forcing final analysis due to max iterations reached")

        try:
            # Create LLM instance
            llm = self.llm_factory.create_llm(self.stage_config.llm_config)

            # Should only have the final answer tool at this point
            if len(state["available_tools"]) != 1 or state["available_tools"][0].name != "submit_initial_analysis_final_answer":
                self.logger.error("Expected only final answer tool in force final mode")
                state["error_message"] = "Invalid tool state in force final mode"
                return state

            # Bind only the final answer tool to LLM
            llm_with_final_tool = llm.bind_tools(state["available_tools"])

            # Add a message instructing the AI to provide final analysis
            force_final_message = SystemMessage(
                content="""You have reached the maximum number of iterations for this analysis. 
                You MUST now provide your final analysis using the submit_initial_analysis_final_answer tool.
                You are REQUIRED to call this tool - do not respond with text only.

                Based on all the information you have gathered so far, provide your best analysis of:
                - The affected assets and their risk levels
                - The observed TTPs and attack patterns
                - The relevant CVEs identified
                - Your overall assessment and recommendations

                Use all available context from your previous investigations to create a comprehensive analysis.
                IMPORTANT: You must call the submit_initial_analysis_final_answer tool with your analysis."""
            )

            # Add the force message to conversation
            state["messages"].append(force_final_message)

            # Get response from LLM
            response = await llm_with_final_tool.ainvoke(state["messages"])

            # Add response to messages
            state["messages"].append(response)

            # Reset retry count for this forced attempt
            state["retry_count"] = 0

            self.logger.info("Forced final analysis response received")

        except Exception as e:
            self.logger.error(f"Error in forced final analysis: {e}")
            state["error_message"] = f"Forced final analysis error: {str(e)}"
            state["analysis_complete"] = True

        return state

    async def _finalize_analysis(
        self, state: InitialAnalysisState
    ) -> InitialAnalysisState:
        """Finalize the analysis"""
        self.logger.info("Finalizing initial analysis")

        if state.get("error_message"):
            self.logger.error(
                f"Analysis completed with error: {state['error_message']}"
            )
        elif state.get("final_analysis"):
            self.logger.info("Analysis completed successfully")
        elif state.get("analysis_complete"):
            # This is the problematic case - analysis marked complete but no final result
            self.logger.error(
                "Analysis marked as complete but no final analysis found - "
                "likely JSON parsing failure or tool execution issue"
            )
            state["error_message"] = (
                "Analysis marked complete but final result missing - check tool execution logs"
            )
        else:
            # Original warning case
            self.logger.warning(
                "Analysis completed without final answer - this should not happen with the current workflow"
            )

        return state

    async def run_analysis(
        self, incident_vulnerability_report: IncidentVulnerabilityReport
    ) -> Dict[str, Any]:
        """
        Run the initial analysis workflow

        Args:
            incident_vulnerability_report: The pre-processed vulnerability report

        Returns:
            Dictionary containing the analysis results
        """
        self.logger.info(
            f"Starting initial analysis for incident: {incident_vulnerability_report.incident_id}"
        )

        # Create initial state
        initial_state = InitialAnalysisState(
            incident_vulnerability_report=incident_vulnerability_report,
            messages=[],
            iteration_count=0,
            max_iterations=5,
            available_tools=[],
            llm_config={},
            analysis_complete=False,
            final_analysis=None,
            error_message=None,
            force_final_mode=False,
            pending_tool_execution=False,
            retry_count=0,
            max_retries=3,
        )

        try:
            # Run the workflow
            final_state = await self.graph.ainvoke(initial_state)

            # Extract results
            result = {
                "incident_id": incident_vulnerability_report.incident_id,
                "workflow_status": "completed",
                "iterations_used": final_state["iteration_count"],
                "max_iterations": final_state["max_iterations"],
                "retry_count": final_state["retry_count"],
                "analysis_complete": final_state["analysis_complete"],
                "final_analysis": final_state.get("final_analysis"),
                "error_message": final_state.get("error_message"),
                "timestamp": datetime.now().isoformat(),
            }

            if final_state.get("error_message"):
                result["workflow_status"] = "error"
            elif not final_state.get("analysis_complete"):
                result["workflow_status"] = "incomplete"

            return result

        except Exception as e:
            self.logger.error(f"Workflow execution failed: {e}")
            return {
                "incident_id": incident_vulnerability_report.incident_id,
                "workflow_status": "failed",
                "error_message": str(e),
                "timestamp": datetime.now().isoformat(),
            }


# Factory function for easy instantiation
async def create_initial_analysis_workflow(
    config: ApplicationConfig, mcp_client_manager: MCPClientManager
) -> InitialAnalysisWorkflow:
    """Create and return an initial analysis workflow instance"""
    return InitialAnalysisWorkflow(config, mcp_client_manager)
