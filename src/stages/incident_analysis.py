from copy import deepcopy
from datetime import datetime
import json
import logging
from typing import Any, Dict, List, Union

from pydantic import ValidationError
from src.core.llm_factory import LLMFactory
from src.models.application_config import ApplicationConfig
from src.models.incident import IncidentData
from src.models.stage_config import Stage
from src.prompts.force_final_analysis_system_prompt import (
    FORCE_FINAL_ANALYSIS_SYSTEM_PROMPT,
)
from src.prompts.initial_analysis_system_prompt import INITIAL_ANALYSIS_SYSTEM_PROMPT
from src.prompts.initial_analysis_user_prompt import INITIAL_ANALYSIS_USER_PROMPT
from src.stages.base import StageBase
from src.tools.lc_tools.submit_analysis_tool import AnalysisVerificationResult
from src.tools.lc_tools.tool_manager import get_tool
from src.tools.mcp_client_manager import MCPClientManager
from src.tools.nvd_tool import IncidentVulnerabilityReport

from langchain.base_language import BaseLanguageModel
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool

FINAL_ANSWER_TOOL_NAME = "submit_analysis"


class IncidentAnalysis(StageBase):
    """Workflow for incident and CVE analysis"""

    def __init__(self, config: ApplicationConfig, mcp_client_manager: MCPClientManager):
        super().__init__(
            config=config,
            mcp_client_manager=mcp_client_manager,
            stage_type=Stage.INITIAL_INCIDENT_AND_CVE_ANALYSIS,
        )

        self.available_tools: Dict[str, BaseTool] = {}
        self.mcp_tools_to_server: Dict[str, str] = {}
        self.messages: List[
            Union[SystemMessage, HumanMessage, AIMessage, ToolMessage]
        ] = []

    async def _initialize_tools(self):
        # Add available tools by config
        if self.stage_config.available_tools:
            for tool_name in self.stage_config.available_tools:
                tool = get_tool(tool_name)
                if tool:
                    self.available_tools[tool_name] = tool
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
                    for tool in mcp_tools:
                        self.available_tools[tool.name] = tool
                        self.mcp_tools_to_server[tool.name] = server_name
                        self.logger.info(
                            f"Added MCP tool: {tool.name} from {server_name}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to get tools from MCP server {server_name}: {e}"
                    )

        # Verify final answer tool is available
        final_answer_tool_found = any(
            tool == FINAL_ANSWER_TOOL_NAME for tool in self.available_tools.keys()
        )
        if not final_answer_tool_found:
            raise ValueError("submit_analysis tool not found in available tools")

    async def run(
        self,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
    ) -> AnalysisVerificationResult:
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

        await self._initialize_tools()

        # Format affected assets
        affected_assets_info = []
        for software_report in incident_vulnerability_report.software_reports:
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
            "total_vulnerabilities": incident_vulnerability_report.total_vulnerabilities,
            "critical_vulnerabilities": incident_vulnerability_report.critical_vulnerabilities,
            "high_vulnerabilities": incident_vulnerability_report.high_vulnerabilities,
            "medium_vulnerabilities": incident_vulnerability_report.medium_vulnerabilities,
            "low_vulnerabilities": incident_vulnerability_report.low_vulnerabilities,
            "most_vulnerable_software": (
                {
                    "name": incident_vulnerability_report.most_vulnerable_software.name,
                    "version": incident_vulnerability_report.most_vulnerable_software.version,
                }
                if incident_vulnerability_report.most_vulnerable_software
                else None
            ),
            "software_summary": affected_assets_info,
            "recommendations": incident_vulnerability_report.recommendations,
        }

        # Create initial messages
        system_message = SystemMessage(content=INITIAL_ANALYSIS_SYSTEM_PROMPT)

        user_prompt = INITIAL_ANALYSIS_USER_PROMPT.format(
            incident_id=incident_vulnerability_report.incident_id,
            timestamp=datetime.now().isoformat(),
            title=incident_data.title,
            description=incident_data.description,
            initial_findings="Pre-processed vulnerability data available",
            affected_assets_info="\n".join(affected_assets_info),
            observed_ttps_info=[i.model_dump() for i in incident_data.observed_ttps]
            or "No TTPs provided",
            indicators_info=[
                i.model_dump() for i in incident_data.indicators_of_compromise
            ]
            or "No indicators provided",
            vulnerability_report=json.dumps(vulnerability_summary, indent=2),
        )

        user_message = HumanMessage(content=user_prompt)

        self.messages = [system_message, user_message]

        self.logger.info("Starting LLM analysis with messages prepared")

        llm_with_tools: BaseLanguageModel = self.llm.bind_tools(
            self.available_tools.values()
        )

        response = await llm_with_tools.ainvoke(self.messages)
        self.messages += [response]

        return await self._execute_research_loop(
            response, incident_vulnerability_report, incident_data, llm_with_tools
        )

    async def _execute_research_loop(
        self,
        response: AIMessage,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
        llm_with_tools: BaseLanguageModel,
        current_iteration: int = 0,
    ) -> AnalysisVerificationResult:
        """
        Execute the research loop based on LLM response

        Args:
            response: The LLM response containing tool calls
            incident_vulnerability_report: The pre-processed vulnerability report
            incident_data: The incident data object
        """
        # Check to see if we are at the max iterations
        if current_iteration >= self.stage_config.max_iterations:
            self.logger.warning(
                f"Max iterations reached ({self.stage_config.max_iterations}), prompting for final answer"
            )
            return await self._force_final_answer(
                response, incident_vulnerability_report, incident_data
            )

        self.logger.info(
            f"Executing research loop iteration {current_iteration} in {Stage.INITIAL_INCIDENT_AND_CVE_ANALYSIS} stage"
        )

        # This loop will execute a max number of times based on the configured max iterations in the stage config
        # self.stage_config.max_iterations
        # If the LLM does not call one of the provided tools, it should be scolded and asked to try again
        # It should either call one of the security research tools, or the final answer tool
        # If the max iterations are reached, it should be prompted to provide a final answer

        # Check if the response contains any tool calls
        if not response.tool_calls:
            self.logger.warning("LLM did not call any tools, scolding and retrying")
            # If no tool calls, prompt the LLM to try again
            retry_message = HumanMessage(
                content=f"Invalid response! Please try again and ensure you call one of the available tools in your response: {', '.join(self.available_tools.keys())}."
            )
            self.messages += [response, retry_message]
            response = await llm_with_tools.ainvoke(self.messages)
            self.messages += [response]
            # Increment the iteration count and continue the loop
            current_iteration += 1
            return await self._execute_research_loop(
                response,
                incident_vulnerability_report,
                incident_data,
                llm_with_tools,
                current_iteration,
            )
        else:
            self.logger.info(
                f"LLM called tools: {[call['name'] for call in response.tool_calls]}"
            )
            # Execute the tools
            tool_messages, final_answer = await self._execute_tools(
                response, incident_vulnerability_report, incident_data
            )

            # Add the tool messages to messages, and re-invoke the LLM if we're still in the loop
            self.messages += tool_messages

            if final_answer:
                self.logger.info("Final answer tool called, exiting research loop")
                # If the final answer tool was called, we can exit the loop
                return final_answer
            else:
                self.logger.info(
                    "Continuing research loop with new messages and incrementing iteration"
                )
                # If not, we continue the loop with the new messages
                current_iteration += 1
                response = await llm_with_tools.ainvoke(self.messages)
                self.messages += [response]
                return await self._execute_research_loop(
                    response,
                    incident_vulnerability_report,
                    incident_data,
                    llm_with_tools,
                    current_iteration,
                )

    async def _execute_tools(
        self,
        response: AIMessage,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
    ) -> tuple[List[ToolMessage], Union[AnalysisVerificationResult, None]]:
        """
        Execute the tools based on the LLM response
        This method will handle tool calls and execute them accordingly
        """

        tool_results = []
        final_answer = None
        has_validation_error = False

        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            # Check if this is an MCP tool
            is_mcp_tool = tool_name in self.mcp_tools_to_server.keys()
            if is_mcp_tool:
                mcp_server = self.mcp_tools_to_server[tool_name]
            else:
                mcp_server = None

            if is_mcp_tool and mcp_server:
                # Use MCP client manager to call the tool
                # Required, since we need to handle MCP-specific tool calls differently
                self.logger.info(
                    f"Executing MCP tool: {tool_name} on server {mcp_server}"
                )
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
                    tool = self.available_tools.get(tool_name)
                    if not tool:
                        result = f"Error: Tool '{tool_name}' not found"
                    else:
                        # Regular langchain tool execution
                        # Add injected tool args
                        tool_args = self._inject_tool_args(
                            tool_args, incident_vulnerability_report, incident_data
                        )
                        try:
                            # Execute the tool - support both sync and async
                            if tool.coroutine:
                                result = await tool.ainvoke(tool_args)
                            else:
                                result = tool.invoke(tool_args)
                        except ValidationError as ve:
                            # Handle validation errors specifically, and kick it back to the AI to retry
                            result = f"Validation error(s) when calling tool '{tool_name}': {str(ve)}\n\nPlease correct the arguments and try again."
                            has_validation_error = True

                        # Check if this was the final answer tool, since we will need to exit the loop
                        if (
                            tool_name == FINAL_ANSWER_TOOL_NAME
                            and not has_validation_error
                        ):
                            if not isinstance(result, AnalysisVerificationResult):
                                raise ValueError(
                                    f"Final answer tool did not return InitialAnalysisResult, got {type(result)}"
                                )

                            final_answer = result
                            self.logger.info("Final analysis submitted successfully")

                except Exception as e:
                    result = f"Error executing tool '{tool_name}': {str(e)}"
                    self.logger.error(result)

            tool_results.append(
                ToolMessage(content=result, tool_call_id=tool_call["id"])
            )

        return tool_results, final_answer

    async def _force_final_answer(
        self,
        response: AIMessage,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
    ) -> AnalysisVerificationResult:
        """
        Force the LLM to provide a final answer when max iterations are reached
        """
        self.logger.info("Max iterations reached, forcing final answer")

        # Execute any remaining tool calls
        tool_messages, final_answer = await self._execute_tools(
            response, incident_vulnerability_report, incident_data
        )

        self.messages += tool_messages
        # If the final answer was already provided, return it
        if final_answer:
            self.logger.info("Final answer already provided, returning it")
            return final_answer

        # Create a final answer system prompt
        force_final_message = SystemMessage(
            content=FORCE_FINAL_ANALYSIS_SYSTEM_PROMPT.format(
                tool_name=FINAL_ANSWER_TOOL_NAME
            )
        )

        # Add the final answer prompt to messages
        self.messages.append(force_final_message)

        # Re-create the llm with tools, but only the final answer tool
        llm_with_tools: BaseLanguageModel = self.llm.bind_tools(
            [get_tool(FINAL_ANSWER_TOOL_NAME)]
        )

        # Re-invoke the LLM with the final answer prompt
        response = await llm_with_tools.ainvoke(self.messages)

        # If there are no tool calls, raise an error.
        # This is unexpected since we forced the LLM to call the final answer tool
        # In this situation, we should not retry, but rather raise an error and deal with it externally
        if not response.tool_calls:
            self.logger.error(
                "LLM did not call any tools after max iterations, expected final answer tool to be called"
            )
            raise ValueError(
                "LLM did not call any tools after max iterations, expected final answer tool to be called"
            )

        # Execute tools again, expecting the final answer tool to be called
        tool_messages, final_answer = await self._execute_tools(
            response, incident_vulnerability_report, incident_data
        )

        # Add the tool messages to messages
        self.messages += tool_messages

        if not final_answer:
            raise ValueError("Final answer tool was not called after max iterations")

        return final_answer

    def _inject_tool_args(
        self,
        tool_args,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
    ):
        """Inject incident data into tool call arguments.

        Args:
            tool_call: The tool call to inject arguments into

        Returns:
            dict: The modified tool call with injected incident data
        """
        try:

            tool_args_copy = deepcopy(tool_args)

            tool_args_copy["incident_vulnerability_report"] = (
                incident_vulnerability_report.model_dump(mode="json")
            )

            tool_args_copy["incident_data"] = incident_data.model_dump(mode="json")

            tool_args_copy["messages"] = [
                msg.model_dump(mode="json") for msg in self.messages
            ]

            return tool_args_copy

        except Exception as e:
            self.logger.error(f"Error in inject_tool_args: {str(e)}")
            raise
