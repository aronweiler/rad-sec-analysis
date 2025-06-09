"""
Analysis Stage

Agentic stage focused on synthesizing research findings into comprehensive security analysis.
"""

from copy import deepcopy
from datetime import datetime
import json
from typing import Any, List, Optional, Tuple

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage

from src.models.application_config import ApplicationConfig
from src.models.incident import IncidentData
from src.models.stage_config import Stage
from src.prompts.analysis_system_prompt import ANALYSIS_SYSTEM_PROMPT
from src.prompts.analysis_user_prompt import ANALYSIS_USER_PROMPT
from src.prompts.force_final_analysis_system_prompt import (
    FORCE_FINAL_ANALYSIS_SYSTEM_PROMPT,
)
from src.stages.agents import AgenticStageBase
from src.stages.agents.loop_controller import ValidationRetryNeeded
from src.tools.lc_tools.submit_analysis_tool import AnalysisVerificationResult
from src.tools.lc_tools.submit_research_tool import ResearchValidationResult
from src.tools.lc_tools.tool_manager import get_tool
from src.tools.mcp_client_manager import MCPClientManager
from src.tools.nvd_tool import IncidentVulnerabilityReport

ANALYSIS_SUBMISSION_TOOL_NAME = "submit_analysis"


class AnalysisStage(AgenticStageBase):
    """Stage focused on synthesizing research findings into comprehensive security analysis"""

    def __init__(self, config: ApplicationConfig, mcp_client_manager: MCPClientManager):
        super().__init__(
            config=config,
            mcp_client_manager=mcp_client_manager,
            stage_type=Stage.INCIDENT_ANALYSIS,
        )

    async def run(
        self,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
        research_results: ResearchValidationResult,
    ) -> tuple[AnalysisVerificationResult, IncidentData]:
        """
        Run the analysis workflow

        Args:
            incident_vulnerability_report: The pre-processed vulnerability report
            incident_data: The incident data object
            research_results: Results from the research stage

        Returns:
            AnalysisVerificationResult containing the analysis findings
        """
        self.logger.info(
            f"Starting analysis for incident: {incident_vulnerability_report.incident_id}"
        )

        return (
            await self.execute_agentic_workflow(
                incident_vulnerability_report=incident_vulnerability_report,
                incident_data=incident_data,
                research_results=research_results,
            ),
            incident_data,
        )

    def get_required_tools(self) -> List[str]:
        """Analysis stage requires the submit_analysis tool"""
        return [ANALYSIS_SUBMISSION_TOOL_NAME]

    def get_termination_tool_names(self) -> List[str]:
        """Analysis stage terminates when submit_analysis is called"""
        return [ANALYSIS_SUBMISSION_TOOL_NAME]

    async def _prepare_initial_messages(self, **kwargs) -> List[BaseMessage]:
        """Prepare the initial system and user messages for analysis"""
        incident_vulnerability_report = kwargs["incident_vulnerability_report"]
        incident_data = kwargs["incident_data"]
        research_results = kwargs["research_results"]

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

        # Format research findings for the prompt
        research_summary = {
            "research_summary": research_results.research.research_summary,
            "researcher_confidence": research_results.research.researcher_confidence,
            "research_duration_minutes": research_results.research.research_duration_minutes,
            "total_sources_consulted": research_results.research.total_sources_consulted,
            "key_discoveries": research_results.research.key_discoveries,
            "research_limitations": research_results.research.research_limitations,
            "cve_findings_count": len(research_results.research.cve_findings),
            "software_findings_count": len(research_results.research.software_findings),
            "threat_intel_findings_count": len(
                research_results.research.threat_intelligence_findings
            ),
            "research_gaps_count": len(research_results.research.research_gaps),
            "recommended_next_steps": research_results.research.recommended_next_steps,
            "detailed_findings": {
                "cve_findings": [
                    finding.model_dump()
                    for finding in research_results.research.cve_findings
                ],
                "software_findings": [
                    finding.model_dump()
                    for finding in research_results.research.software_findings
                ],
                "threat_intelligence_findings": [
                    finding.model_dump()
                    for finding in research_results.research.threat_intelligence_findings
                ],
                "research_gaps": [
                    gap.model_dump() for gap in research_results.research.research_gaps
                ],
                "enriched_context": research_results.research.enriched_incident_context,
                "research_notes": research_results.research.research_notes,
            },
        }

        # Create initial messages
        system_message = SystemMessage(content=ANALYSIS_SYSTEM_PROMPT)

        user_prompt = ANALYSIS_USER_PROMPT.format(
            incident_id=incident_vulnerability_report.incident_id,
            timestamp=datetime.now().isoformat(),
            title=incident_data.title,
            description=incident_data.description,
            affected_assets_info="\n".join(affected_assets_info),
            observed_ttps_info=[i.model_dump() for i in incident_data.observed_ttps]
            or "No TTPs provided",
            indicators_info=[
                i.model_dump() for i in incident_data.indicators_of_compromise
            ]
            or "No indicators provided",
            research_findings=json.dumps(research_summary, indent=2, default=str),
        )

        user_message = HumanMessage(content=user_prompt)

        return [system_message, user_message]

    async def _should_terminate(
        self, response: AIMessage, termination_result: Optional[Any], **kwargs
    ) -> Tuple[bool, Any]:
        """Check if analysis should terminate"""
        if termination_result is not None:
            # Analysis submission tool was called successfully
            if not isinstance(termination_result, AnalysisVerificationResult):
                raise ValueError(
                    f"Analysis submission tool did not return AnalysisVerificationResult, got {type(termination_result)}"
                )
            return True, termination_result

        return False, None

    async def _handle_forced_termination(self, **kwargs) -> AnalysisVerificationResult:
        """Handle forced termination when max iterations are reached"""
        self.logger.info("Executing forced analysis submission")

        # Apply context window management before forced termination
        if self.context_window_manager and self.stage_config.compression_config:
            processed_messages, was_compressed = (
                await self.context_window_manager.manage_context_window(
                    messages=self.messages,
                    compression_config=self.stage_config.compression_config,
                    model_name=(
                        self.stage_config.llm_config.model_name
                        if self.stage_config.llm_config
                        else "default"
                    ),
                    available_tools={},  # No compression tool needed for forced termination
                )
            )

            if was_compressed:
                self.logger.info("Context was compressed before forced termination")
                self.messages.clear()
                self.messages.extend(processed_messages)

        # Create a final analysis submission prompt
        force_final_message = HumanMessage(
            content=FORCE_FINAL_ANALYSIS_SYSTEM_PROMPT.format(
                tool_name=ANALYSIS_SUBMISSION_TOOL_NAME
            )
        )

        # Add the final submission prompt to messages
        self.messages.append(force_final_message)

        # Re-create the llm with tools, but only the analysis submission tool
        llm_with_tools = self.llm.bind_tools([get_tool(ANALYSIS_SUBMISSION_TOOL_NAME)])

        # Re-invoke the LLM with the final submission prompt
        response = await llm_with_tools.ainvoke(self.messages)
        self.messages.append(response)

        # If there are no tool calls, raise an error
        if not response.tool_calls:
            self.logger.error(
                "LLM did not call any tools for forced analysis submission"
            )
            raise ValueError(
                "LLM did not call any tools for forced analysis submission"
            )

        # Execute tools, expecting the analysis submission tool to be called
        tool_messages, termination_result, has_validation_error = (
            await self.tool_manager.execute_tools(
                response,
                lambda args: self._inject_stage_specific_args(args, **kwargs),
                [ANALYSIS_SUBMISSION_TOOL_NAME],
            )
        )

        # Add the tool messages to messages
        self.messages.extend(tool_messages)

        # If there was a validation error, signal retry needed
        if has_validation_error:
            # Add a scolding message for the retry
            retry_message = HumanMessage(
                content=f"There was a validation error in your analysis submission. Please review the error message above and correct your submission. You must call the {ANALYSIS_SUBMISSION_TOOL_NAME} tool with valid arguments."
            )
            self.messages.append(retry_message)

            # Signal that a retry is needed due to validation error
            raise ValidationRetryNeeded(
                "Analysis submission had validation errors, retry needed"
            )

        if not termination_result:
            raise ValueError(
                "Analysis submission tool was called but did not return a result"
            )

        return termination_result

    def _inject_stage_specific_args(self, tool_args: dict, **kwargs) -> dict:
        """Inject analysis-specific arguments into tool calls"""
        incident_vulnerability_report = kwargs["incident_vulnerability_report"]
        incident_data = kwargs["incident_data"]
        research_results = kwargs.get("research_results")

        try:
            tool_args_copy = deepcopy(tool_args)

            tool_args_copy["incident_vulnerability_report"] = (
                incident_vulnerability_report.model_dump(mode="json")
            )

            tool_args_copy["incident_data"] = incident_data.model_dump(mode="json")

            tool_args_copy["messages"] = [
                msg.model_dump(mode="json") for msg in self.messages
            ]

            # Include research results in the context if available
            if research_results:
                tool_args_copy["research_results"] = research_results.model_dump(
                    mode="json"
                )

            return tool_args_copy

        except Exception as e:
            self.logger.error(f"Error in inject_stage_specific_args: {str(e)}")
            raise
