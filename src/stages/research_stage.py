"""
Research Stage

Agentic stage focused on comprehensive incident research and information gathering.
"""

from copy import deepcopy
from datetime import datetime
import json
from typing import Any, List, Optional, Tuple

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage

from src.models.application_config import ApplicationConfig
from src.models.incident import IncidentData
from src.models.stage_config import Stage
from src.prompts.research_system_prompt import RESEARCH_SYSTEM_PROMPT
from src.prompts.research_user_prompt import RESEARCH_USER_PROMPT
from src.prompts.force_final_research_system_prompt import (
    FORCE_FINAL_RESEARCH_SYSTEM_PROMPT,
)
from src.stages.agents import AgenticStageBase
from src.stages.agents.loop_controller import ValidationRetryNeeded
from src.tools.lc_tools.submit_research_tool import ResearchValidationResult
from src.tools.lc_tools.tool_manager import get_tool
from src.tools.mcp_client_manager import MCPClientManager
from src.tools.nvd_tool import IncidentVulnerabilityReport

RESEARCH_SUBMISSION_TOOL_NAME = "submit_research"


class ResearchStage(AgenticStageBase):
    """Stage focused on comprehensive incident research and information gathering"""

    def __init__(self, config: ApplicationConfig, mcp_client_manager: MCPClientManager):
        super().__init__(
            config=config,
            mcp_client_manager=mcp_client_manager,
            stage_type=Stage.INCIDENT_RESEARCH,
        )

    async def run(
        self,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        incident_data: IncidentData,
    ) -> tuple[IncidentVulnerabilityReport, IncidentData, ResearchValidationResult]:
        """
        Run the research workflow

        Args:
            incident_vulnerability_report: The pre-processed vulnerability report
            incident_data: The incident data object

        Returns:
            ResearchValidationResult containing the research findings
        """
        self.logger.info(
            f"Starting research for incident: {incident_vulnerability_report.incident_id}"
        )

        return (
            incident_vulnerability_report,
            incident_data,
            await self.execute_agentic_workflow(
                incident_vulnerability_report=incident_vulnerability_report,
                incident_data=incident_data,
            ),
        )

    def get_required_tools(self) -> List[str]:
        """Research stage requires the submit_research tool"""
        return [RESEARCH_SUBMISSION_TOOL_NAME]

    def get_termination_tool_names(self) -> List[str]:
        """Research stage terminates when submit_research is called"""
        return [RESEARCH_SUBMISSION_TOOL_NAME]

    async def _prepare_initial_messages(self, **kwargs) -> List[BaseMessage]:
        """Prepare the initial system and user messages for research"""
        incident_vulnerability_report = kwargs["incident_vulnerability_report"]
        incident_data = kwargs["incident_data"]

        # Format affected assets summary with software details
        affected_assets_summary = []
        for asset in incident_data.affected_assets:
            software_list = ", ".join(
                [f"{s.name} {s.version}" for s in asset.installed_software[:3]]
            )
            if len(asset.installed_software) > 3:
                software_list += f" (+{len(asset.installed_software)-3} more)"
            affected_assets_summary.append(
                f"**{asset.hostname}** ({asset.role}): {software_list}"
            )

        # Extract top priority CVEs (highest CVSS scores)
        all_cves = []
        for software_report in incident_vulnerability_report.software_reports:
            all_cves.extend(software_report.cves)

        top_cves = sorted(
            [cve for cve in all_cves if cve.cvss_v3_score and cve.cvss_v3_score >= 7.0],
            key=lambda x: (x.cvss_v3_score, x.relevance_score),
            reverse=True,
        )[:10]

        top_cves_list = []
        for cve in top_cves:
            cwe_info = f" ({cve.weaknesses[0]})" if cve.weaknesses else ""
            top_cves_list.append(
                f"**{cve.cve_id}**: CVSS {cve.cvss_v3_score} ({cve.cvss_v3_severity}){cwe_info} - {cve.description[:100]}..."
            )

        # Extract recent CVEs (last 90 days)
        recent_cves = []
        for software_report in incident_vulnerability_report.software_reports:
            recent_cves.extend(
                [cve for cve in software_report.recent_cves if cve.age_days <= 90]
            )

        recent_cves_list = []
        for cve in sorted(recent_cves, key=lambda x: x.published_date, reverse=True)[
            :8
        ]:
            recent_cves_list.append(
                f"**{cve.cve_id}**: {cve.cvss_v3_severity or 'N/A'} - {cve.published_date.strftime('%m/%d')} - {cve.description[:80]}..."
            )

        # Extract CPE strings for precise research
        cpe_data = incident_data.get_all_cpes()
        cpe_list = []
        # Show key software CPEs
        for cpe in cpe_data["software_cpes"][:8]:
            cpe_list.append(f"- {cpe}")
        # Show key asset CPEs
        for cpe in cpe_data["asset_cpes"][:5]:
            cpe_list.append(f"- {cpe}")

        # Format observed TTPs concisely
        if incident_data.observed_ttps:
            observed_ttps_info = "\n".join(
                [f"**{ttp.id}**: {ttp.name}" for ttp in incident_data.observed_ttps]
            )
        else:
            observed_ttps_info = "None specified"

        # Format indicators concisely
        if incident_data.indicators_of_compromise:
            indicators_info = "\n".join(
                [
                    f"**{ioc.type.value}**: {ioc.value} ({ioc.context[:50]}...)"
                    for ioc in incident_data.indicators_of_compromise[:8]
                ]
            )
        else:
            indicators_info = "None specified"

        # Create vulnerability summary
        vulnerability_summary = (
            f"Total: {incident_vulnerability_report.total_vulnerabilities} "
            f"(Critical: {incident_vulnerability_report.critical_vulnerabilities}, "
            f"High: {incident_vulnerability_report.high_vulnerabilities}, "
            f"Medium: {incident_vulnerability_report.medium_vulnerabilities}, "
            f"Low: {incident_vulnerability_report.low_vulnerabilities})"
        )

        # Create messages
        system_message = SystemMessage(content=RESEARCH_SYSTEM_PROMPT)

        user_prompt = RESEARCH_USER_PROMPT.format(
            incident_id=incident_vulnerability_report.incident_id,
            timestamp=datetime.now().isoformat(),
            title=incident_data.title,
            description=incident_data.description,
            affected_assets_summary=(
                "\n".join(affected_assets_summary)
                if affected_assets_summary
                else "No assets specified"
            ),
            top_cves_list=(
                "\n".join(top_cves_list)
                if top_cves_list
                else "No high-severity CVEs found"
            ),
            recent_cves_list=(
                "\n".join(recent_cves_list)
                if recent_cves_list
                else "No recent CVEs found"
            ),
            cpe_list="\n".join(cpe_list) if cpe_list else "No CPE strings available",
            observed_ttps_info=observed_ttps_info,
            indicators_info=indicators_info,
            vulnerability_summary=vulnerability_summary,
        )

        user_message = HumanMessage(content=user_prompt)

        return [system_message, user_message]

    async def _should_terminate(
        self, response: AIMessage, termination_result: Optional[Any], **kwargs
    ) -> Tuple[bool, Any]:
        """Check if research should terminate"""
        if termination_result is not None:
            # Research submission tool was called successfully
            if not isinstance(termination_result, ResearchValidationResult):
                raise ValueError(
                    f"Research submission tool did not return ResearchValidationResult, got {type(termination_result)}"
                )
            return True, termination_result

        return False, None

    async def _handle_forced_termination(self, **kwargs) -> ResearchValidationResult:
        """Handle forced termination when max iterations are reached"""
        self.logger.info("Executing forced research submission")

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

        # Create a final research submission prompt
        force_final_message = HumanMessage(
            content=FORCE_FINAL_RESEARCH_SYSTEM_PROMPT.format(
                tool_name=RESEARCH_SUBMISSION_TOOL_NAME
            )
        )

        # Add the final submission prompt to messages
        self.messages.append(force_final_message)

        # Re-create the llm with tools, but only the research submission tool
        llm_with_tools = self.llm.bind_tools([get_tool(RESEARCH_SUBMISSION_TOOL_NAME)])

        # Re-invoke the LLM with the final submission prompt
        response = await llm_with_tools.ainvoke(self.messages)
        self.messages.append(response)

        # If there are no tool calls, raise an error
        if not response.tool_calls:
            self.logger.error(
                "LLM did not call any tools for forced research submission"
            )
            raise ValueError(
                "LLM did not call any tools for forced research submission"
            )

        # Execute tools, expecting the research submission tool to be called
        tool_messages, termination_result, has_validation_error = (
            await self.tool_manager.execute_tools(
                response,
                lambda args: self._inject_stage_specific_args(args, **kwargs),
                [RESEARCH_SUBMISSION_TOOL_NAME],
            )
        )

        # Add the tool messages to messages
        self.messages.extend(tool_messages)

        # If there was a validation error, signal retry needed
        if has_validation_error:
            # Add a scolding message for the retry
            retry_message = HumanMessage(
                content=f"There was a validation error in your research submission. Please review the error message above and correct your submission. You must call the {RESEARCH_SUBMISSION_TOOL_NAME} tool with valid arguments."
            )
            self.messages.append(retry_message)

            # Signal that a retry is needed due to validation error
            raise ValidationRetryNeeded(
                "Research submission had validation errors, retry needed"
            )

        if not termination_result:
            raise ValueError(
                "Research submission tool was called but did not return a result"
            )

        return termination_result

    def _inject_stage_specific_args(self, tool_args: dict, **kwargs) -> dict:
        """Inject research-specific arguments into tool calls"""
        incident_vulnerability_report = kwargs["incident_vulnerability_report"]
        incident_data = kwargs["incident_data"]

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
            self.logger.error(f"Error in inject_stage_specific_args: {str(e)}")
            raise
