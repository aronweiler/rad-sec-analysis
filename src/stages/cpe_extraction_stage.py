"""
CPE Extraction Stage

Agentic stage for generating CPE (Common Platform Enumeration) strings from security incident data.
Processes incidents in batches and auto-terminates when all incidents are processed.
"""

import logging
from typing import Any, List, Optional, Tuple
from math import ceil

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage
from pydantic import ValidationError

from src.models.application_config import ApplicationConfig
from src.models.incident import IncidentData
from src.models.stage_config import Stage
from src.parsers.base import ParseResult
from src.prompts.construct_cpes_system_prompt import CONSTRUCT_CPES_SYSTEM_PROMPT
from src.prompts.construct_cpes_user_prompt import CONSTRUCT_CPES_USER_PROMPT
from src.stages.agents import AgenticStageBase
from src.stages.agents.loop_controller import ValidationRetryNeeded
from src.tools.mcp_client_manager import MCPClientManager

logger = logging.getLogger(__name__)


class CPEExtractionStage(AgenticStageBase):
    """Stage for generating CPE strings from security incident data"""

    def __init__(self, config: ApplicationConfig, mcp_client_manager: MCPClientManager):
        super().__init__(
            config=config,
            mcp_client_manager=mcp_client_manager,
            stage_type=Stage.CPE_EXTRACTION,
        )

        # Track processing state
        self.current_batch = 0
        self.total_batches = 0
        self.processed_incidents = []
        self.all_incidents = []
        self.current_batch_incidents = []

    async def run(self, incidents: List[ParseResult]) -> List[IncidentData]:
        """
        Run the CPE extraction workflow

        Args:
            incidents: List of incident data objects to process

        Returns:
            List of updated IncidentData objects with populated CPE fields
        """
        self.logger.info(f"Starting CPE extraction for {len(incidents)} incidents")

        # Store incidents for processing
        self.all_incidents = [i.incident for i in incidents]
        self.processed_incidents = []

        # Get batch size from stage config
        batch_size = self.stage_config.settings.get('asset_batch_size', 20)
        self.total_batches = ceil(len(incidents) / batch_size)

        self.logger.info(f"Processing {len(incidents)} incidents in {self.total_batches} batches of size {batch_size}")
        self.logger.info("Note: Batch processing is currently sequential - parallelization planned for future enhancement")

        # Process batches sequentially
        for batch_num in range(self.total_batches):
            self.current_batch = batch_num + 1
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(incidents))
            batch_incidents = incidents[start_idx:end_idx]

            self.logger.info(f"Processing batch {self.current_batch}/{self.total_batches} with {len(batch_incidents)} incidents")

            # Store current batch for injection
            self.current_batch_incidents = batch_incidents

            # Process this batch using the agentic workflow
            processed_batch = await self.execute_agentic_workflow(
                batch_incidents=batch_incidents,
                batch_number=self.current_batch,
                total_batches=self.total_batches
            )

            # Add processed incidents to our result list
            self.processed_incidents.extend(processed_batch)

        self.logger.info(f"Completed CPE extraction for all {len(self.processed_incidents)} incidents")
        return self.processed_incidents

    def get_required_tools(self) -> List[str]:
        """CPE extraction stage requires the generate_cpes_for_batch tool"""
        return ["generate_cpes_for_batch"]

    def get_termination_tool_names(self) -> List[str]:
        """No termination tools - stage auto-terminates after processing"""
        return []

    async def _prepare_initial_messages(self, **kwargs) -> List[BaseMessage]:
        """Prepare the initial system and user messages for CPE extraction"""
        batch_incidents = kwargs["batch_incidents"]
        batch_number = kwargs["batch_number"]
        total_batches = kwargs["total_batches"]

        # Count assets and software in this batch
        asset_count = sum(len(incident.affected_assets) for incident in batch_incidents)
        software_count = sum(
            len(asset.installed_software) 
            for incident in batch_incidents 
            for asset in incident.affected_assets
        )

        # Create detailed batch information
        batch_details = []
        for i, incident in enumerate(batch_incidents, 1):
            batch_details.append(f"**Incident {i}: {incident.incident_id}**")
            batch_details.append(f"Title: {incident.title}")

            for j, asset in enumerate(incident.affected_assets, 1):
                batch_details.append(f"\nAsset {j}:")
                batch_details.append(f"- Hostname: {asset.hostname}")
                batch_details.append(f"- IP: {asset.ip_address}")
                batch_details.append(f"- OS: {asset.os}")
                batch_details.append(f"- Role: {asset.role}")

                if asset.installed_software:
                    batch_details.append(f"- Software:")
                    for software in asset.installed_software:
                        batch_details.append(f"  - {software.name} {software.version}")
                else:
                    batch_details.append(f"- No software listed")

            batch_details.append("")  # Empty line between incidents

        # Create messages
        system_message = SystemMessage(content=CONSTRUCT_CPES_SYSTEM_PROMPT)

        user_prompt = CONSTRUCT_CPES_USER_PROMPT.format(
            batch_number=batch_number,
            total_batches=total_batches,
            asset_count=asset_count,
            software_count=software_count,
            batch_details="\n".join(batch_details)
        )

        user_message = HumanMessage(content=user_prompt)

        return [system_message, user_message]

    async def _should_terminate(
        self, response: AIMessage, termination_result: Optional[Any], **kwargs
    ) -> Tuple[bool, Any]:
        """Check if CPE extraction should terminate (auto-terminate after successful tool execution)"""
        # Check if the generate_cpes_for_batch tool was called
        if response.tool_calls:
            for tool_call in response.tool_calls:
                if tool_call["name"] == "generate_cpes_for_batch":
                    # Tool was called - check if we have a successful result in the conversation
                    # Look for tool messages in the conversation that indicate success
                    for msg in reversed(self.messages):
                        if hasattr(msg, 'content') and isinstance(msg.content, str):
                            # If we see a tool message without validation errors, we can terminate
                            if "ValidationError" not in msg.content and "validation failed" not in msg.content.lower():
                                # Successful tool execution - return the current batch
                                return True, kwargs.get("batch_incidents", [])

        # Continue processing if tool hasn't been called successfully yet
        return False, None

    async def _handle_forced_termination(self, **kwargs) -> List[IncidentData]:
        """Handle forced termination - should not occur with max_iterations=1"""
        self.logger.error("Forced termination in CPE extraction stage - this should not happen with max_iterations=1")
        batch_incidents = kwargs.get("batch_incidents", [])

        # Return the original incidents without CPE data as fallback
        self.logger.warning("Returning original incidents without CPE data due to forced termination")
        return batch_incidents

    def _inject_stage_specific_args(self, tool_args: dict, **kwargs) -> dict:
        """Inject CPE extraction specific arguments into tool calls"""
        # The generate_cpes_for_batch tool expects incident_data and validation_config to be injected
        enhanced_args = tool_args.copy()

        # Inject the current batch incidents
        enhanced_args["incident_data"] = self.current_batch_incidents

        # Inject validation configuration from stage settings
        validation_config = {
            'hostname_similarity_threshold': self.stage_config.settings.get('hostname_similarity_threshold', 0.8),
            'software_name_similarity_threshold': self.stage_config.settings.get('software_name_similarity_threshold', 0.7),
            'software_version_similarity_threshold': self.stage_config.settings.get('software_version_similarity_threshold', 0.8),
            'vendor_product_similarity_threshold': self.stage_config.settings.get('vendor_product_similarity_threshold', 0.6),
            'strict_ip_matching': self.stage_config.settings.get('strict_ip_matching', True),
            'strict_hostname_matching': self.stage_config.settings.get('strict_hostname_matching', False)
        }
        enhanced_args["validation_config"] = validation_config

        return enhanced_args