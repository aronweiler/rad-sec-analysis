import logging
from pathlib import Path
from src.models.incident import IncidentData
from src.models.stage_config import Stage
from src.reports.markdown_report_generator import MarkdownReportGenerator
from src.stages.base import StageBase
from src.tools.lc_tools.submit_analysis_tool import AnalysisVerificationResult


class ReportStage(StageBase):
    """Stage for generating reports based on analysis results"""

    def __init__(self, config, mcp_client_manager):
        """
        Initialize the report stage

        Args:
            config: Application configuration
            mcp_client_manager: MCP client manager for tool access
        """
        super().__init__(config, mcp_client_manager, Stage.REPORT_GENERATION)

        # Ensure the stage configuration is valid
        if not self.stage_config:
            raise ValueError("Report stage not configured")

        self.report_generator = MarkdownReportGenerator()

    async def run(
        self, incident: IncidentData, analysis_result: AnalysisVerificationResult
    ) -> None:
        """
        Generate a report based on the analysis results

        Args:
            *args: Variable positional arguments (not used in this stage)
            **kwargs: Variable keyword arguments (not used in this stage)

        Returns:
            str: The generated report as a string
        """
        output_path = str(
            Path(self.stage_config.settings["output_directory"])
            / f"{incident.incident_id}_report.md"
        )
        self.report_generator.save_report(analysis_result, output_path)
        # Also create a customer-facing report
        self.report_generator.save_customer_report(
            analysis_result,
            output_path.replace("_report.md", "_customer_report.md"),
        )
        self.logger.info(f"Reports generated and saved to {output_path}")
