"""
Submit Analysis Tool

LangChain tool for submitting structured incident analysis results with validation.
"""

from datetime import datetime
from typing import List, Optional, Union, Annotated
from langchain_core.tools import tool, InjectedToolArg
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage, SystemMessage
from pydantic import BaseModel, Field, ConfigDict

from .incident_analysis_result import (
    IncidentAnalysisResult,
    CVEAnalysis,
    AssetRiskAssessment,
    TTPAnalysis,
    VulnerabilityChain,
    ActionableRecommendation,
    RiskLevel,
    ExploitationLikelihood,
)
from src.models.incident_vulnerability_report import IncidentVulnerabilityReport
from src.models.incident import IncidentData


class ValidationWarning(BaseModel):
    """Warning about potential issues in the analysis"""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "category": "asset_consistency",
                "field_path": "asset_risk_assessments[0].hostname",
                "message": "Asset hostname 'web-server-99' not found in original incident data",
                "severity": "medium",
            }
        }
    )

    category: str = Field(..., description="Category of the warning")
    field_path: str = Field(
        ..., description="Path to the field that triggered the warning"
    )
    message: str = Field(..., description="Detailed warning message")
    severity: str = Field(..., description="Severity level: low, medium, high")


class CompletenessIssue(BaseModel):
    """Issue related to completeness of the analysis"""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "category": "missing_asset_analysis",
                "missing_item": "web-app-server-06",
                "message": "Asset 'web-app-server-06' from incident data has no corresponding risk assessment",
                "impact": "Analysis may be incomplete without assessment of this asset",
            }
        }
    )

    category: str = Field(..., description="Category of the completeness issue")
    missing_item: str = Field(..., description="The missing item or field")
    message: str = Field(..., description="Detailed description of what's missing")
    impact: str = Field(..., description="Potential impact of this omission")


class AnalysisVerificationResult(BaseModel):
    """Wrapper for analysis results with validation information"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "analysis": {
                    "incident_id": "INC-2023-08-01-001",
                    "analysis_timestamp": "2023-08-01T10:30:00Z",
                    "analyst_confidence": 8.5,
                    "executive_summary": "Analysis summary...",
                    "overall_risk_assessment": "high",
                },
                "validation_warnings": [
                    {
                        "category": "software_version_mismatch",
                        "field_path": "identified_cves[0].affected_software[0]",
                        "message": "Software version mentioned doesn't exactly match incident data",
                        "severity": "low",
                    }
                ],
                "completeness_issues": [],
                "validation_passed": True,
                "validation_summary": "Analysis passed validation with 1 minor warning",
            }
        },
    )

    analysis: IncidentAnalysisResult = Field(
        ..., description="The validated analysis result"
    )
    validation_warnings: List[ValidationWarning] = Field(
        default_factory=list, description="Non-critical validation warnings"
    )
    completeness_issues: List[CompletenessIssue] = Field(
        default_factory=list, description="Issues with analysis completeness"
    )
    validation_passed: bool = Field(
        ..., description="Whether validation passed overall"
    )
    validation_summary: str = Field(..., description="Summary of validation results")
    
    messages: List[dict] = Field(
        default_factory=list,
        description="Messages exchanged during the analysis process, including AI and human messages",
    )


class AnalysisValidator:
    """Validator for incident analysis results"""

    def __init__(
        self,
        incident_data: IncidentData,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        messages: List[dict],
    ):
        self.incident_data = incident_data
        self.incident_vulnerability_report = incident_vulnerability_report
        self.messages = messages
        self.warnings: List[ValidationWarning] = []
        self.completeness_issues: List[CompletenessIssue] = []

    def validate(self, analysis: IncidentAnalysisResult) -> AnalysisVerificationResult:
        """Validate the analysis result against incident data"""

        # Reset validation state
        self.warnings = []
        self.completeness_issues = []

        # Perform validation checks
        self._validate_incident_id(analysis)
        self._validate_assets(analysis)
        self._validate_ttps(analysis)
        self._validate_cves(analysis)
        self._validate_completeness(analysis)

        # Determine overall validation status
        validation_passed = len([w for w in self.warnings if w.severity == "high"]) == 0

        # Create summary
        warning_count = len(self.warnings)
        issue_count = len(self.completeness_issues)

        if validation_passed and warning_count == 0 and issue_count == 0:
            summary = "Analysis passed validation with no issues"
        elif validation_passed:
            summary = f"Analysis passed validation with {warning_count} warning(s) and {issue_count} completeness issue(s)"
        else:
            summary = f"Analysis failed validation with {warning_count} warning(s) and {issue_count} completeness issue(s)"

        return AnalysisVerificationResult(
            analysis=analysis,
            validation_warnings=self.warnings,
            completeness_issues=self.completeness_issues,
            validation_passed=validation_passed,
            validation_summary=summary,
            messages=self.messages,
        )

    def _validate_incident_id(self, analysis: IncidentAnalysisResult):
        """Validate incident ID matches"""
        if analysis.incident_id != self.incident_data.incident_id:
            raise ValueError(
                f"Incident ID mismatch: analysis has '{analysis.incident_id}' "
                f"but incident data has '{self.incident_data.incident_id}'"
            )

    def _validate_assets(self, analysis: IncidentAnalysisResult):
        """Validate asset references against incident data"""

        # Get valid hostnames and IPs from incident data
        valid_hostnames = {
            asset.hostname for asset in self.incident_data.affected_assets
        }
        valid_ips = {asset.ip_address for asset in self.incident_data.affected_assets}

        # Create mapping for software validation
        asset_software_map = {}
        for asset in self.incident_data.affected_assets:
            asset_software_map[asset.hostname] = {
                f"{sw.name} {sw.version}" for sw in asset.installed_software
            }

        # Validate each asset risk assessment
        for i, asset_assessment in enumerate(analysis.asset_risk_assessments):
            field_prefix = f"asset_risk_assessments[{i}]"

            # Hard validation: hostname must exist (ignore case)
            if asset_assessment.hostname.lower() not in [
                vh.lower() for vh in valid_hostnames
            ]:
                raise ValueError(
                    f"Asset hostname '{asset_assessment.hostname}' not found in incident data. "
                    f"Valid hostnames: {', '.join(valid_hostnames)}"
                )

            # Soft validation: IP address should match (could be N/A)
            if asset_assessment.ip_address.lower() not in [
                vi.lower() for vi in valid_ips
            ]:
                self.warnings.append(
                    ValidationWarning(
                        category="asset_ip_mismatch",
                        field_path=f"{field_prefix}.ip_address",
                        message=f"IP address '{asset_assessment.ip_address}' doesn't match incident data",
                        severity="medium",
                    )
                )

            # Validate software references
            if asset_assessment.hostname.lower() in [
                vh.lower() for vh in valid_hostnames
            ]:
                valid_software = asset_software_map[asset_assessment.hostname]
                for j, cve_id in enumerate(asset_assessment.critical_vulnerabilities):
                    # This is a soft check since CVEs might be discovered through analysis
                    pass  # We'll validate CVE existence in _validate_cves

        # Validate most_critical_assets references
        for i, hostname in enumerate(analysis.most_critical_assets):
            if hostname.lower() not in [vh.lower() for vh in valid_hostnames]:
                raise ValueError(
                    f"Critical asset hostname '{hostname}' not found in incident data. "
                    f"Valid hostnames: {', '.join(valid_hostnames)}"
                )

    def _validate_ttps(self, analysis: IncidentAnalysisResult):
        """Validate TTP references against incident data"""

        # Get valid TTPs from incident data
        valid_ttp_ids = {ttp.id for ttp in self.incident_data.observed_ttps}
        valid_ttp_names = {ttp.name for ttp in self.incident_data.observed_ttps}

        # Validate each TTP analysis
        for i, ttp_analysis in enumerate(analysis.ttp_analysis):
            field_prefix = f"ttp_analysis[{i}]"

            # Hard validation: TTP ID must exist in incident data
            if ttp_analysis.ttp_id not in valid_ttp_ids:
                raise ValueError(
                    f"TTP ID '{ttp_analysis.ttp_id}' not found in incident data. "
                    f"Valid TTP IDs: {', '.join(valid_ttp_ids)}"
                )

            # Soft validation: TTP name should match
            if ttp_analysis.ttp_name not in valid_ttp_names:
                self.warnings.append(
                    ValidationWarning(
                        category="ttp_name_mismatch",
                        field_path=f"{field_prefix}.ttp_name",
                        message=f"TTP name '{ttp_analysis.ttp_name}' doesn't exactly match incident data",
                        severity="low",
                    )
                )

    def _validate_cves(self, analysis: IncidentAnalysisResult):
        """Validate CVE references (minimal validation since report is not ground truth)"""

        # Get CVEs from vulnerability report for reference
        report_cve_ids = set()
        for software_report in self.incident_vulnerability_report.software_reports:
            for cve in software_report.cves:
                report_cve_ids.add(cve.cve_id)

        # Collect all CVE IDs mentioned in analysis
        analysis_cve_ids = set()

        # From identified CVEs
        for cve_analysis in analysis.identified_cves:
            analysis_cve_ids.add(cve_analysis.cve_id)

        # From additional CVEs found
        for cve_analysis in analysis.additional_cves_found:
            analysis_cve_ids.add(cve_analysis.cve_id)

        # Soft validation: warn if many CVEs are not in the original report
        # (since the AI might have discovered new ones through research)
        new_cves = analysis_cve_ids - report_cve_ids
        if len(new_cves) > len(analysis_cve_ids) * 0.5:  # More than 50% are new
            self.warnings.append(
                ValidationWarning(
                    category="many_new_cves",
                    field_path="identified_cves",
                    message=f"Analysis includes many CVEs not in original report: {', '.join(list(new_cves)[:5])}{'...' if len(new_cves) > 5 else ''}",
                    severity="low",
                )
            )

    def _validate_completeness(self, analysis: IncidentAnalysisResult):
        """Check for completeness of the analysis"""

        # Check if all assets have risk assessments
        analyzed_hostnames = {
            assessment.hostname for assessment in analysis.asset_risk_assessments
        }
        incident_hostnames = {
            asset.hostname for asset in self.incident_data.affected_assets
        }

        missing_assets = incident_hostnames - analyzed_hostnames
        for hostname in missing_assets:
            self.completeness_issues.append(
                CompletenessIssue(
                    category="missing_asset_analysis",
                    missing_item=hostname,
                    message=f"Asset '{hostname}' from incident data has no corresponding risk assessment",
                    impact="Analysis may be incomplete without assessment of this asset",
                )
            )

        # Check if all TTPs have analysis
        analyzed_ttp_ids = {ttp.ttp_id for ttp in analysis.ttp_analysis}
        incident_ttp_ids = {ttp.id for ttp in self.incident_data.observed_ttps}

        missing_ttps = incident_ttp_ids - analyzed_ttp_ids
        for ttp_id in missing_ttps:
            self.completeness_issues.append(
                CompletenessIssue(
                    category="missing_ttp_analysis",
                    missing_item=ttp_id,
                    message=f"TTP '{ttp_id}' from incident data has no corresponding analysis",
                    impact="Analysis may miss important attack techniques",
                )
            )

        # Check for empty critical sections
        if not analysis.identified_cves and not analysis.additional_cves_found:
            self.completeness_issues.append(
                CompletenessIssue(
                    category="no_cve_analysis",
                    missing_item="CVE analysis",
                    message="No CVEs were analyzed despite vulnerability report containing vulnerabilities",
                    impact="Critical security vulnerabilities may not be addressed",
                )
            )


@tool
def submit_analysis(
    incident_id: str,
    analysis_timestamp: datetime,
    analyst_confidence: float,
    executive_summary: str,
    overall_risk_assessment: RiskLevel,
    attack_sophistication: str,
    identified_cves: List[CVEAnalysis],
    additional_cves_found: List[CVEAnalysis],
    cve_prioritization_rationale: str,
    asset_risk_assessments: List[AssetRiskAssessment],
    most_critical_assets: List[str],
    ttp_analysis: List[TTPAnalysis],
    attack_progression: str,
    potential_attack_chains: List[VulnerabilityChain],
    most_likely_attack_path: Optional[str],
    threat_actor_assessment: Optional[str],
    environmental_factors: List[str],
    detection_gaps: List[str],
    reasoning_chain: List[str],
    data_sources_used: List[str],
    limitations_and_assumptions: List[str],
    follow_up_investigations: List[str],
    incident_vulnerability_report: Annotated[
        IncidentVulnerabilityReport, InjectedToolArg
    ],
    incident_data: Annotated[IncidentData, InjectedToolArg],
    messages: Annotated[
        List[dict],
        InjectedToolArg,
    ],
    immediate_actions: Optional[List[ActionableRecommendation]],
    short_term_recommendations: Optional[List[ActionableRecommendation]],
    long_term_recommendations: Optional[List[ActionableRecommendation]],
) -> AnalysisVerificationResult:
    """
    Submit a comprehensive incident analysis with validation.

    This tool accepts a complete incident analysis and validates it against the original
    incident data to ensure accuracy and completeness. Fields such as hostnames,
    IPs, and others are checked against the incident data to ensure consistency (they must match exactly).

    Args:
        incident_id: Unique identifier for the incident being analyzed
        analysis_timestamp: When this analysis was performed
        analyst_confidence: Confidence level in the analysis (0-10 scale)
        executive_summary: High-level summary of the incident and key findings
        overall_risk_assessment: Overall risk level assessment for the incident
        attack_sophistication: Assessment of the sophistication level of the attack
        identified_cves: List of CVEs identified and analyzed from the original report
        additional_cves_found: List of additional CVEs discovered during analysis
        cve_prioritization_rationale: Explanation of how CVEs were prioritized
        asset_risk_assessments: Risk assessment for each affected asset
        most_critical_assets: List of hostnames for the most critical assets
        ttp_analysis: Analysis of observed tactics, techniques, and procedures
        attack_progression: Description of how the attack progressed over time
        potential_attack_chains: Potential vulnerability exploitation chains
        most_likely_attack_path: Most probable attack path based on evidence
        threat_actor_assessment: Assessment of threat actor characteristics
        environmental_factors: Environmental factors that influenced the incident
        detection_gaps: Identified gaps in detection capabilities
        reasoning_chain: Step-by-step reasoning process used in the analysis
        data_sources_used: List of data sources consulted during analysis
        limitations_and_assumptions: Known limitations and assumptions in the analysis
        follow_up_investigations: Recommended follow-up investigation activities
        immediate_actions (Optional): Actions that should be taken immediately
        short_term_recommendations (Optional): Recommendations for short-term improvements
        long_term_recommendations (Optional): Recommendations for long-term strategic changes
    """

    # Construct the analysis result
    analysis = IncidentAnalysisResult(
        incident_id=incident_id,
        analysis_timestamp=analysis_timestamp,
        analyst_confidence=analyst_confidence,
        executive_summary=executive_summary,
        overall_risk_assessment=overall_risk_assessment,
        attack_sophistication=attack_sophistication,
        identified_cves=identified_cves,
        additional_cves_found=additional_cves_found,
        cve_prioritization_rationale=cve_prioritization_rationale,
        asset_risk_assessments=asset_risk_assessments,
        most_critical_assets=most_critical_assets,
        ttp_analysis=ttp_analysis,
        attack_progression=attack_progression,
        potential_attack_chains=potential_attack_chains,
        most_likely_attack_path=most_likely_attack_path,
        threat_actor_assessment=threat_actor_assessment,
        environmental_factors=environmental_factors,
        detection_gaps=detection_gaps,
        immediate_actions=immediate_actions,
        short_term_recommendations=short_term_recommendations,
        long_term_recommendations=long_term_recommendations,
        reasoning_chain=reasoning_chain,
        data_sources_used=data_sources_used,
        limitations_and_assumptions=limitations_and_assumptions,
        follow_up_investigations=follow_up_investigations,
    )

    # Create validator and validate the analysis
    validator = AnalysisValidator(
        incident_data=incident_data,
        incident_vulnerability_report=incident_vulnerability_report,
        messages=messages,
    )

    return validator.validate(analysis)


# Export the tools for use
submit_analysis_tools = [submit_analysis]
