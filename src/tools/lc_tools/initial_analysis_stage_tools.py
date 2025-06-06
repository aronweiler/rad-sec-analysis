"""
Initial Incident and CVE Analysis Stage Tools

Stage tools that constrain the output of the initial incident and CVE analysis stage
to ensure proper formatting, data validation, and structured responses.
"""

from dataclasses import dataclass
import re
from langchain_core.tools import tool, InjectedToolArg
from typing import Annotated, List, Optional, Dict, Any, Set, Tuple
from pydantic import BaseModel, Field, field_validator
import json
from datetime import datetime

from src.tools.nvd_tool import CVEInfo, IncidentVulnerabilityReport
from ...models.incident import IncidentData, AssetData, TTPData, IOCData


class CVEAnalysisResult(BaseModel):
    """Individual CVE analysis result for the initial stage"""

    model_config = {
        "json_schema_extra": {
            "example": {
                "cve_id": "CVE-2023-44487",
                "relevance_score": 8.5,
                "severity": "HIGH",
                "cvss_score": 7.5,
                "affected_software": ["nginx", "apache", "cloudflare"],
                "description": "HTTP/2 Rapid Reset vulnerability allowing DDoS attacks",
                "exploitation_likelihood": "HIGH",
                "rationale": "Widely exploited vulnerability affecting web infrastructure components present in the environment",
                "nvd_link": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
            }
        }
    }

    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2023-1234)")
    relevance_score: float = Field(
        ..., ge=0.0, le=10.0, description="Relevance score from 0-10"
    )
    severity: str = Field(
        ..., description="CVSS severity (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    cvss_score: Optional[float] = Field(
        None, description="CVSS base score if available"
    )
    affected_software: List[str] = Field(
        default_factory=list, description="Software/components affected"
    )
    description: str = Field(..., description="Brief description of the vulnerability")
    exploitation_likelihood: str = Field(
        ..., description="Likelihood of exploitation (HIGH, MEDIUM, LOW)"
    )
    rationale: str = Field(
        ..., description="Reasoning for relevance and likelihood assessment"
    )
    nvd_link: Optional[str] = Field(None, description="NVD link for the CVE")

    @field_validator("cve_id")
    @classmethod
    def validate_cve_format(cls, v):
        """Validate CVE ID format"""
        if not v.upper().startswith("CVE-"):
            raise ValueError("CVE ID must start with CVE-")
        return v.upper()

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        """Validate severity values"""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        if v.upper() not in valid_severities:
            raise ValueError(f"Severity must be one of: {valid_severities}")
        return v.upper()

    @field_validator("exploitation_likelihood")
    @classmethod
    def validate_likelihood(cls, v):
        """Validate exploitation likelihood values"""
        valid_likelihoods = ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        if v.upper() not in valid_likelihoods:
            raise ValueError(
                f"Exploitation likelihood must be one of: {valid_likelihoods}"
            )
        return v.upper()


class AssetAnalysisResult(BaseModel):
    """Analysis result for an affected asset"""

    model_config = {
        "json_schema_extra": {
            "example": {
                "hostname": "web-server-01",
                "ip_address": "192.168.1.100",
                "role": "Web Server",
                "risk_level": "HIGH",
                "vulnerable_software": ["nginx 1.18.0", "openssl 1.1.1"],
                "security_concerns": [
                    "Exposed to internet traffic",
                    "Running outdated software versions",
                    "Missing security patches",
                ],
            }
        }
    }

    hostname: str = Field(..., description="Asset hostname")
    ip_address: str = Field(..., description="Asset IP address")
    role: str = Field(..., description="Asset role/function")
    risk_level: str = Field(
        ..., description="Risk level for this asset (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    vulnerable_software: List[str] = Field(
        default_factory=list, description="Identified vulnerable software"
    )
    security_concerns: List[str] = Field(
        default_factory=list, description="Specific security concerns for this asset"
    )

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v):
        """Validate risk level values"""
        valid_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Risk level must be one of: {valid_levels}")
        return v.upper()


class TTPAnalysisResult(BaseModel):
    """Analysis result for observed TTPs"""

    model_config = {
        "json_schema_extra": {
            "example": {
                "framework": "MITRE ATT&CK",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "confidence": "HIGH",
                "evidence": "Multiple failed login attempts observed in authentication logs from source IP 203.0.113.45",
                "mitre_link": "https://attack.mitre.org/techniques/T1110/",
            }
        }
    }

    framework: str = Field(..., description="Framework (e.g., MITRE ATT&CK)")
    technique_id: str = Field(..., description="Technique ID (e.g., T1110)")
    technique_name: str = Field(..., description="Technique name")
    confidence: str = Field(..., description="Confidence level (HIGH, MEDIUM, LOW)")
    evidence: str = Field(
        ..., description="Evidence supporting this TTP identification"
    )
    mitre_link: Optional[str] = Field(None, description="MITRE ATT&CK link")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v):
        """Validate confidence values"""
        valid_confidence = ["HIGH", "MEDIUM", "LOW"]
        if v.upper() not in valid_confidence:
            raise ValueError(f"Confidence must be one of: {valid_confidence}")
        return v.upper()

    @field_validator("mitre_link", mode="before")
    @classmethod
    def generate_mitre_link(cls, v, info):
        """Generate MITRE link if not provided"""
        values = info.data
        if v is None and "technique_id" in values:
            technique_id = values["technique_id"]
            if technique_id:
                return f"https://attack.mitre.org/techniques/{technique_id}/"
        return v


class InitialAnalysisResult(BaseModel):
    """Complete initial incident and CVE analysis result"""

    model_config = {
        "json_schema_extra": {
            "example": {
                "incident_id": "INC-2024-001",
                "analysis_timestamp": "2024-06-05T10:30:00Z",
                "affected_assets_analysis": [
                    {
                        "hostname": "web-server-01",
                        "ip_address": "192.168.1.100",
                        "role": "Web Server",
                        "risk_level": "HIGH",
                        "vulnerable_software": ["nginx 1.18.0"],
                        "security_concerns": [
                            "Exposed to internet",
                            "Outdated software",
                        ],
                    }
                ],
                "observed_ttps_analysis": [
                    {
                        "framework": "MITRE ATT&CK",
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "confidence": "HIGH",
                        "evidence": "Multiple failed login attempts",
                        "mitre_link": "https://attack.mitre.org/techniques/T1110/",
                    }
                ],
                "initial_findings_summary": "Web server under brute force attack with vulnerable software",
                "key_indicators": ["Repeated login failures", "Source IP 203.0.113.45"],
                "relevant_cves": [
                    {
                        "cve_id": "CVE-2023-44487",
                        "relevance_score": 8.5,
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "affected_software": ["nginx"],
                        "description": "HTTP/2 Rapid Reset vulnerability",
                        "exploitation_likelihood": "HIGH",
                        "rationale": "Affects web server infrastructure",
                        "nvd_link": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
                    }
                ],
                "overall_severity": "HIGH",
                "immediate_actions_needed": [
                    "Block suspicious IP addresses",
                    "Update nginx to latest version",
                    "Enable rate limiting",
                ],
                "investigation_rationale": "Need deeper analysis of attack patterns and potential data exfiltration",
            }
        }
    }

    incident_id: str = Field(..., description="Reference to the original incident ID")
    analysis_timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="When this analysis was completed"
    )

    # Asset Analysis
    affected_assets_analysis: List[AssetAnalysisResult] = Field(
        ..., description="Analysis of each affected asset"
    )

    # TTP Analysis
    observed_ttps_analysis: List[TTPAnalysisResult] = Field(
        ..., description="Analysis of observed tactics, techniques, and procedures"
    )

    # Initial Findings
    initial_findings_summary: str = Field(
        ..., description="Summary of initial findings and key insights"
    )
    key_indicators: List[str] = Field(
        default_factory=list,
        description="Key indicators of compromise or attack patterns",
    )

    # CVE Analysis
    relevant_cves: List[CVEAnalysisResult] = Field(
        ..., description="List of relevant CVEs identified and analyzed"
    )

    # Overall Assessment
    overall_severity: str = Field(
        ..., description="Overall incident severity assessment"
    )
    immediate_actions_needed: List[str] = Field(
        default_factory=list, description="Immediate actions that should be taken"
    )

    investigation_rationale: Optional[str] = Field(
        None, description="Rationale for additional investigation if needed"
    )

    @field_validator("overall_severity")
    @classmethod
    def validate_overall_severity(cls, v):
        """Validate overall severity"""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if v.upper() not in valid_severities:
            raise ValueError(f"Overall severity must be one of: {valid_severities}")
        return v.upper()

    @field_validator("affected_assets_analysis")
    @classmethod
    def validate_assets_exist(cls, v):
        """Ensure at least one asset is analyzed"""
        if not v:
            raise ValueError("At least one asset must be analyzed")
        return v


@tool
def submit_initial_analysis_final_answer(
    incident_id: str,
    affected_assets_analysis: List[AssetAnalysisResult],
    observed_ttps_analysis: List[TTPAnalysisResult],
    initial_findings_summary: str,
    relevant_cves: List[CVEAnalysisResult],
    overall_severity: str,
    incident_vulnerability_report: Annotated[
        IncidentVulnerabilityReport, InjectedToolArg
    ],
    key_indicators: Optional[List[str]] = None,
    immediate_actions_needed: Optional[List[str]] = None,
    investigation_rationale: Optional[str] = None,
) -> str:
    """
    Submit your analysis for the incident CVE data once you have completed your initial investigation.

    Args:
        incident_id: Reference to the original incident ID
        affected_assets_analysis: List of asset analysis results containing hostname, ip_address,
                                role, risk_level, vulnerable_software, and security_concerns
        observed_ttps_analysis: List of TTP analysis results containing framework, technique_id,
                              technique_name, confidence, evidence, and optional mitre_link
        initial_findings_summary: Summary of initial findings and key insights
        relevant_cves: List of CVE analysis results containing cve_id, relevance_score, severity,
                      affected_software, description, exploitation_likelihood, rationale, and optional nvd_link
        overall_severity: Overall incident severity (CRITICAL, HIGH, MEDIUM, LOW)
        key_indicators: Optional list of key indicators of compromise or attack patterns
        immediate_actions_needed: Optional list of immediate actions that should be taken
        investigation_rationale: Rationale for additional investigation if needed

    Returns:
        JSON string containing the validated and structured initial analysis result
    """
    try:

        # Create the complete analysis result
        analysis_result = InitialAnalysisResult(
            incident_id=incident_id,
            affected_assets_analysis=affected_assets_analysis,
            observed_ttps_analysis=observed_ttps_analysis,
            initial_findings_summary=initial_findings_summary,
            relevant_cves=relevant_cves,
            overall_severity=overall_severity,
            key_indicators=key_indicators or [],
            immediate_actions_needed=immediate_actions_needed or [],
            investigation_rationale=investigation_rationale,
        )

        # Validate the analysis result against the incident vulnerability report
        validate_initial_analysis_result(
            analysis_result=analysis_result,
            incident_vulnerability_report=incident_vulnerability_report,
        )

        # Convert to JSON for return
        result_dict = analysis_result.model_dump()
        result_dict["analysis_timestamp"] = (
            analysis_result.analysis_timestamp.isoformat()
        )

        # Add validation summary
        validation_summary = {
            "validation_status": "PASSED",
            "assets_analyzed": len(affected_assets_analysis),
            "ttps_identified": len(observed_ttps_analysis),
            "cves_analyzed": len(relevant_cves),
            "overall_severity": overall_severity,
        }

        final_result = {
            "stage": "initial_incident_and_cve_analysis",
            "analysis_result": result_dict,
            "validation_summary": validation_summary,
        }

        return json.dumps(final_result, indent=2)

    except Exception as e:
        # Return validation error information
        error_result = {
            "stage": "initial_incident_and_cve_analysis",
            "validation_status": "FAILED",
            "error": str(e),
            "error_type": type(e).__name__,
            "incident_id": incident_id,
        }
        return json.dumps(error_result, indent=2)


@dataclass
class ValidationError(Exception):
    """Custom exception for validation failures"""

    message: str
    validation_type: str
    details: List[str]


def validate_initial_analysis_result(
    analysis_result: InitialAnalysisResult,
    incident_vulnerability_report: IncidentVulnerabilityReport,
) -> None:
    """
    Validate that the InitialAnalysisResult is consistent with the IncidentVulnerabilityReport.

    Args:
        analysis_result: The initial analysis result to validate
        incident_vulnerability_report: The vulnerability report to validate against

    Raises:
        ValidationError: If validation fails with details about the failure
    """
    validation_errors = []

    # Extract reference data from vulnerability report
    report_software = {
        (sw.software.name.lower(), sw.software.version.lower())
        for sw in incident_vulnerability_report.software_reports
    }

    # Create mapping of CVE ID to CVE info for detailed validation
    cve_id_to_info = {
        cve.cve_id.upper(): cve
        for sw_report in incident_vulnerability_report.software_reports
        for cve in sw_report.cves
    }

    # Create mapping of software to CVEs
    software_to_cves = {}
    for sw_report in incident_vulnerability_report.software_reports:
        sw_key = (sw_report.software.name.lower(), sw_report.software.version.lower())
        software_to_cves[sw_key] = [cve.cve_id.upper() for cve in sw_report.cves]

    # Validate software consistency
    _validate_software_consistency(
        analysis_result.affected_assets_analysis, report_software, validation_errors
    )

    # Validate severity and scoring consistency
    _validate_severity_consistency(
        analysis_result.relevant_cves, cve_id_to_info, validation_errors
    )

    # Validate risk level correlation
    _validate_risk_level_correlation(
        analysis_result.affected_assets_analysis,
        software_to_cves,
        cve_id_to_info,
        validation_errors,
    )

    # If there are validation errors, raise an exception
    if validation_errors:
        raise ValidationError(
            message=f"Initial analysis validation failed with {len(validation_errors)} error(s)",
            validation_type="BASIC_VALIDATION",  # We should do a more thorough validation
            details=validation_errors,
        )


def _validate_software_consistency(
    affected_assets_analysis: List[AssetAnalysisResult],
    report_software: Set[Tuple[str, str]],
    validation_errors: List[str],
) -> None:
    """Validate software consistency between analysis and report"""

    for asset_analysis in affected_assets_analysis:
        for vuln_software in asset_analysis.vulnerable_software:
            # Parse software string (handle various formats like "nginx 1.18.0", "openssl 1.1.1")
            parsed_software = _parse_software_string(vuln_software)

            if parsed_software:
                software_name, software_version = parsed_software
                software_key = (software_name.lower(), software_version.lower())

                # Check if this software exists in the vulnerability report
                if software_key not in report_software:
                    # Try to find partial matches for more helpful error messages
                    name_matches = [
                        sw for sw in report_software if sw[0] == software_name.lower()
                    ]
                    if name_matches:
                        validation_errors.append(
                            f"Asset {asset_analysis.hostname}: Software '{vuln_software}' version not found in vulnerability report. "
                            f"Available versions for {software_name}: {[sw[1] for sw in name_matches]}"
                        )
                    else:
                        validation_errors.append(
                            f"Asset {asset_analysis.hostname}: Software '{vuln_software}' not found in vulnerability report"
                        )


def _validate_severity_consistency(
    relevant_cves: List[CVEAnalysisResult],
    cve_id_to_info: Dict[str, CVEInfo],
    validation_errors: List[str],
) -> None:
    """Validate severity level consistency"""

    # Define severity hierarchy for validation
    severity_hierarchy = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for cve_analysis in relevant_cves:
        cve_id_upper = cve_analysis.cve_id.upper()

        if cve_id_upper in cve_id_to_info:
            cve_info = cve_id_to_info[cve_id_upper]

            # Check exploitation likelihood vs severity alignment
            if (
                cve_analysis.exploitation_likelihood == "HIGH"
                and cve_analysis.severity in ["LOW", "MEDIUM"]
            ):
                validation_errors.append(
                    f"CVE {cve_analysis.cve_id}: High exploitation likelihood inconsistent with "
                    f"{cve_analysis.severity} severity"
                )

            # Check relevance score vs severity alignment
            if cve_analysis.relevance_score >= 8.0 and cve_analysis.severity in [
                "LOW",
                "MEDIUM",
            ]:
                validation_errors.append(
                    f"CVE {cve_analysis.cve_id}: High relevance score ({cve_analysis.relevance_score}) "
                    f"inconsistent with {cve_analysis.severity} severity"
                )


def _validate_risk_level_correlation(
    affected_assets_analysis: List[AssetAnalysisResult],
    software_to_cves: Dict[Tuple[str, str], List[str]],
    cve_id_to_info: Dict[str, CVEInfo],
    validation_errors: List[str],
) -> None:
    """Validate that asset risk levels correlate with vulnerability severity"""

    for asset in affected_assets_analysis:
        # Calculate expected risk level based on vulnerabilities
        max_severity_score = 0
        critical_count = 0
        high_count = 0

        for vuln_software in asset.vulnerable_software:
            parsed = _parse_software_string(vuln_software)
            if parsed:
                software_key = (parsed[0].lower(), parsed[1].lower())
                if software_key in software_to_cves:
                    for cve_id in software_to_cves[software_key]:
                        if cve_id in cve_id_to_info:
                            cve_info = cve_id_to_info[cve_id]
                            if cve_info.cvss_v3_severity == "CRITICAL":
                                critical_count += 1
                                max_severity_score = max(max_severity_score, 4)
                            elif cve_info.cvss_v3_severity == "HIGH":
                                high_count += 1
                                max_severity_score = max(max_severity_score, 3)

        # Validate risk level alignment
        if critical_count > 0 and asset.risk_level not in ["CRITICAL", "HIGH"]:
            validation_errors.append(
                f"Asset {asset.hostname}: Risk level '{asset.risk_level}' too low for "
                f"{critical_count} critical vulnerabilities"
            )
        elif high_count > 2 and asset.risk_level in ["LOW", "MEDIUM"]:
            validation_errors.append(
                f"Asset {asset.hostname}: Risk level '{asset.risk_level}' too low for "
                f"{high_count} high severity vulnerabilities"
            )


def _parse_software_string(software_string: str) -> Tuple[str, str] | None:
    """
    Parse software string to extract name and version.
    Handles formats like: "nginx 1.18.0", "openssl 1.1.1", "Apache Tomcat 9.0.50"
    """
    # Common patterns for software strings
    patterns = [
        r"^(.+?)\s+(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?(?:-[a-zA-Z0-9]+)*)$",  # "name version"
        r"^(.+?)\s+v(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?(?:-[a-zA-Z0-9]+)*)$",  # "name vversion"
        r"^(.+?)\s+version\s+(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?(?:-[a-zA-Z0-9]+)*)$",  # "name version X"
    ]

    for pattern in patterns:
        match = re.match(pattern, software_string.strip(), re.IGNORECASE)
        if match:
            return match.group(1).strip(), match.group(2).strip()

    # If no pattern matches, return None
    return None


# Export the tools for use in LangGraph
initial_analysis_stage_tools = [submit_initial_analysis_final_answer]
