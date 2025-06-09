"""
Submit Research Tool

LangChain tool for submitting structured incident research results.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Annotated
from langchain_core.tools import tool, InjectedToolArg
from pydantic import BaseModel, Field, ConfigDict

from .incident_research_result import (
    IncidentResearchResult,
    CVEResearchFinding,
    SoftwareResearchFinding,
    ThreatIntelligenceFinding,
    ResearchGap,
    ResearchConfidence,
)
from ...models.incident_vulnerability_report import IncidentVulnerabilityReport
from ...models.incident import IncidentData


class ResearchValidationResult(BaseModel):
    """Wrapper for research results with validation information"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "research": {
                    "incident_id": "INC-2023-08-01-001",
                    "research_timestamp": "2023-08-01T10:30:00Z",
                    "researcher_confidence": 8.5,
                    "research_summary": "Research summary...",
                },
                "validation_passed": True,
                "validation_summary": "Research passed validation successfully",
                "messages": [],
            }
        },
    )

    research: IncidentResearchResult = Field(
        ..., description="The validated research result"
    )
    validation_passed: bool = Field(..., description="Whether validation passed")
    validation_summary: str = Field(..., description="Summary of validation results")
    messages: List[dict] = Field(
        default_factory=list,
        description="Messages exchanged during the research process",
    )


class ResearchValidator:
    """Validator for incident research results"""

    def __init__(
        self,
        incident_data: IncidentData,
        incident_vulnerability_report: IncidentVulnerabilityReport,
        messages: List[dict],
    ):
        self.incident_data = incident_data
        self.incident_vulnerability_report = incident_vulnerability_report
        self.messages = messages

    def validate(self, research: IncidentResearchResult) -> ResearchValidationResult:
        """Validate the research result against incident data"""

        # Basic validation checks
        validation_passed = True
        validation_issues = []

        # Validate incident ID matches
        if research.incident_id != self.incident_data.incident_id:
            validation_passed = False
            validation_issues.append(
                f"Incident ID mismatch: research has '{research.incident_id}' but incident data has '{self.incident_data.incident_id}'"
            )

        # Validate confidence is in valid range
        if not (0 <= research.researcher_confidence <= 10):
            validation_passed = False
            validation_issues.append(
                f"Researcher confidence must be between 0-10, got {research.researcher_confidence}"
            )

        # Validate research duration is reasonable
        if research.research_duration_minutes < 0:
            validation_passed = False
            validation_issues.append(
                f"Research duration cannot be negative: {research.research_duration_minutes}"
            )

        # Create summary
        if validation_passed:
            if validation_issues:
                summary = f"Research passed validation with {len(validation_issues)} minor issue(s)"
            else:
                summary = "Research passed validation successfully"
        else:
            summary = f"Research failed validation with {len(validation_issues)} issue(s): {'; '.join(validation_issues)}"

        return ResearchValidationResult(
            research=research,
            validation_passed=validation_passed,
            validation_summary=summary,
            messages=self.messages,
        )


@tool
def submit_research(
    incident_id: str,
    research_timestamp: datetime,
    research_duration_minutes: int,
    researcher_confidence: float,
    research_summary: str,
    cve_findings: List[CVEResearchFinding],
    software_findings: List[SoftwareResearchFinding],
    threat_intelligence_findings: List[ThreatIntelligenceFinding],
    research_gaps: List[ResearchGap],
    total_sources_consulted: int,
    research_methodology: str,
    key_discoveries: List[str],
    research_limitations: List[str],
    recommended_next_steps: List[str],
    enriched_incident_context: Dict[str, Any],
    research_notes: List[str],
    incident_vulnerability_report: Annotated[
        IncidentVulnerabilityReport, InjectedToolArg
    ],
    incident_data: Annotated[IncidentData, InjectedToolArg],
    messages: Annotated[List[dict], InjectedToolArg],
) -> ResearchValidationResult:
    """
    Submit comprehensive incident research results.

    Args:
        incident_id: Unique identifier for the incident being researched
        research_timestamp: When this research was completed
        research_duration_minutes: How long the research took in minutes
        researcher_confidence: Confidence level in the research (0-10 scale)
        research_summary: High-level summary of research conducted
        cve_findings: List of CVE research findings
        software_findings: List of software research findings
        threat_intelligence_findings: List of threat intelligence findings
        research_gaps: List of identified research gaps
        total_sources_consulted: Total number of sources consulted
        research_methodology: Methodology used for research
        key_discoveries: Key discoveries made during research
        research_limitations: Limitations encountered during research
        recommended_next_steps: Recommended next steps for analysis
        enriched_incident_context: A dictionary of additional context discovered about the incident
        research_notes: Additional research notes and observations
    """

    # Construct the research result
    research = IncidentResearchResult(
        incident_id=incident_id,
        research_timestamp=research_timestamp,
        research_duration_minutes=research_duration_minutes,
        researcher_confidence=researcher_confidence,
        research_summary=research_summary,
        cve_findings=cve_findings,
        software_findings=software_findings,
        threat_intelligence_findings=threat_intelligence_findings,
        research_gaps=research_gaps,
        total_sources_consulted=total_sources_consulted,
        research_methodology=research_methodology,
        key_discoveries=key_discoveries,
        research_limitations=research_limitations,
        recommended_next_steps=recommended_next_steps,
        enriched_incident_context=enriched_incident_context,
        research_notes=research_notes,
    )

    # Create validator and validate the research
    validator = ResearchValidator(
        incident_data=incident_data,
        incident_vulnerability_report=incident_vulnerability_report,
        messages=messages,
    )

    return validator.validate(research)


# Export the tools for use
submit_research_tools = [submit_research]
