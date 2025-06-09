"""
Incident Research Result Models

Data models for structured incident research results from the research stage.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum


class ResearchConfidence(str, Enum):
    """Confidence levels for research findings"""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ResearchSource(BaseModel):
    """Information about a research source"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "source_type": "nvd_database",
                "source_name": "National Vulnerability Database",
                "query_used": "search_cves_by_keyword",
                "timestamp": "2023-08-01T10:30:00Z",
                "reliability": "high",
            }
        },
    )

    source_type: str = Field(
        ..., description="Type of source (e.g., nvd_database, threat_intel)"
    )
    source_name: str = Field(..., description="Name of the source")
    query_used: str = Field(
        ..., description="Query or method used to obtain information"
    )
    timestamp: datetime = Field(..., description="When this source was consulted")
    reliability: str = Field(..., description="Reliability assessment of this source")


class CVEResearchFinding(BaseModel):
    """Research findings for a specific CVE"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2023-12345",
                "discovery_method": "keyword_search",
                "relevance_to_incident": "High - affects primary web server software",
                "additional_context": "Recently disclosed, active exploitation reported",
                "exploitation_indicators": ["Public PoC available", "CISA KEV listed"],
                "related_cves": ["CVE-2023-12346", "CVE-2023-12347"],
                "confidence": "high",
                "sources": [],
            }
        },
    )

    cve_id: str = Field(..., description="CVE identifier")
    discovery_method: str = Field(
        ..., description="How this CVE was discovered during research"
    )
    relevance_to_incident: str = Field(
        ..., description="Why this CVE is relevant to the incident"
    )
    additional_context: str = Field(
        ..., description="Additional context discovered about this CVE"
    )
    exploitation_indicators: List[str] = Field(
        default_factory=list, description="Indicators of active exploitation"
    )
    related_cves: List[str] = Field(
        default_factory=list, description="Related CVEs discovered"
    )
    confidence: ResearchConfidence = Field(
        ..., description="Confidence in this finding"
    )
    sources: List[ResearchSource] = Field(
        default_factory=list, description="Sources for this finding"
    )


class SoftwareResearchFinding(BaseModel):
    """Research findings for software components"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "software_name": "Apache HTTP Server",
                "version": "2.4.41",
                "research_focus": "vulnerability_assessment",
                "key_findings": ["Multiple high-severity CVEs", "End-of-life version"],
                "vulnerability_summary": "15 critical, 23 high severity vulnerabilities",
                "upgrade_recommendations": "Upgrade to version 2.4.54 or later",
                "confidence": "high",
                "sources": [],
            }
        },
    )

    software_name: str = Field(..., description="Name of the software")
    version: str = Field(..., description="Version of the software")
    research_focus: str = Field(..., description="What aspect was researched")
    key_findings: List[str] = Field(
        default_factory=list, description="Key findings from research"
    )
    vulnerability_summary: str = Field(
        ..., description="Summary of vulnerabilities found"
    )
    upgrade_recommendations: str = Field(
        ..., description="Recommendations for upgrades"
    )
    confidence: ResearchConfidence = Field(..., description="Confidence in findings")
    sources: List[ResearchSource] = Field(
        default_factory=list, description="Sources for this research"
    )


class ThreatIntelligenceFinding(BaseModel):
    """Threat intelligence findings"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "finding_type": "ttp_context",
                "description": "T1190 technique commonly used with CVE-2023-12345",
                "relevance": "Matches observed attack pattern in incident",
                "threat_actor_context": "Associated with APT29 campaigns",
                "indicators": ["specific_file_hash", "c2_domain"],
                "confidence": "medium",
                "sources": [],
            }
        },
    )

    finding_type: str = Field(..., description="Type of threat intelligence finding")
    description: str = Field(..., description="Description of the finding")
    relevance: str = Field(..., description="Relevance to the current incident")
    threat_actor_context: Optional[str] = Field(
        None, description="Threat actor context if available"
    )
    indicators: List[str] = Field(
        default_factory=list, description="Associated indicators"
    )
    confidence: ResearchConfidence = Field(
        ..., description="Confidence in this intelligence"
    )
    sources: List[ResearchSource] = Field(
        default_factory=list, description="Sources for this intelligence"
    )


class ResearchGap(BaseModel):
    """Identified gaps in research"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "gap_type": "missing_software_analysis",
                "description": "Unable to find vulnerability data for custom application",
                "impact": "May miss critical vulnerabilities in custom software",
                "suggested_follow_up": "Manual code review or specialized scanning",
            }
        },
    )

    gap_type: str = Field(..., description="Type of research gap")
    description: str = Field(..., description="Description of what's missing")
    impact: str = Field(..., description="Potential impact of this gap")
    suggested_follow_up: str = Field(..., description="Suggested follow-up actions")


class IncidentResearchResult(BaseModel):
    """Complete research results for an incident"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "incident_id": "INC-2023-08-01-001",
                "research_timestamp": "2023-08-01T10:30:00Z",
                "research_duration_minutes": 45,
                "researcher_confidence": 8.5,
                "research_summary": "Comprehensive research completed on incident components",
                "cve_findings": [],
                "software_findings": [],
                "threat_intelligence_findings": [],
                "research_gaps": [],
                "total_sources_consulted": 12,
                "research_methodology": "Systematic analysis of all incident components",
                "key_discoveries": [
                    "New CVE affecting primary asset",
                    "Active exploitation campaign",
                ],
                "research_limitations": ["Limited threat intel access"],
                "recommended_next_steps": ["Proceed to analysis stage with findings"],
            }
        },
    )

    incident_id: str = Field(..., description="Unique identifier for the incident")
    research_timestamp: datetime = Field(..., description="When research was completed")
    research_duration_minutes: int = Field(
        ..., description="Duration of research in minutes"
    )
    researcher_confidence: float = Field(
        ..., description="Overall confidence in research (0-10 scale)"
    )
    research_summary: str = Field(
        ..., description="High-level summary of research conducted"
    )

    # Research findings
    cve_findings: List[CVEResearchFinding] = Field(
        default_factory=list, description="CVE research findings"
    )
    software_findings: List[SoftwareResearchFinding] = Field(
        default_factory=list, description="Software research findings"
    )
    threat_intelligence_findings: List[ThreatIntelligenceFinding] = Field(
        default_factory=list, description="Threat intelligence findings"
    )

    # Research metadata
    research_gaps: List[ResearchGap] = Field(
        default_factory=list, description="Identified research gaps"
    )
    total_sources_consulted: int = Field(
        ..., description="Total number of sources consulted"
    )
    research_methodology: str = Field(..., description="Methodology used for research")
    key_discoveries: List[str] = Field(
        default_factory=list, description="Key discoveries made during research"
    )
    research_limitations: List[str] = Field(
        default_factory=list, description="Limitations encountered during research"
    )
    recommended_next_steps: List[str] = Field(
        default_factory=list, description="Recommended next steps for analysis"
    )

    # Context preservation
    enriched_incident_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="A dictionary of additional context discovered about the incident",
    )
    research_notes: List[str] = Field(
        default_factory=list, description="Additional research notes and observations"
    )
