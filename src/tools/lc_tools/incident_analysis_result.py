"""
Incident Analysis Result Models

Pydantic models for structured LLM analysis results with comprehensive validation
and example schemas for proper JSON generation.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level enumeration for consistent categorization"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ExploitationLikelihood(str, Enum):
    """Exploitation likelihood enumeration for vulnerability assessment"""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"
    UNKNOWN = "unknown"


class CVEAnalysis(BaseModel):
    """Analysis of a specific CVE in the incident context"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2023-12345",
                "cvss_score": 8.5,
                "severity": "HIGH",
                "exploitation_likelihood": "high",
                "relevance_to_incident": 8.5,
                "affected_software": [
                    "Apache Tomcat 9.0.50",
                    "MySQL Connector/J 8.0.25",
                ],
                "attack_vector_alignment": "This CVE enables remote code execution which aligns with the observed unauthorized access patterns",
                "contextual_risk_assessment": "High risk due to internet-facing web server and observed exploitation attempts",
                "exploitation_evidence": "Log entries show requests matching known exploit patterns for this CVE",
                "mitigation_priority": 9,
            }
        },
    )

    cve_id: str = Field(..., description="CVE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score if available")
    severity: Optional[str] = Field(None, description="Severity level")
    exploitation_likelihood: ExploitationLikelihood = Field(
        ..., description="Likelihood of exploitation in this incident"
    )
    relevance_to_incident: float = Field(
        ..., description="Relevance score (0-10) to this specific incident"
    )
    affected_software: List[str] = Field(
        default_factory=list, description="Software affected by this CVE"
    )
    attack_vector_alignment: str = Field(
        ..., description="How this CVE aligns with observed attack vectors"
    )
    contextual_risk_assessment: str = Field(
        ..., description="Risk assessment specific to this incident context"
    )
    exploitation_evidence: Optional[str] = Field(
        None, description="Evidence suggesting this CVE was exploited"
    )
    mitigation_priority: int = Field(
        ..., description="Priority for mitigation (1-10, 10 being highest)"
    )


class AssetRiskAssessment(BaseModel):
    """Risk assessment for a specific affected asset"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "hostname": "web-app-server-05",
                "ip_address": "10.10.5.20",
                "role": "Internal Web Application Server",
                "overall_risk_level": "high",
                "vulnerability_count": 15,
                "critical_vulnerabilities": ["CVE-2023-12345", "CVE-2023-67890"],
                "network_exposure": "Internet-facing with limited firewall protection",
                "business_impact_potential": "High - serves customer-facing applications and contains sensitive data",
                "recommended_actions": [
                    "Immediately patch CVE-2023-12345",
                    "Implement additional network segmentation",
                    "Enable enhanced logging and monitoring",
                ],
                "compromise_indicators": [
                    "Unusual outbound network connections",
                    "Suspicious process execution",
                    "Unauthorized file modifications",
                ],
            }
        },
    )

    hostname: str = Field(..., description="Asset hostname")
    ip_address: str = Field(..., description="Asset IP address")
    role: str = Field(..., description="Asset role/function")
    overall_risk_level: RiskLevel = Field(
        ..., description="Overall risk level for this asset"
    )
    vulnerability_count: int = Field(
        ..., description="Number of vulnerabilities affecting this asset"
    )
    critical_vulnerabilities: List[str] = Field(
        default_factory=list, description="Critical CVEs affecting this asset"
    )
    network_exposure: str = Field(..., description="Assessment of network exposure")
    business_impact_potential: str = Field(
        ..., description="Potential business impact if compromised"
    )
    recommended_actions: List[str] = Field(
        default_factory=list, description="Specific actions for this asset"
    )
    compromise_indicators: List[str] = Field(
        default_factory=list, description="Indicators suggesting compromise"
    )


class TTPAnalysis(BaseModel):
    """Analysis of observed Tactics, Techniques, and Procedures"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "ttp_id": "T1110",
                "ttp_name": "Brute Force",
                "framework": "MITRE ATT&CK",
                "relevance_to_vulnerabilities": "Brute force attacks were enabled by weak authentication mechanisms and lack of account lockout policies",
                "attack_stage": "Initial Access",
                "supporting_cves": ["CVE-2023-12345"],
                "defensive_gaps": [
                    "No account lockout policy",
                    "Weak password requirements",
                    "Insufficient monitoring of failed login attempts",
                ],
                "detection_opportunities": [
                    "Monitor for multiple failed authentication attempts",
                    "Implement behavioral analysis for login patterns",
                    "Deploy honeypot accounts",
                ],
            }
        },
    )

    ttp_id: str = Field(..., description="TTP identifier (e.g., T1110)")
    ttp_name: str = Field(..., description="TTP name")
    framework: str = Field(..., description="Framework (e.g., MITRE ATT&CK)")
    relevance_to_vulnerabilities: str = Field(
        ..., description="How this TTP relates to identified vulnerabilities"
    )
    attack_stage: str = Field(..., description="Stage in the attack lifecycle")
    supporting_cves: List[str] = Field(
        default_factory=list, description="CVEs that could enable this TTP"
    )
    defensive_gaps: List[str] = Field(
        default_factory=list, description="Defensive gaps this TTP exploits"
    )
    detection_opportunities: List[str] = Field(
        default_factory=list, description="Opportunities for detection"
    )


class VulnerabilityChain(BaseModel):
    """Potential vulnerability exploitation chain"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "chain_id": "CHAIN-001",
                "description": "Initial access via web application vulnerability followed by privilege escalation",
                "cves_in_chain": ["CVE-2023-12345", "CVE-2023-67890"],
                "likelihood": "high",
                "impact_assessment": "Complete system compromise with potential for lateral movement to other network segments",
                "supporting_evidence": [
                    "Web server logs show exploitation attempts",
                    "System logs indicate privilege escalation activities",
                    "Network traffic analysis reveals lateral movement patterns",
                ],
            }
        },
    )

    chain_id: str = Field(..., description="Unique identifier for this chain")
    description: str = Field(..., description="Description of the attack chain")
    cves_in_chain: List[str] = Field(..., description="CVEs that form this chain")
    likelihood: ExploitationLikelihood = Field(
        ..., description="Likelihood of this chain being exploited"
    )
    impact_assessment: str = Field(
        ..., description="Potential impact if this chain is exploited"
    )
    supporting_evidence: List[str] = Field(
        default_factory=list, description="Evidence supporting this chain"
    )


class ActionableRecommendation(BaseModel):
    """Specific actionable recommendation"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "priority": 9,
                "category": "Immediate",
                "action": "Patch CVE-2023-12345 on all affected web servers",
                "rationale": "This vulnerability is actively being exploited and provides remote code execution capabilities",
                "affected_assets": ["web-app-server-05", "web-app-server-06"],
                "related_cves": ["CVE-2023-12345"],
                "estimated_effort": "4-6 hours including testing and deployment",
                "risk_reduction": "Eliminates primary attack vector and reduces overall incident risk by 70%",
            }
        },
    )

    priority: int = Field(..., description="Priority level (1-10, 10 being highest)")
    category: str = Field(
        ..., description="Category (e.g., 'Immediate', 'Short-term', 'Long-term')"
    )
    action: str = Field(..., description="Specific action to take")
    rationale: str = Field(..., description="Reasoning behind this recommendation")
    affected_assets: List[str] = Field(
        default_factory=list, description="Assets this recommendation applies to"
    )
    related_cves: List[str] = Field(
        default_factory=list, description="CVEs this recommendation addresses"
    )
    estimated_effort: str = Field(..., description="Estimated effort required")
    risk_reduction: str = Field(..., description="Expected risk reduction")


class IncidentAnalysisResult(BaseModel):
    """Complete structured analysis result from the LLM"""

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "incident_id": "INC-2023-08-01-001",
                "analysis_timestamp": "2023-08-01T10:30:00Z",
                "analyst_confidence": 8.5,
                "executive_summary": "A sophisticated brute force attack successfully compromised VPN credentials and gained access to internal web servers. Multiple critical vulnerabilities were identified that enabled lateral movement and privilege escalation.",
                "overall_risk_assessment": "high",
                "attack_sophistication": "Medium - Used common attack tools but showed knowledge of specific vulnerabilities",
                "prioritized_relevant_cves": [
                    {
                        "cve_id": "CVE-2023-12345",
                        "cvss_score": 8.5,
                        "severity": "HIGH",
                        "exploitation_likelihood": "high",
                        "relevance_to_incident": 9.0,
                        "affected_software": ["Apache Tomcat 9.0.50"],
                        "attack_vector_alignment": "Enables remote code execution matching observed attack patterns",
                        "contextual_risk_assessment": "Critical due to internet exposure and active exploitation",
                        "exploitation_evidence": "Log analysis shows exploit attempts matching this CVE",
                        "mitigation_priority": 10,
                    }
                ],
                "additional_cves_found": [],
                "cve_prioritization_rationale": "Prioritized based on active exploitation evidence, CVSS scores, and alignment with observed attack patterns",
                "asset_risk_assessments": [
                    {
                        "hostname": "web-app-server-05",
                        "ip_address": "10.10.5.20",
                        "role": "Internal Web Application Server",
                        "overall_risk_level": "high",
                        "vulnerability_count": 15,
                        "critical_vulnerabilities": ["CVE-2023-12345"],
                        "network_exposure": "Internet-facing with limited firewall protection",
                        "business_impact_potential": "High impact due to customer data access",
                        "recommended_actions": [
                            "Immediate patching",
                            "Network segmentation",
                        ],
                        "compromise_indicators": [
                            "Unusual network traffic",
                            "Suspicious processes",
                        ],
                    }
                ],
                "most_critical_assets": ["web-app-server-05"],
                "ttp_analysis": [
                    {
                        "ttp_id": "T1110",
                        "ttp_name": "Brute Force",
                        "framework": "MITRE ATT&CK",
                        "relevance_to_vulnerabilities": "Enabled by weak authentication and missing lockout policies",
                        "attack_stage": "Initial Access",
                        "supporting_cves": [],
                        "defensive_gaps": ["No account lockout", "Weak passwords"],
                        "detection_opportunities": [
                            "Monitor failed logins",
                            "Behavioral analysis",
                        ],
                    }
                ],
                "attack_progression": "Initial brute force against VPN, followed by lateral movement to web servers and privilege escalation",
                "potential_attack_chains": [
                    {
                        "chain_id": "CHAIN-001",
                        "description": "VPN compromise leading to web server exploitation",
                        "cves_in_chain": ["CVE-2023-12345"],
                        "likelihood": "high",
                        "impact_assessment": "Complete network compromise potential",
                        "supporting_evidence": ["Network logs", "System artifacts"],
                    }
                ],
                "most_likely_attack_path": "Brute force VPN credentials, lateral movement to web servers, exploit CVE-2023-12345 for privilege escalation",
                "threat_actor_assessment": "Likely opportunistic attacker with moderate technical skills",
                "environmental_factors": [
                    "Internet-facing services",
                    "Weak authentication policies",
                ],
                "detection_gaps": ["Limited VPN logging", "No behavioral monitoring"],
                "immediate_actions": [
                    {
                        "priority": 10,
                        "category": "Immediate",
                        "action": "Patch CVE-2023-12345",
                        "rationale": "Active exploitation observed",
                        "affected_assets": ["web-app-server-05"],
                        "related_cves": ["CVE-2023-12345"],
                        "estimated_effort": "4-6 hours",
                        "risk_reduction": "Eliminates primary attack vector",
                    }
                ],
                "short_term_recommendations": [],
                "long_term_recommendations": [],
                "reasoning_chain": [
                    "Analyzed incident data and identified brute force attack pattern",
                    "Correlated attack with vulnerable software versions",
                    "Assessed exploitation likelihood based on network exposure",
                    "Prioritized remediation based on risk and impact",
                ],
                "data_sources_used": [
                    "Incident report",
                    "Vulnerability database",
                    "Network logs",
                ],
                "limitations_and_assumptions": [
                    "Limited log retention",
                    "Assumed standard network architecture",
                ],
                "follow_up_investigations": [
                    "Deep packet inspection",
                    "Memory forensics",
                    "Timeline analysis",
                ],
            }
        },
    )

    # Meta information
    incident_id: str = Field(..., description="Incident identifier")
    analysis_timestamp: datetime = Field(
        default_factory=datetime.now, description="When analysis was performed"
    )
    analyst_confidence: float = Field(
        ..., description="Confidence level in analysis (0-10)"
    )

    # Executive Summary
    executive_summary: str = Field(..., description="High-level summary of findings")
    overall_risk_assessment: RiskLevel = Field(
        ..., description="Overall incident risk level"
    )
    attack_sophistication: str = Field(
        ..., description="Assessment of attack sophistication"
    )

    # CVE Analysis
    prioritized_relevant_cves: List[CVEAnalysis] = Field(
        default_factory=list, description="Prioritized list of detailed CVE analysis"
    )
    cve_prioritization_rationale: str = Field(
        ..., description="Explanation of CVE prioritization methodology"
    )

    # Asset Analysis
    asset_risk_assessments: List[AssetRiskAssessment] = Field(
        default_factory=list, description="Risk assessment for each affected asset"
    )
    most_critical_assets: List[str] = Field(
        default_factory=list, description="Hostnames of most critical assets"
    )

    # TTP Analysis
    ttp_analysis: List[TTPAnalysis] = Field(
        default_factory=list, description="Analysis of observed TTPs"
    )
    attack_progression: str = Field(
        ..., description="Assessment of attack progression and timeline"
    )

    # Attack Chain Analysis
    potential_attack_chains: List[VulnerabilityChain] = Field(
        default_factory=list, description="Potential vulnerability exploitation chains"
    )
    most_likely_attack_path: Optional[str] = Field(
        None, description="Most likely attack path based on evidence"
    )

    # Intelligence and Context
    threat_actor_assessment: Optional[str] = Field(
        None, description="Assessment of potential threat actor characteristics"
    )
    environmental_factors: List[str] = Field(
        default_factory=list, description="Environmental factors affecting the incident"
    )
    detection_gaps: List[str] = Field(
        default_factory=list, description="Identified detection gaps"
    )

    # Recommendations
    immediate_actions: Optional[List[ActionableRecommendation]] = Field(
        default_factory=list, description="Immediate response actions"
    )
    short_term_recommendations: Optional[List[ActionableRecommendation]] = Field(
        default_factory=list, description="Short-term improvements"
    )
    long_term_recommendations: Optional[List[ActionableRecommendation]] = Field(
        default_factory=list, description="Long-term strategic recommendations"
    )

    # Supporting Information
    reasoning_chain: List[str] = Field(
        default_factory=list, description="Step-by-step reasoning process"
    )
    data_sources_used: List[str] = Field(
        default_factory=list, description="Data sources consulted during analysis"
    )
    limitations_and_assumptions: List[str] = Field(
        default_factory=list, description="Analysis limitations and assumptions"
    )
    follow_up_investigations: List[str] = Field(
        default_factory=list, description="Recommended follow-up investigations"
    )
