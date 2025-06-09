"""
Incident Data Models

Core data structures for security incident representation based on the sample data format.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Literal
from .ioc_types import IOCType
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class SoftwareInfo(BaseModel):
    """Information about installed software on an asset"""

    name: str = Field(..., description="Software name")
    version: str = Field(..., description="Software version")
    cpe_string: Optional[str] = Field(None, description="Generated CPE string for this software")

    class Config:
        schema_extra = {
            "example": {
                "name": "Apache Tomcat", 
                "version": "9.0.50",
                "cpe_string": "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"
            }
        }


class AssetData(BaseModel):
    """Information about an affected asset"""

    hostname: str = Field(..., description="Asset hostname")
    ip_address: str = Field(..., description="Asset IP address")
    os: str = Field(..., description="Operating system")
    installed_software: List[SoftwareInfo] = Field(
        default_factory=list, description="List of installed software"
    )
    role: str = Field(..., description="Asset role/function")
    cpe_strings: List[str] = Field(
        default_factory=list, description="Generated CPE strings for this asset (OS, hardware, etc.)"
    )

    # Don't validate IP, since we can have other values like 'unknown' or 'N/A'
    # @field_validator("ip_address")
    # @classmethod
    # def validate_ip_format(cls, v):
    #     """Basic IP address format validation"""
    #     # Simple validation - could be enhanced with ipaddress module
    #     parts = v.split(".")
    #     if len(parts) != 4:
    #         raise ValueError("Invalid IP address format")
    #     return v

    class Config:
        schema_extra = {
            "example": {
                "hostname": "web-app-server-05",
                "ip_address": "10.10.5.20",
                "os": "CentOS 7",
                "installed_software": [
                    {
                        "name": "Apache Tomcat", 
                        "version": "9.0.50",
                        "cpe_string": "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"
                    },
                    {
                        "name": "MySQL Connector/J", 
                        "version": "8.0.25",
                        "cpe_string": "cpe:2.3:a:mysql:connector%2fj:8.0.25:*:*:*:*:*:*:*"
                    },
                ],
                "role": "Internal Web Application Server",
                "cpe_strings": [
                    "cpe:2.3:o:centos:centos:7:*:*:*:*:*:*:*"
                ]
            }
        }


class TTPData(BaseModel):
    """MITRE ATT&CK Tactics, Techniques, and Procedures data"""

    framework: str = Field(..., description="Framework name (e.g., 'MITRE ATT&CK')")
    id: str = Field(..., description="Technique ID (e.g., 'T1110')")
    name: str = Field(..., description="Technique name")

    class Config:
        schema_extra = {
            "example": {
                "framework": "MITRE ATT&CK",
                "id": "T1110",
                "name": "Brute Force",
            }
        }


class IOCData(BaseModel):
    """Indicator of Compromise data"""

    type: IOCType = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    context: str = Field(..., description="Context or description of the indicator")

    class Config:
        schema_extra = {
            "example": {
                "type": "ip_address",
                "value": "172.91.8.123",
                "context": "Source IP of successful login",
            }
        }


class IncidentData(BaseModel):
    """Complete incident data structure"""

    incident_id: str = Field(..., description="Unique incident identifier")
    timestamp: datetime = Field(..., description="Incident timestamp")
    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Detailed incident description")
    affected_assets: List[AssetData] = Field(..., description="List of affected assets")
    observed_ttps: List[TTPData] = Field(
        default_factory=list, description="Observed tactics, techniques, and procedures"
    )
    indicators_of_compromise: List[IOCData] = Field(
        default_factory=list, description="Indicators of compromise"
    )
    initial_findings: str = Field(..., description="Initial analysis findings")

    # Optional fields for enhanced data
    severity: Optional[str] = Field(None, description="Incident severity level")
    source: Optional[str] = Field(None, description="Detection source")
    analyst: Optional[str] = Field(None, description="Assigned analyst")
    status: Optional[str] = Field(None, description="Incident status")

    @field_validator("affected_assets")
    @classmethod
    def validate_assets_not_empty(cls, v):
        """Ensure at least one affected asset"""
        if not v:
            raise ValueError("At least one affected asset is required")
        return v

    @property
    def asset_count(self) -> int:
        """Number of affected assets"""
        return len(self.affected_assets)

    @property
    def ttp_count(self) -> int:
        """Number of observed TTPs"""
        return len(self.observed_ttps)

    @property
    def ioc_count(self) -> int:
        """Number of IOCs"""
        return len(self.indicators_of_compromise)    

    def get_assets_by_role(self, role: str) -> List[AssetData]:
        """Get assets filtered by role"""
        return [
            asset
            for asset in self.affected_assets
            if role.lower() in asset.role.lower()
        ]

    def get_iocs_by_type(self, ioc_type: IOCType) -> List[IOCData]:
        """Get IOCs filtered by type"""
        return [ioc for ioc in self.indicators_of_compromise if ioc.type == ioc_type]
    
    def get_all_cpes(self) -> Dict[str, List[str]]:
        """Get all CPE strings from all assets and software"""
        all_cpes = {
            "asset_cpes": [],
            "software_cpes": [],
            "total_count": 0
        }

        for asset in self.affected_assets:
            # Add asset-level CPEs
            all_cpes["asset_cpes"].extend(asset.cpe_strings)

            # Add software CPEs
            for software in asset.installed_software:
                if software.cpe_string:
                    all_cpes["software_cpes"].append(software.cpe_string)

        all_cpes["total_count"] = len(all_cpes["asset_cpes"]) + len(all_cpes["software_cpes"])
        return all_cpes

    def get_unique_software(self) -> List[SoftwareInfo]:
        """Get unique software across all affected assets"""
        software_set = set()
        unique_software = []

        for asset in self.affected_assets:
            for software in asset.installed_software:
                software_key = (software.name, software.version)
                if software_key not in software_set:
                    software_set.add(software_key)
                    unique_software.append(software)

        return unique_software

    class Config:
        schema_extra = {
            "example": {
                "incident_id": "INC-2023-08-01-001",
                "timestamp": "2023-08-01T09:15:00Z",
                "title": "Example VPN Brute Force Attack",
                "description": "A successful brute force attack was detected against the VPN gateway.",
                "affected_assets": [
                    {
                        "hostname": "vpn-gateway-01",
                        "ip_address": "203.0.113.1",
                        "os": "Cisco IOS XE",
                        "installed_software": [
                            {"name": "Cisco IOS XE", "version": "17.3.4a"}
                        ],
                        "role": "VPN Gateway",
                    }
                ],
                "observed_ttps": [
                    {"framework": "MITRE ATT&CK", "id": "T1110", "name": "Brute Force"},
                    {
                        "framework": "MITRE ATT&CK",
                        "id": "T1078",
                        "name": "Valid Accounts",
                    },
                ],
                "indicators_of_compromise": [
                    {
                        "type": "ip_address",
                        "value": "172.91.8.123",
                        "context": "Source IP of successful login",
                    },
                    {
                        "type": "username",
                        "value": "admin",
                        "context": "Account used for successful login",
                    },
                ],
                "initial_findings": "Credential stuffing or brute force attack successful against VPN.",
            }
        }


class IncidentBatch(BaseModel):
    """Collection of incidents for batch processing"""
    incidents: List[IncidentData] = Field(..., description="List of incidents")
    batch_id: Optional[str] = Field(None, description="Batch identifier")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Batch creation time"
    )

    @property
    def incident_count(self) -> int:
        """Number of incidents in batch"""
        return len(self.incidents)

    @property
    def total_assets(self) -> int:
        """Total number of affected assets across all incidents"""
        return sum(incident.asset_count for incident in self.incidents)

    def get_incidents_by_severity(self, severity: str) -> List[IncidentData]:
        """Get incidents filtered by severity"""
        return [
            incident
            for incident in self.incidents
            if incident.severity and incident.severity.lower() == severity.lower()
        ]

    class Config:
        schema_extra = {
            "example": {
                "incidents": [],  # Would contain IncidentData objects
                "batch_id": "BATCH-2023-08-01-001",
                "created_at": "2023-08-01T10:00:00Z",
            }
        }


