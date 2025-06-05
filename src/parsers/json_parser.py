"""
JSON Incident Parser

Parses incident data from JSON format matching the sample data structure.
"""

import json
import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from .base import IncidentParser, ParseResult, ParseIssue, ParseSeverity, ParseError
from src.models.incident import (
    IncidentData,
    AssetData,
    SoftwareInfo,
    TTPData,
    IOCData,
    IOCType,
)


class JSONIncidentParser(IncidentParser):
    """Parser for JSON-formatted incident data"""

    def __init__(self, parser_name: str = "json_v1"):
        super().__init__(parser_name)

        # Define required fields for basic incident parsing
        self.required_fields = [
            "incident_id",
            "title",
            "description",
            "affected_assets",
        ]

        # Define expected fields for validation
        self.expected_fields = {
            "incident_id": str,
            "timestamp": (str, datetime),
            "title": str,
            "description": str,
            "affected_assets": list,
            "observed_ttps": list,
            "indicators_of_compromise": list,
            "initial_findings": str,
        }

    def can_parse(self, data: Any) -> bool:
        """
        Check if this parser can handle the given data.

        Checks for JSON structure with required incident fields.
        """
        try:
            # Handle string data (JSON string)
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    return False

            # Must be a dictionary or list of dictionaries
            if isinstance(data, dict):
                # Check for key incident fields
                return (
                    "incident_id" in data
                    and "title" in data
                    and "affected_assets" in data
                )
            elif isinstance(data, list) and len(data) > 0:
                # Check first item in list
                first_item = data[0]
                if isinstance(first_item, dict):
                    return (
                        "incident_id" in first_item
                        and "title" in first_item
                        and "affected_assets" in first_item
                    )

            return False

        except Exception as e:
            self.logger.debug(f"Error checking if data can be parsed: {e}")
            return False

    def parse_single(self, data: Any) -> ParseResult:
        """Parse a single incident from JSON data"""
        start_time = time.time()

        try:
            # Handle string input
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError as e:
                    raise ParseError(f"Invalid JSON format: {e}")

            if not isinstance(data, dict):
                raise ParseError("Data must be a JSON object (dictionary)")

            # Create parse result
            result = ParseResult(
                success=False,  # Will be set to True if parsing succeeds
                parser_used=self.parser_name,
                raw_data=data,
            )

            # Validate required fields
            validation_issues = self._validate_required_fields(
                data, self.required_fields
            )
            result.issues.extend(validation_issues)

            # If critical validation errors, return early
            if any(
                issue.severity == ParseSeverity.ERROR for issue in validation_issues
            ):
                result.success = False
                return result

            # Parse incident fields with best-effort approach
            incident_data = self._parse_incident_fields(data, result)

            # Parse affected assets
            assets = self._parse_affected_assets(
                data.get("affected_assets", []), result
            )
            incident_data["affected_assets"] = assets

            # Parse TTPs
            ttps = self._parse_ttps(data.get("observed_ttps", []), result)
            incident_data["observed_ttps"] = ttps

            # Parse IOCs
            iocs = self._parse_iocs(data.get("indicators_of_compromise", []), result)
            incident_data["indicators_of_compromise"] = iocs

            # Create IncidentData object
            try:
                incident = IncidentData(**incident_data)
                result.incident = incident
                result.success = True

            except Exception as e:
                result.add_issue(
                    ParseSeverity.CRITICAL,
                    f"Failed to create IncidentData object: {e}",
                    suggested_fix="Check data structure and field types",
                )
                result.success = False

            # Calculate parse time
            parse_time = int((time.time() - start_time) * 1000)
            result.parse_time_ms = parse_time

            return result

        except ParseError as e:
            # Create failed result for parse errors
            result = ParseResult(
                success=False,
                parser_used=self.parser_name,
                raw_data=data if isinstance(data, dict) else {"raw": str(data)},
            )
            result.add_issue(
                ParseSeverity.CRITICAL, e.message, field=e.field, raw_value=e.raw_value
            )
            return result

        except Exception as e:
            # Create failed result for unexpected errors
            result = ParseResult(
                success=False,
                parser_used=self.parser_name,
                raw_data=data if isinstance(data, dict) else {"raw": str(data)},
            )
            result.add_issue(
                ParseSeverity.CRITICAL,
                f"Unexpected error during parsing: {e}",
                suggested_fix="Check data format and contact support",
            )
            return result

    def _parse_incident_fields(
        self, data: Dict[str, Any], result: ParseResult
    ) -> Dict[str, Any]:
        """Parse basic incident fields"""
        incident_data = {}

        # Required fields
        incident_data["incident_id"] = self._safe_extract(
            data, "incident_id", required=True
        )
        incident_data["title"] = self._safe_extract(data, "title", required=True)
        incident_data["description"] = self._safe_extract(
            data, "description", required=True
        )
        incident_data["initial_findings"] = self._safe_extract(
            data, "initial_findings", default=""
        )

        # Timestamp with fallback
        timestamp_raw = data.get("timestamp")
        if timestamp_raw:
            try:
                incident_data["timestamp"] = self._safe_parse_datetime(
                    timestamp_raw, "timestamp"
                )
            except Exception as e:
                result.add_issue(
                    ParseSeverity.WARNING,
                    f"Could not parse timestamp: {e}",
                    field="timestamp",
                    raw_value=timestamp_raw,
                    suggested_fix="Use ISO 8601 format",
                )
                incident_data["timestamp"] = datetime.now(timezone.utc)
        else:
            result.add_issue(
                ParseSeverity.WARNING,
                "Timestamp field missing, using current time",
                field="timestamp",
                suggested_fix="Add timestamp field",
            )
            incident_data["timestamp"] = datetime.now(timezone.utc)

        # Optional fields
        for field in ["severity", "source", "analyst", "status"]:
            if field in data:
                incident_data[field] = data[field]

        return incident_data

    def _parse_affected_assets(
        self, assets_data: List[Any], result: ParseResult
    ) -> List[AssetData]:
        """Parse affected assets with error handling"""
        assets = []

        if not isinstance(assets_data, list):
            result.add_issue(
                ParseSeverity.ERROR,
                "affected_assets must be a list",
                field="affected_assets",
                raw_value=type(assets_data).__name__,
            )
            return assets

        for i, asset_raw in enumerate(assets_data):
            try:
                if not isinstance(asset_raw, dict):
                    result.add_issue(
                        ParseSeverity.WARNING,
                        f"Asset {i} is not a dictionary, skipping",
                        field=f"affected_assets[{i}]",
                        raw_value=asset_raw,
                    )
                    continue

                # Parse software info
                software_list = []
                software_raw = asset_raw.get("installed_software", [])

                if isinstance(software_raw, list):
                    for j, software_item in enumerate(software_raw):
                        try:
                            if isinstance(software_item, dict):
                                software = SoftwareInfo(
                                    name=software_item.get("name", "Unknown"),
                                    version=software_item.get("version", "Unknown"),
                                )
                                software_list.append(software)
                            else:
                                result.add_issue(
                                    ParseSeverity.WARNING,
                                    f"Software item {j} in asset {i} is not a dictionary",
                                    field=f"affected_assets[{i}].installed_software[{j}]",
                                    raw_value=software_item,
                                )
                        except Exception as e:
                            result.add_issue(
                                ParseSeverity.WARNING,
                                f"Error parsing software item {j} in asset {i}: {e}",
                                field=f"affected_assets[{i}].installed_software[{j}]",
                            )

                # Create asset with required fields and best-effort parsing
                asset = AssetData(
                    hostname=asset_raw.get("hostname", f"unknown-host-{i}"),
                    ip_address=asset_raw.get("ip_address", "N/A"),
                    os=asset_raw.get("os", "Unknown"),
                    installed_software=software_list,
                    role=asset_raw.get("role", "Unknown"),
                )
                assets.append(asset)

            except Exception as e:
                result.add_issue(
                    ParseSeverity.WARNING,
                    f"Error parsing asset {i}: {e}",
                    field=f"affected_assets[{i}]",
                    raw_value=asset_raw,
                    suggested_fix="Check asset data structure",
                )

        # Ensure at least one asset exists
        if not assets:
            result.add_issue(
                ParseSeverity.ERROR,
                "No valid assets could be parsed",
                field="affected_assets",
                suggested_fix="Ensure at least one asset with hostname, ip_address, os, and role",
            )
            # Create a placeholder asset to prevent total failure
            assets.append(
                AssetData(
                    hostname="unknown-host",
                    ip_address="N/A",
                    os="Unknown",
                    role="Unknown",
                    installed_software=[],
                )
            )

        return assets

    def _parse_ttps(self, ttps_data: List[Any], result: ParseResult) -> List[TTPData]:
        """Parse TTPs with error handling"""
        ttps = []

        if not isinstance(ttps_data, list):
            result.add_issue(
                ParseSeverity.WARNING,
                "observed_ttps is not a list, treating as empty",
                field="observed_ttps",
                raw_value=type(ttps_data).__name__,
            )
            return ttps

        for i, ttp_raw in enumerate(ttps_data):
            try:
                if not isinstance(ttp_raw, dict):
                    result.add_issue(
                        ParseSeverity.WARNING,
                        f"TTP {i} is not a dictionary, skipping",
                        field=f"observed_ttps[{i}]",
                        raw_value=ttp_raw,
                    )
                    continue

                ttp = TTPData(
                    framework=ttp_raw.get("framework", "Unknown"),
                    id=ttp_raw.get("id", f"UNKNOWN-{i}"),
                    name=ttp_raw.get("name", "Unknown Technique"),
                )
                ttps.append(ttp)

            except Exception as e:
                result.add_issue(
                    ParseSeverity.WARNING,
                    f"Error parsing TTP {i}: {e}",
                    field=f"observed_ttps[{i}]",
                    raw_value=ttp_raw,
                )

        return ttps

    def _parse_iocs(self, iocs_data: List[Any], result: ParseResult) -> List[IOCData]:
        """Parse IOCs with error handling"""
        iocs = []

        if not isinstance(iocs_data, list):
            result.add_issue(
                ParseSeverity.WARNING,
                "indicators_of_compromise is not a list, treating as empty",
                field="indicators_of_compromise",
                raw_value=type(iocs_data).__name__,
            )
            return iocs

        for i, ioc_raw in enumerate(iocs_data):
            try:
                if not isinstance(ioc_raw, dict):
                    result.add_issue(
                        ParseSeverity.WARNING,
                        f"IOC {i} is not a dictionary, skipping",
                        field=f"indicators_of_compromise[{i}]",
                        raw_value=ioc_raw,
                    )
                    continue

                # Parse IOC type with fallback
                ioc_type_raw = ioc_raw.get("type", "unknown")
                try:
                    ioc_type = IOCType(ioc_type_raw)
                except ValueError:
                    result.add_issue(
                        ParseSeverity.WARNING,
                        f"Unknown IOC type '{ioc_type_raw}' for IOC {i}, using ip_address as fallback",
                        field=f"indicators_of_compromise[{i}].type",
                        raw_value=ioc_type_raw,
                        suggested_fix=f"Use one of: {', '.join([t.value for t in IOCType])}",
                    )
                    ioc_type = IOCType.IP_ADDRESS  # Default fallback

                ioc = IOCData(
                    type=ioc_type,
                    value=ioc_raw.get("value", "unknown"),
                    context=ioc_raw.get("context", "No context provided"),
                )
                iocs.append(ioc)

            except Exception as e:
                result.add_issue(
                    ParseSeverity.WARNING,
                    f"Error parsing IOC {i}: {e}",
                    field=f"indicators_of_compromise[{i}]",
                    raw_value=ioc_raw,
                )

        return iocs
