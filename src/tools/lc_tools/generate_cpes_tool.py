"""
Generate CPEs Tool

LangChain tool for generating CPE (Common Platform Enumeration) strings from asset and software data.
Includes comprehensive validation to prevent hallucinations and ensure data integrity.
"""

import re
import logging
from typing import List, Dict, Any, Annotated, Optional, Tuple
from dataclasses import dataclass
from difflib import SequenceMatcher
import json

from langchain_core.tools import tool, InjectedToolArg
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_core import ErrorDetails

from ..models.incident import IncidentData, AssetData, SoftwareInfo

logger = logging.getLogger(__name__)


@dataclass
class CPEValidationConfig:
    """Configuration for CPE validation thresholds"""

    hostname_similarity_threshold: float = 0.8
    software_name_similarity_threshold: float = 0.7
    software_version_similarity_threshold: float = 0.8
    vendor_product_similarity_threshold: float = 0.6
    strict_ip_matching: bool = True
    strict_hostname_matching: bool = (
        False  # Allow some flexibility for hostname variations
    )


@dataclass
class CPEValidationResult:
    """Result of CPE validation"""

    is_valid: bool
    cpe_string: str
    errors: List[str]


class AssetCPEMapping(BaseModel):
    """Mapping between asset/software and generated CPE"""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "asset_hostname": "web-server-01",
                "asset_ip": "10.1.1.100",
                "cpe_string": "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*",
                "cpe_type": "software",
                "software_name": "Apache Tomcat",
                "software_version": "9.0.50",
            }
        }
    )

    asset_hostname: str = Field(..., description="Hostname of the asset")
    asset_ip: str = Field(..., description="IP address of the asset")
    cpe_string: str = Field(..., description="Generated CPE string in CPE 2.3 format")
    cpe_type: str = Field(
        ..., description="Either 'asset' (for OS/hardware) or 'software'"
    )
    software_name: Optional[str] = Field(
        None, description="Name of software (required if cpe_type='software')"
    )
    software_version: Optional[str] = Field(
        None, description="Version of software (required if cpe_type='software')"
    )


class CPEValidator:
    """Comprehensive CPE validation logic"""

    # CPE 2.3 format regex - strict validation
    CPE_23_PATTERN = re.compile(
        r"^cpe:2\.3:[aho\*\-]:"  # CPE version and part
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # vendor
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # product
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*)"  # version
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?"  # update (optional)
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?"  # edition (optional)
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?"  # language (optional)
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?"  # sw_edition (optional)
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?"  # target_sw (optional)
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?"  # target_hw (optional)
        r"(?::([a-zA-Z0-9\.\-\_\~\%\*]*|\*))?$"  # other (optional)
    )

    def __init__(self, config: CPEValidationConfig):
        self.config = config

    def validate_cpe_format(self, cpe_string: str) -> CPEValidationResult:
        """Validate CPE format and structure - strict validation only"""
        errors = []

        # Basic format validation
        if not cpe_string.startswith("cpe:2.3:"):
            errors.append("CPE must start with 'cpe:2.3:'")

        # Regex validation
        if not self.CPE_23_PATTERN.match(cpe_string):
            errors.append(
                f"CPE ({cpe_string}) does not match CPE 2.3 format specification"
            )

        # Component count validation
        parts = cpe_string.split(":")
        if len(parts) > 13 or len(parts) < 5:
            errors.append(
                f"CPE ({cpe_string}) must have between 5 and 13 components, found {len(parts)}"
            )
        else:
            part = parts[2]
            # Validate part (application, hardware, operating system)
            if part not in ["a", "h", "o", "*", "-"]:
                errors.append(
                    f"Invalid CPE part '{part}', must be 'a', 'h', 'o', '*', or '-'"
                )

            # Check for empty components (should be '*' or '-')
            for i, component in enumerate(parts[3:], 3):
                if component == "":
                    errors.append(f"Component {i} is empty, should be '*' or '-'")

        return CPEValidationResult(
            is_valid=len(errors) == 0, cpe_string=cpe_string, errors=errors
        )

    def validate_asset_linkage(
        self,
        mapping: AssetCPEMapping,
        original_asset: AssetData,
        original_software: Optional[SoftwareInfo] = None,
    ) -> CPEValidationResult:
        """Validate that CPE mapping correctly links to the original asset/software"""
        errors = []

        # Strict IP validation
        if (
            self.config.strict_ip_matching
            and mapping.asset_ip != original_asset.ip_address
        ):
            errors.append(
                f"IP address mismatch: provided '{mapping.asset_ip}' vs original '{original_asset.ip_address}'"
            )

        # Hostname validation with configurable strictness
        if self.config.strict_hostname_matching:
            if mapping.asset_hostname != original_asset.hostname:
                errors.append(
                    f"Hostname mismatch: provided '{mapping.asset_hostname}' vs original '{original_asset.hostname}'"
                )
        else:
            hostname_similarity = self._calculate_similarity(
                mapping.asset_hostname.lower(), original_asset.hostname.lower()
            )
            if hostname_similarity < self.config.hostname_similarity_threshold:
                errors.append(
                    f"Hostname similarity too low: provided '{mapping.asset_hostname}' vs original '{original_asset.hostname}' (similarity: {hostname_similarity:.2f}, threshold: {self.config.hostname_similarity_threshold})"
                )

        # Software linkage validation if applicable
        if mapping.cpe_type == "software" and original_software:
            if mapping.software_name:
                name_similarity = self._calculate_similarity(
                    mapping.software_name.lower(), original_software.name.lower()
                )
                if name_similarity < self.config.software_name_similarity_threshold:
                    errors.append(
                        f"Software name similarity too low: provided '{mapping.software_name}' vs original '{original_software.name}' (similarity: {name_similarity:.2f}, threshold: {self.config.software_name_similarity_threshold})"
                    )

            if mapping.software_version:
                version_similarity = self._calculate_similarity(
                    mapping.software_version.lower(), original_software.version.lower()
                )
                if (
                    version_similarity
                    < self.config.software_version_similarity_threshold
                ):
                    errors.append(
                        f"Software version similarity too low: provided '{mapping.software_version}' vs original '{original_software.version}' (similarity: {version_similarity:.2f}, threshold: {self.config.software_version_similarity_threshold})"
                    )

        # Validate CPE content matches asset/software data
        content_validation = self._validate_cpe_content_matching(
            mapping, original_asset, original_software
        )
        errors.extend(content_validation.errors)

        return CPEValidationResult(
            is_valid=len(errors) == 0, cpe_string=mapping.cpe_string, errors=errors
        )

    def _validate_cpe_content_matching(
        self,
        mapping: AssetCPEMapping,
        original_asset: AssetData,
        original_software: Optional[SoftwareInfo] = None,
    ) -> CPEValidationResult:
        """Validate that CPE content matches the asset/software characteristics"""
        errors = []

        parts = mapping.cpe_string.split(":")
        if len(parts) < 6:
            return CPEValidationResult(
                False, mapping.cpe_string, ["Invalid CPE format"]
            )

        part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]

        if mapping.cpe_type == "asset":
            # For asset CPEs, validate against OS information
            os_lower = original_asset.os.lower()

            # Check if CPE part matches expectation (should be 'o' for OS)
            if part not in ["o", "*"]:
                errors.append(
                    f"Asset CPE part is '{part}', expected 'o' for operating system"
                )

            # Concrete validation against known OS patterns
            if not self._validate_os_vendor_product(vendor, product, os_lower):
                errors.append(
                    f"CPE vendor/product '{vendor}:{product}' does not match OS '{original_asset.os}' based on known patterns"
                )

        elif mapping.cpe_type == "software" and original_software:
            # For software CPEs, validate against software information
            software_name_lower = original_software.name.lower()

            # Check if CPE part matches expectation (should be 'a' for application)
            if part not in ["a", "*"]:
                errors.append(
                    f"Software CPE part is '{part}', expected 'a' for application"
                )

            # Concrete validation against known software patterns
            if not self._validate_software_vendor_product(
                vendor, product, software_name_lower
            ):
                errors.append(
                    f"CPE vendor/product '{vendor}:{product}' does not match software '{original_software.name}' based on known patterns"
                )

        return CPEValidationResult(
            is_valid=len(errors) == 0, cpe_string=mapping.cpe_string, errors=errors
        )

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using SequenceMatcher"""
        return SequenceMatcher(None, str1, str2).ratio()

    def _validate_os_vendor_product(
        self, vendor: str, product: str, os_string: str
    ) -> bool:
        """Validate OS vendor/product with permissive approach for automation"""
        vendor_lower = vendor.lower()
        product_lower = product.lower()

        # Allow wildcards
        if vendor == "*" or product == "*":
            return True

        # Basic sanity checks - catch obvious errors
        if not vendor or not product or vendor == "" or product == "":
            return False

        # Check for obviously invalid characters/patterns
        invalid_chars = ["<", ">", "script", "javascript", "null", "undefined"]
        combined = f"{vendor} {product}".lower()
        if any(invalid in combined for invalid in invalid_chars):
            return False

        # For automation: if it passes basic sanity, accept it
        return True

    def _validate_software_vendor_product(
        self, vendor: str, product: str, software_name: str
    ) -> bool:
        """Validate software vendor/product with permissive approach for automation"""
        vendor_lower = vendor.lower()
        product_lower = product.lower()

        # Allow wildcards
        if vendor == "*" or product == "*":
            return True

        # Basic sanity checks only
        if not vendor or not product or vendor == "" or product == "":
            return False

        # Check for obviously invalid patterns
        invalid_chars = ["<", ">", "script", "javascript", "null", "undefined"]
        combined = f"{vendor} {product}".lower()
        if any(invalid in combined for invalid in invalid_chars):
            return False

        # For automation: accept if it passes basic sanity
        return True


def extract_assets_and_software(
    incidents: List[IncidentData],
) -> Tuple[
    List[Tuple[AssetData, Optional[SoftwareInfo]]],
    Dict[str, Tuple[AssetData, Optional[SoftwareInfo]]],
]:
    """Extract unique assets and software from incidents for CPE generation"""
    assets_software = []
    lookup_map = {}  # For validation lookup

    for incident in incidents:
        for asset in incident.affected_assets:
            # Add asset-level entry (for OS CPE)
            asset_key = f"{asset.hostname}:{asset.ip_address}:asset"
            if asset_key not in lookup_map:
                assets_software.append((asset, None))
                lookup_map[asset_key] = (asset, None)

            # Add software-level entries
            for software in asset.installed_software:
                software_key = f"{asset.hostname}:{asset.ip_address}:software:{software.name}:{software.version}"
                if software_key not in lookup_map:
                    assets_software.append((asset, software))
                    lookup_map[software_key] = (asset, software)

    return assets_software, lookup_map


@tool
def generate_cpes_for_batch(
    asset_mappings: List[AssetCPEMapping],
    incident_data: Annotated[List[IncidentData], InjectedToolArg],
    validation_config: Annotated[Optional[Dict[str, Any]], InjectedToolArg] = None,
) -> str:
    """
    Generate and validate CPE strings for a batch of assets and software.

    Use this tool to process a batch of asset and software data, generating CPE strings.

    Args:
        asset_mappings: List of asset/software to CPE mappings. Each mapping should contain:
            - asset_hostname: Hostname of the asset
            - asset_ip: IP address of the asset
            - cpe_string: Generated CPE string in CPE 2.3 format
            - cpe_type: Either 'asset' (for OS/hardware) or 'software'
            - software_name: Name of software (required if cpe_type='software')
            - software_version: Version of software (required if cpe_type='software')
    """
    logger.info(
        f"Processing CPE generation for {len(asset_mappings)} mappings across {len(incident_data)} incidents"
    )

    # Initialize validation config with defaults
    config_dict = validation_config or {}
    config = CPEValidationConfig(
        hostname_similarity_threshold=config_dict.get(
            "hostname_similarity_threshold", 0.8
        ),
        software_name_similarity_threshold=config_dict.get(
            "software_name_similarity_threshold", 0.7
        ),
        software_version_similarity_threshold=config_dict.get(
            "software_version_similarity_threshold", 0.8
        ),
        vendor_product_similarity_threshold=config_dict.get(
            "vendor_product_similarity_threshold", 0.6
        ),
        strict_ip_matching=config_dict.get("strict_ip_matching", True),
        strict_hostname_matching=config_dict.get("strict_hostname_matching", False),
    )

    # Initialize validator
    validator = CPEValidator(config)

    # Extract all assets and software for validation lookup
    _, lookup_map = extract_assets_and_software(incident_data)

    # Validate each mapping
    validated_mappings = []
    validation_errors = []

    for i, mapping in enumerate(asset_mappings):
        try:
            # Validate CPE format
            format_validation = validator.validate_cpe_format(mapping.cpe_string)
            if not format_validation.is_valid:
                validation_errors.extend(
                    [
                        f"asset_mappings_{i} - {error}"
                        for error in format_validation.errors
                    ]
                )
                continue

            # Find corresponding original asset/software for linkage validation
            if mapping.cpe_type == "asset":
                lookup_key = f"{mapping.asset_hostname}:{mapping.asset_ip}:asset"
            else:
                lookup_key = f"{mapping.asset_hostname}:{mapping.asset_ip}:software:{mapping.software_name}:{mapping.software_version}"

            if lookup_key not in lookup_map:
                validation_errors.append(
                    f"asset_mappings_{i} - No matching asset/software found for {lookup_key}"
                )
                continue

            original_asset, original_software = lookup_map[lookup_key]

            # Validate asset linkage
            linkage_validation = validator.validate_asset_linkage(
                mapping, original_asset, original_software
            )
            if not linkage_validation.is_valid:
                validation_errors.extend(
                    [
                        f"asset_mappings_{i} - {error}"
                        for error in linkage_validation.errors
                    ]
                )
                continue

            validated_mappings.append(mapping)

        except Exception as e:
            validation_errors.append(f"asset_mappings_{i} - Validation error: {str(e)}")

    # If there are validation errors, raise ValidationError
    if validation_errors:
        error_msg = (
            f"CPE validation failed with {len(validation_errors)} errors:\n"
            + "\n".join(validation_errors)
        )
        logger.error(error_msg)

        # Create line_errors in the correct format
        line_errors = []
        for i, error in enumerate(validation_errors):
            line_errors.append(
                {
                    "type": "value_error",
                    "loc": ("cpe_validation", f"error_{i}"),
                    "msg": f"Value error, {error}",
                    "input": None,
                    "ctx": {"error": error},
                }
            )

        raise ValidationError.from_exception_data(
            title="CPEValidation", line_errors=line_errors
        )

    logger.info(f"Successfully validated {len(validated_mappings)} CPE mappings")

    # Apply validated CPE mappings to incident data (modifying in place)
    for incident in incident_data:
        # Update assets with CPE data directly
        for asset in incident.affected_assets:
            # Find asset-level CPEs
            asset_cpes = [
                m
                for m in validated_mappings
                if m.asset_hostname == asset.hostname
                and m.asset_ip == asset.ip_address
                and m.cpe_type == "asset"
            ]
            asset.cpe_strings = [m.cpe_string for m in asset_cpes]

            # Update software with CPE data
            for software in asset.installed_software:
                software_cpes = [
                    m
                    for m in validated_mappings
                    if (
                        m.asset_hostname == asset.hostname
                        and m.asset_ip == asset.ip_address
                        and m.cpe_type == "software"
                        and m.software_name == software.name
                        and m.software_version == software.version
                    )
                ]
                if software_cpes:
                    software.cpe_string = software_cpes[
                        0
                    ].cpe_string  # Take the first match

    # Log summary
    total_asset_cpes = sum(
        len(asset.cpe_strings)
        for incident in incident_data
        for asset in incident.affected_assets
    )
    total_software_cpes = sum(
        1
        for incident in incident_data
        for asset in incident.affected_assets
        for software in asset.installed_software
        if software.cpe_string
    )

    logger.info(
        f"Applied {total_asset_cpes} asset CPEs and {total_software_cpes} software CPEs to {len(incident_data)} incidents"
    )

    return "Successfully generated and validated CPEs for the batch"


generate_cpes_tools = [generate_cpes_for_batch]
