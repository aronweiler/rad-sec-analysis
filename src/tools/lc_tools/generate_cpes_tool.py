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
from pydantic import BaseModel, Field, ValidationError

from src.models.incident import IncidentData, AssetData, SoftwareInfo

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


@dataclass
class AssetCPEMapping:
    """Mapping between asset/software and generated CPE"""

    asset_hostname: str
    asset_ip: str
    cpe_string: str
    cpe_type: str  # 'asset' or 'software'
    software_name: Optional[str] = None
    software_version: Optional[str] = None


class CPEValidator:
    """Comprehensive CPE validation logic"""

    # CPE 2.3 format regex - strict validation
    CPE_23_PATTERN = re.compile(
        r"^cpe:2\.3:[aho\*\-]:"  # CPE version and part
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # vendor
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # product
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # version
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # update
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # edition
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # language
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # sw_edition
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # target_sw
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*):"  # target_hw
        r"([a-zA-Z0-9\.\-\_\~\%\*]*|\*)$"  # other
    )

    # Known OS patterns for concrete validation
    OS_VENDOR_PATTERNS = {
        "windows": {
            "vendors": ["microsoft"],
            "products": [
                "windows",
                "windows_server",
                "windows_10",
                "windows_11",
                "windows_server_2019",
                "windows_server_2022",
            ],
        },
        "linux": {
            "vendors": ["canonical", "redhat", "centos", "debian", "suse", "oracle"],
            "products": [
                "ubuntu",
                "ubuntu_linux",
                "rhel",
                "red_hat_enterprise_linux",
                "centos",
                "debian_linux",
                "suse_linux",
            ],
        },
        "macos": {"vendors": ["apple"], "products": ["macos", "mac_os_x", "mac_os"]},
        "cisco": {"vendors": ["cisco"], "products": ["ios", "ios_xe", "nx-os", "asa"]},
    }

    # Known software vendor patterns for concrete validation
    SOFTWARE_VENDOR_PATTERNS = {
        "apache": ["tomcat", "httpd", "struts", "kafka", "spark", "maven"],
        "microsoft": ["iis", "sql_server", "exchange", "sharepoint", "office"],
        "oracle": ["mysql", "java", "weblogic", "database"],
        "nginx": ["nginx"],
        "postgresql": ["postgresql"],
        "mongodb": ["mongodb"],
        "redis": ["redis"],
        "elasticsearch": ["elasticsearch"],
        "docker": ["docker"],
        "kubernetes": ["kubernetes"],
    }

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
            errors.append("CPE does not match CPE 2.3 format specification")

        # Component count validation
        parts = cpe_string.split(":")
        if len(parts) != 13:
            errors.append(f"CPE must have exactly 13 components, found {len(parts)}")
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
        """Concrete validation of OS vendor/product against known patterns"""
        vendor_lower = vendor.lower()
        product_lower = product.lower()

        # Allow wildcards
        if vendor == "*" or product == "*":
            return True

        # Check against known OS patterns
        for os_type, patterns in self.OS_VENDOR_PATTERNS.items():
            if any(
                pattern in os_string for pattern in [os_type] + patterns["products"]
            ):
                # Found matching OS type, validate vendor/product
                if vendor_lower in patterns["vendors"] or any(
                    prod in product_lower for prod in patterns["products"]
                ):
                    return True

        # If no concrete pattern match found, use similarity threshold
        for os_type, patterns in self.OS_VENDOR_PATTERNS.items():
            if any(pattern in os_string for pattern in [os_type]):
                # Check similarity with known vendors/products
                for known_vendor in patterns["vendors"]:
                    if (
                        self._calculate_similarity(vendor_lower, known_vendor)
                        >= self.config.vendor_product_similarity_threshold
                    ):
                        return True
                for known_product in patterns["products"]:
                    if (
                        self._calculate_similarity(product_lower, known_product)
                        >= self.config.vendor_product_similarity_threshold
                    ):
                        return True

        return False

    def _validate_software_vendor_product(
        self, vendor: str, product: str, software_name: str
    ) -> bool:
        """Concrete validation of software vendor/product against known patterns"""
        vendor_lower = vendor.lower()
        product_lower = product.lower()

        # Allow wildcards
        if vendor == "*" or product == "*":
            return True

        # Check against known software vendor patterns
        for known_vendor, products in self.SOFTWARE_VENDOR_PATTERNS.items():
            if any(prod in software_name for prod in products):
                # Found matching software, validate vendor/product
                if (
                    vendor_lower == known_vendor
                    or any(prod in product_lower for prod in products)
                    or self._calculate_similarity(vendor_lower, known_vendor)
                    >= self.config.vendor_product_similarity_threshold
                ):
                    return True

        # Fallback: check if any significant part of software name appears in vendor or product
        software_words = [
            word for word in re.findall(r"\w+", software_name.lower()) if len(word) > 2
        ]
        vendor_words = re.findall(r"\w+", vendor_lower)
        product_words = re.findall(r"\w+", product_lower)

        # Check for word overlap with similarity threshold
        for sw_word in software_words:
            for v_word in vendor_words + product_words:
                if (
                    self._calculate_similarity(sw_word, v_word)
                    >= self.config.vendor_product_similarity_threshold
                ):
                    return True

        return False


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
    asset_mappings: List[Dict[str, Any]],
    incident_data: Annotated[List[IncidentData], InjectedToolArg],
    validation_config: Annotated[Optional[Dict[str, Any]], InjectedToolArg] = None,
) -> List[IncidentData]:
    """
    Generate and validate CPE strings for a batch of assets and software.

    This tool processes asset and software information to generate CPE (Common Platform Enumeration)
    strings following the CPE 2.3 specification. It includes comprehensive validation to ensure
    data integrity and prevent hallucinations.

    Args:
        asset_mappings: List of asset/software to CPE mappings. Each mapping should contain:
            - asset_hostname: Hostname of the asset
            - asset_ip: IP address of the asset
            - cpe_string: Generated CPE string in CPE 2.3 format
            - cpe_type: Either 'asset' (for OS/hardware) or 'software'
            - software_name: Name of software (required if cpe_type='software')
            - software_version: Version of software (required if cpe_type='software')
        incident_data: List of incident data objects (injected automatically)
        validation_config: Validation configuration with thresholds (injected automatically)

    Returns:
        List of updated IncidentData objects with populated CPE fields

    Raises:
        ValidationError: If CPE validation fails

    Example asset_mappings format:
    [
        {
            "asset_hostname": "web-server-01",
            "asset_ip": "10.1.1.100",
            "cpe_string": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
            "cpe_type": "asset"
        },
        {
            "asset_hostname": "web-server-01",
            "asset_ip": "10.1.1.100",
            "cpe_string": "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*",
            "cpe_type": "software",
            "software_name": "Apache Tomcat",
            "software_version": "9.0.50"
        }
    ]
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

    for i, mapping_dict in enumerate(asset_mappings):
        try:
            # Convert dict to AssetCPEMapping
            mapping = AssetCPEMapping(
                asset_hostname=mapping_dict.get("asset_hostname", ""),
                asset_ip=mapping_dict.get("asset_ip", ""),
                software_name=mapping_dict.get("software_name"),
                software_version=mapping_dict.get("software_version"),
                cpe_string=mapping_dict.get("cpe_string", ""),
                cpe_type=mapping_dict.get("cpe_type", "asset"),
            )

            # Validate CPE format
            format_validation = validator.validate_cpe_format(mapping.cpe_string)
            if not format_validation.is_valid:
                validation_errors.extend(
                    [f"Mapping {i+1}: {error}" for error in format_validation.errors]
                )
                continue

            # Find corresponding original asset/software for linkage validation
            if mapping.cpe_type == "asset":
                lookup_key = f"{mapping.asset_hostname}:{mapping.asset_ip}:asset"
            else:
                lookup_key = f"{mapping.asset_hostname}:{mapping.asset_ip}:software:{mapping.software_name}:{mapping.software_version}"

            if lookup_key not in lookup_map:
                validation_errors.append(
                    f"Mapping {i+1}: No matching asset/software found for {lookup_key}"
                )
                continue

            original_asset, original_software = lookup_map[lookup_key]

            # Validate asset linkage
            linkage_validation = validator.validate_asset_linkage(
                mapping, original_asset, original_software
            )
            if not linkage_validation.is_valid:
                validation_errors.extend(
                    [f"Mapping {i+1}: {error}" for error in linkage_validation.errors]
                )
                continue

            validated_mappings.append(mapping)

        except Exception as e:
            validation_errors.append(f"Mapping {i+1}: Validation error: {str(e)}")

    # If there are validation errors, raise ValidationError
    if validation_errors:
        error_msg = (
            f"CPE validation failed with {len(validation_errors)} errors:\n"
            + "\n".join(validation_errors)
        )
        logger.error(error_msg)
        raise ValidationError(error_msg)

    logger.info(f"Successfully validated {len(validated_mappings)} CPE mappings")

    # Apply validated CPE mappings to incident data
    updated_incidents = []
    for incident in incident_data:
        # Create a copy of the incident to avoid modifying the original
        updated_incident = incident.model_copy(deep=True)

        # Update assets with CPE data
        for asset in updated_incident.affected_assets:
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

        updated_incidents.append(updated_incident)

    # Log summary
    total_asset_cpes = sum(
        len(asset.cpe_strings)
        for incident in updated_incidents
        for asset in incident.affected_assets
    )
    total_software_cpes = sum(
        1
        for incident in updated_incidents
        for asset in incident.affected_assets
        for software in asset.installed_software
        if software.cpe_string
    )

    logger.info(
        f"Applied {total_asset_cpes} asset CPEs and {total_software_cpes} software CPEs to {len(updated_incidents)} incidents"
    )

    return updated_incidents


generate_cpes_tools = [generate_cpes_for_batch]
