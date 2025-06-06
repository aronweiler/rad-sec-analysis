"""
NVD (National Vulnerability Database) Tool

A comprehensive tool for interacting with the NIST NVD API 2.0 to analyze
vulnerabilities in software identified in security incidents.

This tool integrates with the incident data model to automatically analyze
software vulnerabilities and provide detailed CVE information.
"""

import os
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
import requests
from urllib.parse import urlencode
from pydantic import BaseModel, Field, ConfigDict

# Import your incident models
from ..models.incident import IncidentData, AssetData, SoftwareInfo


class CVEInfo(BaseModel):
    """Structured CVE information from NVD"""

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    cve_id: str = Field(..., description="CVE identifier")
    description: str = Field(..., description="CVE description")
    published_date: datetime = Field(..., description="Publication date")
    last_modified: datetime = Field(..., description="Last modification date")
    cvss_v3_score: Optional[float] = Field(None, description="CVSS v3 base score")
    cvss_v3_severity: Optional[str] = Field(None, description="CVSS v3 severity")
    cvss_v2_score: Optional[float] = Field(None, description="CVSS v2 base score")
    cvss_v2_severity: Optional[str] = Field(None, description="CVSS v2 severity")
    cpe_matches: List[str] = Field(default_factory=list, description="CPE matches")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    weaknesses: List[str] = Field(default_factory=list, description="CWE identifiers")
    configurations: List[Dict[str, Any]] = Field(
        default_factory=list, description="Vulnerable configurations"
    )
    vendor_comments: List[str] = Field(
        default_factory=list, description="Vendor comments"
    )


class SoftwareVulnerabilityReport(BaseModel):
    """Vulnerability report for a specific software"""

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    software: SoftwareInfo = Field(..., description="Software information")
    cves: List[CVEInfo] = Field(default_factory=list, description="List of CVEs")
    critical_count: int = Field(0, description="Count of critical vulnerabilities")
    high_count: int = Field(0, description="Count of high severity vulnerabilities")
    medium_count: int = Field(0, description="Count of medium severity vulnerabilities")
    low_count: int = Field(0, description="Count of low severity vulnerabilities")
    total_count: int = Field(0, description="Total count of vulnerabilities")


class IncidentVulnerabilityReport(BaseModel):
    """Complete vulnerability report for an incident"""

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    incident_id: str = Field(..., description="Incident identifier")
    software_reports: List[SoftwareVulnerabilityReport] = Field(
        default_factory=list, description="Software vulnerability reports"
    )
    total_vulnerabilities: int = Field(0, description="Total vulnerabilities count")
    critical_vulnerabilities: int = Field(
        0, description="Critical vulnerabilities count"
    )
    high_vulnerabilities: int = Field(
        0, description="High severity vulnerabilities count"
    )
    medium_vulnerabilities: int = Field(
        0, description="Medium severity vulnerabilities count"
    )
    low_vulnerabilities: int = Field(
        0, description="Low severity vulnerabilities count"
    )
    most_vulnerable_software: Optional[SoftwareInfo] = Field(
        None, description="Most vulnerable software"
    )
    recommendations: List[str] = Field(
        default_factory=list, description="Security recommendations"
    )


class NVDTool:
    """
    NVD API Tool for vulnerability analysis

    Provides methods to query the NIST National Vulnerability Database
    and analyze vulnerabilities in software from security incidents.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the NVD Tool

        Args:
            api_key: NVD API key. If None, will try to get from NVD_API_KEY environment variable
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()

        # Set up headers
        self.headers = {
            "User-Agent": "r-sec-nvd-tool/1.0",
            "Accept": "application/json",
        }

        if self.api_key:
            self.headers["apiKey"] = self.api_key
            self.rate_limit_delay = 0.6  # 100 requests per minute with API key
        else:
            self.rate_limit_delay = 6.0  # 10 requests per minute without API key
            logging.warning(
                "No NVD API key provided. Rate limited to 10 requests per minute."
            )

        self.session.headers.update(self.headers)

        # Set up logging
        self.logger = logging.getLogger(__name__)

    def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a rate-limited request to the NVD API

        Args:
            params: Query parameters for the API request

        Returns:
            JSON response from the API

        Raises:
            requests.RequestException: If the API request fails
        """
        # Apply rate limiting
        time.sleep(self.rate_limit_delay)

        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"NVD API request failed: {e}")
            raise

    def search_cves_by_keyword(
        self, keyword: str, results_per_page: int = 20
    ) -> List[CVEInfo]:
        """
        Search for CVEs by keyword

        Args:
            keyword: Search keyword (software name, vendor, etc.)
            results_per_page: Number of results per page (max 2000)

        Returns:
            List of CVE information objects
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 2000),
        }

        try:
            data = self._make_request(params)
            return self._parse_cve_response(data)
        except Exception as e:
            self.logger.error(f"Failed to search CVEs for keyword '{keyword}': {e}")
            return []

    def search_cves_by_cpe(
        self, cpe_name: str, results_per_page: int = 20
    ) -> List[CVEInfo]:
        """
        Search for CVEs by CPE (Common Platform Enumeration) name

        Args:
            cpe_name: CPE name (e.g., "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*")
            results_per_page: Number of results per page

        Returns:
            List of CVE information objects
        """
        params = {"cpeName": cpe_name, "resultsPerPage": min(results_per_page, 2000)}

        try:
            data = self._make_request(params)
            return self._parse_cve_response(data)
        except Exception as e:
            self.logger.error(f"Failed to search CVEs for CPE '{cpe_name}': {e}")
            return []

    def get_cve_by_id(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Get detailed information for a specific CVE ID

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            CVE information object or None if not found
        """
        params = {"cveId": cve_id}

        try:
            data = self._make_request(params)
            cves = self._parse_cve_response(data)
            return cves[0] if cves else None
        except Exception as e:
            self.logger.error(f"Failed to get CVE '{cve_id}': {e}")
            return None

    def search_cves_by_date_range(
        self, start_date: datetime, end_date: datetime, results_per_page: int = 20
    ) -> List[CVEInfo]:
        """
        Search for CVEs published within a date range

        Args:
            start_date: Start date for the search
            end_date: End date for the search
            results_per_page: Number of results per page

        Returns:
            List of CVE information objects
        """
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(results_per_page, 2000),
        }

        try:
            data = self._make_request(params)
            return self._parse_cve_response(data)
        except Exception as e:
            self.logger.error(f"Failed to search CVEs by date range: {e}")
            return []

    def analyze_software_vulnerabilities(
        self, software: SoftwareInfo, max_results: int = 50
    ) -> SoftwareVulnerabilityReport:
        """
        Analyze vulnerabilities for a specific software with intelligent search strategies

        Args:
            software: Software information object
            max_results: Maximum number of CVEs to retrieve

        Returns:
            Software vulnerability report
        """
        self.logger.info(
            f"Analyzing vulnerabilities for {software.name} {software.version}"
        )

        all_cves = []
        seen_cve_ids = set()

        # Strategy 1: Progressive keyword refinement
        search_strategies = self._generate_search_strategies(software)

        for strategy_name, search_terms in search_strategies.items():
            self.logger.debug(f"Trying search strategy: {strategy_name}")

            for term in search_terms:
                if len(all_cves) >= max_results:
                    break

                self.logger.debug(f"Searching for: '{term}'")
                cves = self.search_cves_by_keyword(
                    term, min(max_results - len(all_cves), 50)
                )

                # Filter and add relevant CVEs
                relevant_count = 0
                for cve in cves:
                    if cve.cve_id not in seen_cve_ids:
                        if self._is_cve_relevant_to_software(cve, software):
                            all_cves.append(cve)
                            seen_cve_ids.add(cve.cve_id)
                            relevant_count += 1

                self.logger.debug(
                    f"Found {len(cves)} CVEs, {relevant_count} relevant for '{term}'"
                )

                # If we found good results with this term, continue with this strategy
                if relevant_count > 0:
                    continue

            # If this strategy found results, we can be less aggressive with other strategies
            if len(all_cves) > 10:
                break

        # Strategy 2: Try CPE-style searches if we have common software
        if len(all_cves) < 10:
            cpe_searches = self._generate_cpe_searches(software)
            for cpe_term in cpe_searches:
                if len(all_cves) >= max_results:
                    break
                cves = self.search_cves_by_keyword(
                    cpe_term, min(max_results - len(all_cves), 25)
                )
                for cve in cves:
                    if (
                        cve.cve_id not in seen_cve_ids
                        and self._is_cve_relevant_to_software(cve, software)
                    ):
                        all_cves.append(cve)
                        seen_cve_ids.add(cve.cve_id)

        # Count vulnerabilities by severity
        critical_count = sum(
            1 for cve in all_cves if cve.cvss_v3_severity == "CRITICAL"
        )
        high_count = sum(1 for cve in all_cves if cve.cvss_v3_severity == "HIGH")
        medium_count = sum(1 for cve in all_cves if cve.cvss_v3_severity == "MEDIUM")
        low_count = sum(1 for cve in all_cves if cve.cvss_v3_severity == "LOW")

        self.logger.info(
            f"Found {len(all_cves)} relevant CVEs for {software.name} {software.version}"
        )

        return SoftwareVulnerabilityReport(
            software=software,
            cves=all_cves,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_count=len(all_cves),
        )

    def _generate_search_strategies(
        self, software: SoftwareInfo
    ) -> Dict[str, List[str]]:
        """
        Generate intelligent search strategies for different types of software

        Args:
            software: Software information object

        Returns:
            Dictionary of strategy names to search term lists
        """
        name = software.name.strip()
        version = software.version.strip()
        name_lower = name.lower()

        strategies = {}

        # Strategy 1: Exact and near-exact matches
        strategies["exact_matches"] = [
            f'"{name}"',  # Quoted exact match
            name,  # Exact name
        ]

        # Strategy 2: Core product name (remove common suffixes/prefixes)
        core_name = self._extract_core_product_name(name)
        if core_name != name:
            strategies["core_product"] = [f'"{core_name}"', core_name]

        # Strategy 3: Vendor + product combinations
        vendor_product = self._extract_vendor_product(name)
        if vendor_product:
            strategies["vendor_product"] = vendor_product

        # Strategy 4: Version-specific searches (only if we haven't found much)
        version_terms = []
        if version and version.lower() not in ["unknown", "n/a", ""]:
            # Try major version only
            major_version = (
                version.split(".")[0] if "." in version else version.split()[0]
            )
            version_terms.extend(
                [f"{core_name} {major_version}", f"{name} {major_version}"]
            )
        strategies["version_specific"] = version_terms

        # Strategy 5: Broad category searches (last resort)
        broad_terms = self._generate_broad_search_terms(name)
        if broad_terms:
            strategies["broad_search"] = broad_terms

        return strategies

    def _extract_core_product_name(self, name: str) -> str:
        """Extract core product name by removing common prefixes/suffixes"""
        name_lower = name.lower()

        # Remove common prefixes
        prefixes_to_remove = [
            "microsoft ",
            "adobe ",
            "oracle ",
            "apache ",
            "cisco ",
            "vmware ",
            "red hat ",
            "redhat ",
            "ibm ",
            "google ",
            "amazon ",
            "aws ",
            "open source ",
        ]

        core_name = name
        for prefix in prefixes_to_remove:
            if name_lower.startswith(prefix):
                core_name = name[len(prefix) :]
                break

        # Remove common suffixes
        suffixes_to_remove = [
            " server",
            " client",
            " enterprise",
            " professional",
            " standard",
            " community",
            " edition",
            " software",
            " application",
            " service",
            " platform",
            " framework",
        ]

        core_lower = core_name.lower()
        for suffix in suffixes_to_remove:
            if core_lower.endswith(suffix):
                core_name = core_name[: -len(suffix)]
                break

        return core_name.strip()

    def _extract_vendor_product(self, name: str) -> List[str]:
        """Extract vendor and product combinations for better searching"""
        name_lower = name.lower()
        vendor_mappings = {
            "cisco": ["cisco", "ios", "nx-os", "asa", "pix"],
            "microsoft": [
                "microsoft",
                "windows",
                "office",
                "exchange",
                "sql server",
                "iis",
            ],
            "apache": ["apache", "tomcat", "httpd", "struts", "kafka"],
            "oracle": ["oracle", "java", "mysql", "weblogic"],
            "adobe": ["adobe", "acrobat", "reader", "flash", "photoshop"],
            "vmware": ["vmware", "vsphere", "vcenter", "esxi"],
            "wordpress": ["wordpress", "wp"],
            "postgresql": ["postgresql", "postgres"],
            "nginx": ["nginx"],
            "openssl": ["openssl", "ssl", "tls"],
        }

        search_terms = []
        for vendor, products in vendor_mappings.items():
            if vendor in name_lower:
                # Add vendor-specific searches
                search_terms.extend([f'"{vendor}"', vendor])
                # Add product-specific searches if they appear in the name
                for product in products:
                    if product in name_lower and product != vendor:
                        search_terms.extend([f'"{product}"', product])
                break

        return search_terms

    def _generate_cpe_searches(self, software: SoftwareInfo) -> List[str]:
        """Generate CPE-style search terms"""
        name_lower = software.name.lower()

        # Common CPE vendor:product mappings
        cpe_mappings = {
            "cisco ios": "cisco:ios",
            "apache tomcat": "apache:tomcat",
            "microsoft windows": "microsoft:windows",
            "postgresql": "postgresql:postgresql",
            "wordpress": "wordpress:wordpress",
            "nginx": "nginx:nginx",
            "openssl": "openssl:openssl",
            "mysql": "oracle:mysql",
        }

        search_terms = []
        for pattern, cpe_style in cpe_mappings.items():
            if pattern in name_lower:
                search_terms.append(cpe_style.replace(":", " "))
                search_terms.append(f'"{cpe_style.replace(":", " ")}"')

        return search_terms

    def _generate_broad_search_terms(self, name: str) -> List[str]:
        """Generate broad search terms as last resort"""
        name_lower = name.lower()
        broad_terms = []

        # Extract significant words (longer than 3 characters)
        words = [word for word in name_lower.split() if len(word) > 3]

        # Use the longest/most specific words
        if words:
            words.sort(key=len, reverse=True)
            broad_terms.extend(words[:2])  # Take top 2 longest words

        return broad_terms

    def analyze_incident_vulnerabilities(
        self, incident: IncidentData, max_cves_per_software: int = 25
    ) -> IncidentVulnerabilityReport:
        """
        Analyze vulnerabilities for all software in an incident

        Args:
            incident: Incident data object
            max_cves_per_software: Maximum CVEs to retrieve per software

        Returns:
            Complete incident vulnerability report
        """
        self.logger.info(
            f"Analyzing vulnerabilities for incident {incident.incident_id}"
        )

        # Get unique software across all assets
        unique_software = incident.get_unique_software()

        software_reports = []
        total_vulnerabilities = 0
        critical_vulnerabilities = 0
        high_vulnerabilities = 0
        medium_vulnerabilities = 0
        low_vulnerabilities = 0

        for software in unique_software:
            report = self.analyze_software_vulnerabilities(
                software, max_cves_per_software
            )
            software_reports.append(report)

            total_vulnerabilities += report.total_count
            critical_vulnerabilities += report.critical_count
            high_vulnerabilities += report.high_count
            medium_vulnerabilities += report.medium_count
            low_vulnerabilities += report.low_count

        # Find most vulnerable software
        most_vulnerable_software = None
        if software_reports:
            most_vulnerable_report = max(software_reports, key=lambda r: r.total_count)
            if most_vulnerable_report.total_count > 0:
                most_vulnerable_software = most_vulnerable_report.software

        # Generate recommendations
        recommendations = self._generate_recommendations(software_reports, incident)

        return IncidentVulnerabilityReport(
            incident_id=incident.incident_id,
            software_reports=software_reports,
            total_vulnerabilities=total_vulnerabilities,
            critical_vulnerabilities=critical_vulnerabilities,
            high_vulnerabilities=high_vulnerabilities,
            medium_vulnerabilities=medium_vulnerabilities,
            low_vulnerabilities=low_vulnerabilities,
            most_vulnerable_software=most_vulnerable_software,
            recommendations=recommendations,
        )

    def get_recent_cves(
        self, days: int = 7, results_per_page: int = 50
    ) -> List[CVEInfo]:
        """
        Get recently published CVEs

        Args:
            days: Number of days back to search
            results_per_page: Number of results per page

        Returns:
            List of recent CVE information objects
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        return self.search_cves_by_date_range(start_date, end_date, results_per_page)

    def _parse_cve_response(self, data: Dict[str, Any]) -> List[CVEInfo]:
        """
        Parse CVE response data from NVD API

        Args:
            data: JSON response from NVD API

        Returns:
            List of parsed CVE information objects
        """
        cves = []

        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})

            # Basic CVE information
            cve_id = cve_data.get("id", "")

            # Description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Dates
            published_date = datetime.fromisoformat(
                cve_data.get("published", "").replace("Z", "+00:00")
            )
            last_modified = datetime.fromisoformat(
                cve_data.get("lastModified", "").replace("Z", "+00:00")
            )

            # CVSS scores
            metrics = cve_data.get("metrics", {})
            cvss_v3_score = None
            cvss_v3_severity = None
            cvss_v2_score = None
            cvss_v2_severity = None

            # CVSS v3
            if "cvssMetricV31" in metrics:
                cvss_v3_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_v3_score = cvss_v3_data.get("baseScore")
                cvss_v3_severity = cvss_v3_data.get("baseSeverity")
            elif "cvssMetricV30" in metrics:
                cvss_v3_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_v3_score = cvss_v3_data.get("baseScore")
                cvss_v3_severity = cvss_v3_data.get("baseSeverity")

            # CVSS v2
            if "cvssMetricV2" in metrics:
                cvss_v2_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_v2_score = cvss_v2_data.get("baseScore")
                cvss_v2_severity = cvss_v2_data.get("baseSeverity")

            # CPE matches
            cpe_matches = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe_matches.append(cpe_match.get("criteria", ""))

            # References
            references = []
            for ref in cve_data.get("references", []):
                references.append(ref.get("url", ""))

            # Weaknesses
            weaknesses = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value", ""))

            # Vendor comments
            vendor_comments = []
            for comment in cve_data.get("vendorComments", []):
                vendor_comments.append(comment.get("comment", ""))

            cve_info = CVEInfo(
                cve_id=cve_id,
                description=description,
                published_date=published_date,
                last_modified=last_modified,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_severity=cvss_v3_severity,
                cvss_v2_score=cvss_v2_score,
                cvss_v2_severity=cvss_v2_severity,
                cpe_matches=cpe_matches,
                references=references,
                weaknesses=weaknesses,
                configurations=configurations,
                vendor_comments=vendor_comments,
            )

            cves.append(cve_info)

        return cves

    def _is_cve_relevant_to_software(
        self, cve: CVEInfo, software: SoftwareInfo
    ) -> bool:
        """
        Determine if a CVE is relevant to specific software

        Args:
            cve: CVE information object
            software: Software information object

        Returns:
            True if the CVE is relevant to the software
        """
        software_name_lower = software.name.lower()
        software_version = software.version.lower()

        # Check description
        description_lower = cve.description.lower()
        if software_name_lower in description_lower:
            return True

        # Check CPE matches
        for cpe in cve.cpe_matches:
            cpe_lower = cpe.lower()
            if software_name_lower in cpe_lower:
                # If version is specified in CPE, check if it matches or is vulnerable
                if software_version in cpe_lower or "*" in cpe_lower:
                    return True

        # Check for common software name variations
        name_parts = software_name_lower.split()
        for part in name_parts:
            if len(part) > 3 and part in description_lower:
                return True

        return False

    def _generate_recommendations(
        self,
        software_reports: List[SoftwareVulnerabilityReport],
        incident: IncidentData,
    ) -> List[str]:
        """
        Generate security recommendations based on vulnerability analysis

        Args:
            software_reports: List of software vulnerability reports
            incident: Incident data object

        Returns:
            List of recommendation strings
        """
        recommendations = []

        # Critical vulnerabilities
        critical_software = [r for r in software_reports if r.critical_count > 0]
        if critical_software:
            recommendations.append(
                f"URGENT: {len(critical_software)} software packages have CRITICAL vulnerabilities. "
                "Immediate patching or mitigation required."
            )

        # High vulnerabilities
        high_software = [r for r in software_reports if r.high_count > 0]
        if high_software:
            recommendations.append(
                f"HIGH PRIORITY: {len(high_software)} software packages have HIGH severity vulnerabilities. "
                "Schedule patching within 72 hours."
            )  # Most vulnerable software
        if software_reports:
            most_vulnerable = max(software_reports, key=lambda r: r.total_count)
            if most_vulnerable.total_count > 5:
                recommendations.append(
                    f"Focus on {most_vulnerable.software.name} {most_vulnerable.software.version} "
                    f"which has {most_vulnerable.total_count} known vulnerabilities."
                )

        # Asset-specific recommendations
        public_assets = incident.get_assets_by_role("public")
        if public_assets and any(
            r.critical_count > 0 or r.high_count > 0 for r in software_reports
        ):
            recommendations.append(
                "Public-facing assets detected with high/critical vulnerabilities. "
                "Consider additional network controls and monitoring."
            )

        # General recommendations
        if any(r.total_count > 0 for r in software_reports):
            recommendations.extend(
                [
                    "Implement automated vulnerability scanning for all assets.",
                    "Establish a patch management process with defined SLAs.",
                    "Consider implementing network segmentation to limit exposure.",
                    "Monitor for exploitation attempts of identified vulnerabilities.",
                ]        )

        return recommendations

    def export_report_to_dict(
        self, report: IncidentVulnerabilityReport
    ) -> Dict[str, Any]:
        """
        Export vulnerability report to dictionary format with proper datetime handling

        Args:
            report: Incident vulnerability report

        Returns:
            Dictionary representation of the report
        """
        # Use Pydantic's built-in serialization which handles datetime objects
        return report.model_dump(mode='json')

    def serialize_report_to_json(self, report: IncidentVulnerabilityReport) -> str:
        """
        Serialize vulnerability report to JSON string

        Args:
            report: Incident vulnerability report

        Returns:
            JSON string representation of the report
        """
        return report.model_dump_json()

    def serialize_report_to_dict(self, report: IncidentVulnerabilityReport) -> Dict[str, Any]:
        """
        Serialize vulnerability report to dictionary

        Args:
            report: Incident vulnerability report

        Returns:
            Dictionary representation of the report
        """
        return report.model_dump(mode='json')
