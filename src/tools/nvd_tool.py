"""
NVD (National Vulnerability Database) Tool

A comprehensive tool for interacting with the NIST NVD API 2.0 to analyze
vulnerabilities in software identified in security incidents.

This tool integrates with the incident data model to automatically analyze
software vulnerabilities and provide detailed CVE information with enhanced
filtering, version matching, and recency prioritization.
"""

import os
import re
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Set
import requests
from urllib.parse import urlencode
from pydantic import BaseModel, Field, ConfigDict

from src.models.incident_vulnerability_report import CVEInfo, IncidentVulnerabilityReport, SoftwareVulnerabilityReport

# Import incident models
from ..models.incident import IncidentData, AssetData, SoftwareInfo


class NVDTool:
    """
    NVD API Tool for vulnerability analysis

    Provides methods to query the NIST National Vulnerability Database
    and analyze vulnerabilities in software from security incidents with
    enhanced filtering, version matching, and recency prioritization.
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
            "User-Agent": "r-sec-nvd-tool/2.0",
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
        self,
        keyword: str,
        results_per_page: int = 20,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[CVEInfo]:
        """
        Search for CVEs by keyword with optional date filtering

        Args:
            keyword: Search keyword (software name, vendor, etc.)
            results_per_page: Number of results per page (max 2000)
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering

        Returns:
            List of CVE information objects
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 2000),
        }

        # Validate and add date filtering if provided
        if start_date and end_date:
            # Ensure end_date is not in the future
            now = datetime.now(timezone.utc)
            if end_date > now:
                end_date = now - timedelta(
                    minutes=5
                )  # 5 minutes in the past to be safe

                # Check if date range exceeds 120 days
                date_diff = (end_date - start_date).days
                if date_diff > 120:
                    self.logger.warning(
                        f"Date range ({date_diff} days) exceeds NVD API limit of 120 days. Truncating to 120 days."
                    )
                    start_date = end_date - timedelta(days=120)

                # Format dates in UTC
                params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        try:
            data = self._make_request(params)
            return self._parse_cve_response(data)
        except requests.RequestException as e:
            # If date filtering fails, try without dates as fallback
            if start_date or end_date:
                self.logger.warning(
                    f"Date-filtered search failed for '{keyword}', retrying without dates: {e}"
                )
                fallback_params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": min(results_per_page, 2000),
                }
                try:
                    data = self._make_request(fallback_params)
                    return self._parse_cve_response(data)
                except Exception as fallback_e:
                    self.logger.error(
                        f"Fallback search also failed for keyword '{keyword}': {fallback_e}"
                    )
                    return []
            else:
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
        self,
        software: SoftwareInfo,
        max_results: int = 50,
        max_age_days: Optional[int] = None,
        prioritize_recent_days: int = 365,
        strict_version_matching: bool = False,
        min_relevance_score: float = 0.3,
        incident_date: Optional[
            datetime
        ] = None,  # NEW: Incident timestamp for contextual filtering
    ) -> SoftwareVulnerabilityReport:
        """
        Analyze vulnerabilities for a specific software with enhanced filtering

        Args:
            software: Software information object
            max_results: Maximum number of CVEs to retrieve
            max_age_days: Filter out CVEs older than this many days
            prioritize_recent_days: Prioritize CVEs from the last X days (will be chunked if > 120)
            strict_version_matching: Enable strict version matching
            min_relevance_score: Minimum relevance score for including CVEs
            incident_date: Date when the incident occurred (for contextual filtering)

        Returns:
            Software vulnerability report
        """
        self.logger.info(
            f"Analyzing vulnerabilities for {software.name} {software.version}"
            f"{' (incident-contextualized)' if incident_date else ''}"
        )

        all_cves = []
        seen_cve_ids = set()

        # Calculate date filters based on incident date if available
        if incident_date:
            # Primary search: CVEs published before the incident (lookback period)
            lookback_years = 3  # Look back 3 years from incident date
            primary_start = incident_date - timedelta(days=lookback_years * 365)
            primary_end = incident_date  # Secondary search: CVEs published shortly after incident (for post-incident discoveries)
            post_incident_days = 90  # 90 days after incident
            secondary_start = incident_date
            secondary_end = min(
                incident_date + timedelta(days=post_incident_days),
                datetime.now(timezone.utc),
            )

            self.logger.debug(
                f"Using incident date {incident_date.strftime('%Y-%m-%d')} for contextual filtering"
            )
        else:
            # Fallback to original logic if no incident date
            now = datetime.now(timezone.utc)
            primary_start = now - timedelta(days=min(prioritize_recent_days, 120))
            primary_end = now - timedelta(minutes=5)
            secondary_start = None
            secondary_end = None

        # Strategy 1: Primary search (pre-incident or recent CVEs)
        self.logger.debug(
            f"Primary search: CVEs from {primary_start.strftime('%Y-%m-%d')} to {primary_end.strftime('%Y-%m-%d')}"
        )

        primary_cves = self._search_software_cves_in_date_range(
            software,
            primary_start,
            primary_end,
            max_results * 2 // 3,
            strict_version_matching,
        )

        for cve in primary_cves:
            if cve.cve_id not in seen_cve_ids:
                relevance_score = self._calculate_relevance_score(
                    cve, software, strict_version_matching, incident_date
                )
                if relevance_score >= min_relevance_score:
                    cve.relevance_score = relevance_score
                    cve.age_days = (
                        datetime.now(timezone.utc) - cve.published_date
                    ).days
                    all_cves.append(cve)
                    seen_cve_ids.add(cve.cve_id)

        # Strategy 2: Secondary search (post-incident discoveries) if incident date is available
        if (
            incident_date
            and secondary_start
            and secondary_end
            and len(all_cves) < max_results
        ):
            remaining_results = max_results - len(all_cves)
            self.logger.debug(
                f"Secondary search: Post-incident CVEs from {secondary_start.strftime('%Y-%m-%d')} to {secondary_end.strftime('%Y-%m-%d')}"
            )

            secondary_cves = self._search_software_cves_in_date_range(
                software,
                secondary_start,
                secondary_end,
                remaining_results,
                strict_version_matching,
            )

            for cve in secondary_cves:
                if cve.cve_id not in seen_cve_ids:
                    relevance_score = self._calculate_relevance_score(
                        cve, software, strict_version_matching, incident_date
                    )
                    if relevance_score >= min_relevance_score:
                        cve.relevance_score = (
                            relevance_score * 0.8
                        )  # Slight penalty for post-incident CVEs
                        cve.age_days = (
                            datetime.now(timezone.utc) - cve.published_date
                        ).days
                        all_cves.append(cve)
                        seen_cve_ids.add(cve.cve_id)

        # Strategy 3: Broader search if we still need more results (without date filtering)
        remaining_results = max_results - len(all_cves)
        if remaining_results > 0:
            self.logger.debug("Broader search: Additional CVEs without date filtering")

            search_strategies = self._generate_enhanced_search_strategies(
                software, strict_version_matching
            )

            for strategy_name, search_config in search_strategies.items():
                if len(all_cves) >= max_results:
                    break

                self.logger.debug(f"Trying search strategy: {strategy_name}")

                for search_term, use_date_filter in search_config:
                    if len(all_cves) >= max_results:
                        break

                    cves = self.search_cves_by_keyword(
                        search_term, min(remaining_results, 30)
                    )

                    relevant_count = 0
                    for cve in cves:
                        if cve.cve_id not in seen_cve_ids:
                            # Apply age filtering in post-processing if specified
                            cve_age_days = (
                                datetime.now(timezone.utc) - cve.published_date
                            ).days
                            if max_age_days and cve_age_days > max_age_days:
                                continue

                            relevance_score = self._calculate_relevance_score(
                                cve, software, strict_version_matching, incident_date
                            )
                            if relevance_score >= min_relevance_score:
                                cve.relevance_score = relevance_score
                                cve.age_days = cve_age_days
                                all_cves.append(cve)
                                seen_cve_ids.add(cve.cve_id)
                                relevant_count += 1

                    self.logger.debug(
                        f"Found {len(cves)} CVEs, {relevant_count} relevant for '{search_term}'"
                    )

                    remaining_results = max_results - len(all_cves)

        # Sort by relevance score and recency
        all_cves.sort(key=lambda x: (x.relevance_score, -x.age_days), reverse=True)

        # Take only the top results
        all_cves = all_cves[:max_results]

        # Separate recent CVEs (relative to incident date if available)
        if incident_date:
            # Recent CVEs are those published within prioritize_recent_days before the incident
            recent_threshold = incident_date - timedelta(days=prioritize_recent_days)
            recent_cves = [
                cve
                for cve in all_cves
                if cve.published_date >= recent_threshold
                and cve.published_date <= incident_date
            ]
        else:
            recent_cves = [
                cve for cve in all_cves if cve.age_days <= prioritize_recent_days
            ]

        # Count vulnerabilities by severity
        critical_count = sum(
            1 for cve in all_cves if cve.cvss_v3_severity == "CRITICAL"
        )
        high_count = sum(1 for cve in all_cves if cve.cvss_v3_severity == "HIGH")
        medium_count = sum(1 for cve in all_cves if cve.cvss_v3_severity == "MEDIUM")
        low_count = sum(1 for cve in all_cves if cve.cvss_v3_severity == "LOW")

        # Count recent critical/high vulnerabilities
        recent_critical_count = sum(
            1 for cve in recent_cves if cve.cvss_v3_severity == "CRITICAL"
        )
        recent_high_count = sum(
            1 for cve in recent_cves if cve.cvss_v3_severity == "HIGH"
        )

        # Calculate average relevance score
        avg_relevance_score = (
            sum(cve.relevance_score for cve in all_cves) / len(all_cves)
            if all_cves
            else 0.0
        )

        self.logger.info(
            f"Found {len(all_cves)} relevant CVEs ({len(recent_cves)} recent) for {software.name} {software.version}"
        )

        return SoftwareVulnerabilityReport(
            software=software,
            cves=all_cves,
            recent_cves=recent_cves,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_count=len(all_cves),
            recent_critical_count=recent_critical_count,
            recent_high_count=recent_high_count,
            avg_relevance_score=avg_relevance_score,
        )

    def _search_software_cves_in_date_range(
        self,
        software: SoftwareInfo,
        start_date: datetime,
        end_date: datetime,
        max_results: int,
        strict_version_matching: bool = False,
    ) -> List[CVEInfo]:
        """Search for CVEs for specific software within a date range with chunking for large ranges"""
        all_cves = []
        seen_cve_ids = set()

        # Use the most specific search terms for recent CVEs
        search_terms = [
            f'"{software.name}"',  # Exact quoted match
            software.name,  # Exact name
        ]

        # Add version-specific terms if available and strict matching is enabled
        if (
            strict_version_matching
            and software.version
            and software.version.lower() not in ["unknown", "n/a", ""]
        ):
            search_terms.insert(0, f'"{software.name}" "{software.version}"')
            search_terms.insert(1, f"{software.name} {software.version}")

        # Calculate date chunks (120 days max per request)
        date_chunks = self._create_date_chunks(start_date, end_date)

        for chunk_start, chunk_end in date_chunks:
            if len(all_cves) >= max_results:
                break

            for term in search_terms:
                if len(all_cves) >= max_results:
                    break

                term_cves = self.search_cves_by_keyword(
                    term,
                    min(max_results - len(all_cves), 25),
                    start_date=chunk_start,
                    end_date=chunk_end,
                )

                for cve in term_cves:
                    if cve.cve_id not in seen_cve_ids:
                        all_cves.append(cve)
                        seen_cve_ids.add(cve.cve_id)

        return all_cves[:max_results]

    def _create_date_chunks(
        self, start_date: datetime, end_date: datetime
    ) -> List[Tuple[datetime, datetime]]:
        """
        Create date chunks of maximum 120 days each for NVD API compliance

        Args:
            start_date: Start date
            end_date: End date

        Returns:
            List of (start, end) date tuples, each spanning max 120 days
        """
        chunks = []
        current_start = start_date
        max_chunk_days = 120

        # Ensure end_date is not in the future
        now = datetime.now(timezone.utc)
        if end_date > now:
            end_date = now - timedelta(minutes=5)

        while current_start < end_date:
            current_end = min(current_start + timedelta(days=max_chunk_days), end_date)
            chunks.append((current_start, current_end))
            current_start = current_end

        return chunks

    def _generate_enhanced_search_strategies(
        self, software: SoftwareInfo, strict_version_matching: bool = False
    ) -> Dict[str, List[Tuple[str, bool]]]:
        """
        Generate enhanced search strategies with date filtering preferences

        Returns:
            Dictionary mapping strategy names to list of (search_term, use_date_filter) tuples
        """
        name = software.name.strip()
        version = software.version.strip()
        name_lower = name.lower()

        strategies = {}

        # Strategy 1: Exact matches (always use date filtering for precision)
        exact_terms = [
            (f'"{name}"', True),  # Quoted exact match
            (name, True),  # Exact name
        ]

        if (
            strict_version_matching
            and version
            and version.lower() not in ["unknown", "n/a", ""]
        ):
            exact_terms.insert(0, (f'"{name}" "{version}"', True))
            exact_terms.insert(1, (f"{name} {version}", True))

        strategies["exact_matches"] = exact_terms

        # Strategy 2: Core product name (with date filtering)
        core_name = self._extract_core_product_name(name)
        if core_name != name:
            strategies["core_product"] = [(f'"{core_name}"', True), (core_name, True)]

        # Strategy 3: Vendor + product combinations (with date filtering)
        vendor_product = self._extract_vendor_product(name)
        if vendor_product:
            strategies["vendor_product"] = [(term, True) for term in vendor_product]

        # Strategy 4: Version-specific searches (only if strict matching is disabled)
        if (
            not strict_version_matching
            and version
            and version.lower() not in ["unknown", "n/a", ""]
        ):
            major_version = (
                version.split(".")[0] if "." in version else version.split()[0]
            )
            strategies["version_specific"] = [
                (f"{core_name} {major_version}", True),
                (f"{name} {major_version}", True),
            ]

        # Strategy 5: Broad searches (no date filtering, last resort)
        broad_terms = self._generate_broad_search_terms(name)
        if broad_terms and not strict_version_matching:
            strategies["broad_search"] = [(term, False) for term in broad_terms]

        return strategies

    def _calculate_relevance_score(
        self,
        cve: CVEInfo,
        software: SoftwareInfo,
        strict_version_matching: bool = False,
        incident_date: Optional[
            datetime
        ] = None,  # NEW: For incident-contextualized scoring
    ) -> float:
        """
        Calculate relevance score for a CVE based on software matching criteria

        Args:
            cve: CVE information object
            software: Software information object
            strict_version_matching: Whether to apply strict version matching
            incident_date: Date of the incident for temporal relevance scoring

        Returns:
            Relevance score between 0.0 and 1.0
        """
        score = 0.0
        software_name_lower = software.name.lower()
        software_version = software.version.lower() if software.version else ""

        # Base score for description matching
        description_lower = cve.description.lower()

        # Exact name match in description (high score)
        if f" {software_name_lower} " in f" {description_lower} ":
            score += 0.4
        elif software_name_lower in description_lower:
            score += 0.2

        # CPE matching (highest score for exact matches)
        cpe_score = 0.0
        for cpe in cve.cpe_matches:
            cpe_lower = cpe.lower()
            cpe_parts = self._parse_cpe(cpe)

            if cpe_parts:
                vendor, product, version, update, edition = cpe_parts

                # Exact product match
                if product and software_name_lower in product:
                    cpe_score = max(cpe_score, 0.5)

                    # Version matching
                    if strict_version_matching and software_version and version:
                        if self._version_matches(software_version, version):
                            cpe_score = max(cpe_score, 0.8)
                        elif version == "*" or version == "-":
                            cpe_score = max(cpe_score, 0.6)
                    elif not strict_version_matching:
                        cpe_score = max(cpe_score, 0.6)

        score += cpe_score

        # Vendor matching
        vendor_score = 0.0
        core_name = self._extract_core_product_name(software.name)
        if core_name.lower() != software_name_lower:
            if core_name.lower() in description_lower:
                vendor_score = 0.1

        score += vendor_score

        # Penalty for very generic matches
        name_parts = software_name_lower.split()
        if len(name_parts) > 1:
            # Check if only partial words match
            partial_matches = sum(
                1 for part in name_parts if len(part) > 3 and part in description_lower
            )
            if partial_matches < len(name_parts) and score < 0.3:
                score *= 0.5  # Reduce score for partial matches

        # Incident-contextualized temporal scoring
        if incident_date:
            # Calculate days between CVE publication and incident
            days_before_incident = (incident_date - cve.published_date).days

            if days_before_incident >= 0:  # CVE published before incident
                if days_before_incident <= 30:
                    score *= 1.3  # High boost for CVEs published within 30 days before incident
                elif days_before_incident <= 90:
                    score *= 1.2  # Medium boost for CVEs published within 90 days before incident
                elif days_before_incident <= 365:
                    score *= 1.1  # Small boost for CVEs published within 1 year before incident
                # CVEs older than 1 year before incident get no temporal boost
            else:  # CVE published after incident (post-incident discovery)
                days_after_incident = abs(days_before_incident)
                if days_after_incident <= 30:
                    score *= (
                        1.1  # Small boost for CVEs discovered shortly after incident
                    )
                elif days_after_incident <= 90:
                    score *= 1.05  # Very small boost for CVEs discovered within 90 days after
                # CVEs discovered long after incident get no boost
        else:
            # Original recency scoring when no incident date is available
            age_days = (datetime.now(timezone.utc) - cve.published_date).days
            if age_days <= 30:
                score *= 1.2
            elif age_days <= 90:
                score *= 1.1
            elif age_days <= 365:
                score *= 1.05

        # Boost score for higher severity
        if cve.cvss_v3_severity in ["CRITICAL", "HIGH"]:
            score *= 1.1

        return min(score, 1.0)  # Cap at 1.0

    def _parse_cpe(self, cpe: str) -> Optional[Tuple[str, str, str, str, str]]:
        """
        Parse CPE string to extract components

        Returns:
            Tuple of (vendor, product, version, update, edition) or None if invalid
        """
        try:
            # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            if cpe.startswith("cpe:2.3:"):
                parts = cpe.split(":")
                if len(parts) >= 7:
                    return (
                        parts[3],  # vendor
                        parts[4],  # product
                        parts[5],  # version
                        parts[6] if len(parts) > 6 else "",  # update
                        parts[7] if len(parts) > 7 else "",  # edition
                    )
            # CPE 2.2 format: cpe:/part:vendor:product:version:update:edition:language
            elif cpe.startswith("cpe:/"):
                parts = cpe.split(":")
                if len(parts) >= 5:
                    return (
                        parts[2],  # vendor
                        parts[3],  # product
                        parts[4],  # version
                        parts[5] if len(parts) > 5 else "",  # update
                        parts[6] if len(parts) > 6 else "",  # edition
                    )
        except Exception:
            pass
        return None

    def _version_matches(self, software_version: str, cpe_version: str) -> bool:
        """
        Check if software version matches CPE version specification

        Args:
            software_version: Version from software info
            cpe_version: Version from CPE string

        Returns:
            True if versions match
        """
        if not software_version or not cpe_version:
            return False

        # Wildcard matches
        if cpe_version in ["*", "-"]:
            return True

        # Exact match
        if software_version == cpe_version:
            return True

        # Semantic version matching
        try:
            # Extract numeric parts for comparison
            sw_parts = re.findall(r"\d+", software_version)
            cpe_parts = re.findall(r"\d+", cpe_version)

            if sw_parts and cpe_parts:
                # Compare major version at minimum
                if sw_parts[0] == cpe_parts[0]:
                    # If CPE version is shorter, it might be a range
                    if len(cpe_parts) <= len(sw_parts):
                        return all(
                            sw_parts[i] == cpe_parts[i] for i in range(len(cpe_parts))
                        )

        except Exception:
            pass

        return False

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

    def _generate_broad_search_terms(self, name: str) -> List[str]:
        """Generate broad search terms as last resort (more restrictive than before)"""
        name_lower = name.lower()
        broad_terms = []

        # Extract significant words (longer than 4 characters to be more restrictive)
        words = [word for word in name_lower.split() if len(word) > 4]

        # Use only the longest/most specific word to avoid too many irrelevant results
        if words:
            words.sort(key=len, reverse=True)
            broad_terms.append(words[0])  # Take only the longest word

        return broad_terms

    def analyze_incident_vulnerabilities(
        self,
        incident: IncidentData,
        max_cves_per_software: int = 25,
        max_age_days: Optional[int] = None,
        prioritize_recent_days: int = 365,
        strict_version_matching: bool = False,
        min_relevance_score: float = 0.3,
    ) -> IncidentVulnerabilityReport:
        """
        Analyze vulnerabilities for all software in an incident with enhanced filtering

        Args:
            incident: Incident data object
            max_cves_per_software: Maximum CVEs to retrieve per software
            max_age_days: Filter out CVEs older than this many days
            prioritize_recent_days: Prioritize CVEs from the last X days
            strict_version_matching: Enable strict version matching for more precise results
            min_relevance_score: Minimum relevance score for including CVEs (0.0-1.0)

        Returns:
            Complete incident vulnerability report
        """
        # Extract incident timestamp for contextual filtering
        incident_date = (
            incident.timestamp
            if hasattr(incident, "timestamp") and incident.timestamp
            else None
        )

        self.logger.info(
            f"Analyzing vulnerabilities for incident {incident.incident_id} "
            f"(incident_date: {incident_date.strftime('%Y-%m-%d %H:%M:%S') if incident_date else 'N/A'}, "
            f"max_age: {max_age_days}, recent_priority: {prioritize_recent_days}, "
            f"strict_version: {strict_version_matching}, min_relevance: {min_relevance_score})"
        )

        # Store analysis configuration
        analysis_config = {
            "max_cves_per_software": max_cves_per_software,
            "max_age_days": max_age_days,
            "prioritize_recent_days": prioritize_recent_days,
            "strict_version_matching": strict_version_matching,
            "min_relevance_score": min_relevance_score,
            "incident_date": incident_date.isoformat() if incident_date else None,
            "analysis_timestamp": datetime.now().isoformat(),
        }

        # Get unique software across all assets
        unique_software = incident.get_unique_software()

        software_reports = []
        total_vulnerabilities = 0
        recent_vulnerabilities = 0
        critical_vulnerabilities = 0
        high_vulnerabilities = 0
        medium_vulnerabilities = 0
        low_vulnerabilities = 0

        for software in unique_software:
            report = self.analyze_software_vulnerabilities(
                software,
                max_cves_per_software,
                max_age_days,
                prioritize_recent_days,
                strict_version_matching,
                min_relevance_score,
                incident_date,  # Pass incident date for contextual analysis
            )
            software_reports.append(report)

            total_vulnerabilities += report.total_count
            recent_vulnerabilities += len(report.recent_cves)
            critical_vulnerabilities += report.critical_count
            high_vulnerabilities += report.high_count
            medium_vulnerabilities += report.medium_count
            low_vulnerabilities += report.low_count

        # Find most vulnerable software (by total count)
        most_vulnerable_software = None
        if software_reports:
            most_vulnerable_report = max(software_reports, key=lambda r: r.total_count)
            if most_vulnerable_report.total_count > 0:
                most_vulnerable_software = most_vulnerable_report.software

        # Find software with most recent vulnerabilities
        most_recent_vulnerable_software = None
        if software_reports:
            most_recent_report = max(software_reports, key=lambda r: len(r.recent_cves))
            if len(most_recent_report.recent_cves) > 0:
                most_recent_vulnerable_software = most_recent_report.software

        # Generate enhanced recommendations
        recommendations = self._generate_enhanced_recommendations(
            software_reports, incident, analysis_config
        )

        return IncidentVulnerabilityReport(
            incident_id=incident.incident_id,
            software_reports=software_reports,
            total_vulnerabilities=total_vulnerabilities,
            recent_vulnerabilities=recent_vulnerabilities,
            critical_vulnerabilities=critical_vulnerabilities,
            high_vulnerabilities=high_vulnerabilities,
            medium_vulnerabilities=medium_vulnerabilities,
            low_vulnerabilities=low_vulnerabilities,
            most_vulnerable_software=most_vulnerable_software,
            most_recent_vulnerable_software=most_recent_vulnerable_software,
            recommendations=recommendations,
            analysis_config=analysis_config,
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
        end_date = datetime.now(timezone.utc)
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
                    break  # Dates
            published_date = datetime.fromisoformat(
                cve_data.get("published", "").replace("Z", "+00:00")
            )
            last_modified = datetime.fromisoformat(
                cve_data.get("lastModified", "").replace("Z", "+00:00")
            )

            # Ensure dates are timezone-aware (fallback to UTC if naive)
            if published_date.tzinfo is None:
                published_date = published_date.replace(tzinfo=timezone.utc)
            if last_modified.tzinfo is None:
                last_modified = last_modified.replace(tzinfo=timezone.utc)

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
                vendor_comments.append(comment.get("comment", ""))  # Calculate age
            age_days = (datetime.now(timezone.utc) - published_date).days

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
                relevance_score=0.0,  # Will be calculated later
                age_days=age_days,
            )

            cves.append(cve_info)

        return cves

    def _generate_enhanced_recommendations(
        self,
        software_reports: List[SoftwareVulnerabilityReport],
        incident: IncidentData,
        analysis_config: Dict[str, Any],
    ) -> List[str]:
        """
        Generate enhanced security recommendations based on vulnerability analysis

        Args:
            software_reports: List of software vulnerability reports
            incident: Incident data object
            analysis_config: Configuration used for the analysis

        Returns:
            List of recommendation strings
        """
        recommendations = []
        incident_date = analysis_config.get("incident_date")

        # Incident-contextualized recommendations
        if incident_date:
            incident_dt = datetime.fromisoformat(incident_date)

            # Check for CVEs published shortly before the incident
            pre_incident_cves = []
            for report in software_reports:
                for cve in report.cves:
                    days_before = (incident_dt - cve.published_date).days
                    if (
                        0 <= days_before <= 90
                    ):  # CVEs published 0-90 days before incident
                        pre_incident_cves.append((cve, report.software, days_before))

            if pre_incident_cves:
                pre_incident_cves.sort(
                    key=lambda x: x[2]
                )  # Sort by days before incident
                closest_cve, closest_software, days_before = pre_incident_cves[0]

                recommendations.append(
                    f"🎯 INCIDENT CONTEXT: CVE {closest_cve.cve_id} affecting {closest_software.name} "
                    f"was published {days_before} days before the incident. This may be related to the attack vector."
                )

                if len(pre_incident_cves) > 1:
                    recommendations.append(
                        f"⚠️ {len(pre_incident_cves)} CVEs were published within 90 days before the incident. "
                        "Review patch management timeline for potential missed vulnerabilities."
                    )

        # Recent critical vulnerabilities (highest priority)
        recent_critical_software = [
            r for r in software_reports if r.recent_critical_count > 0
        ]
        if recent_critical_software:
            total_recent_critical = sum(
                r.recent_critical_count for r in recent_critical_software
            )
            timeframe = (
                "before the incident"
                if incident_date
                else f"in the last {analysis_config.get('prioritize_recent_days', 365)} days"
            )
            recommendations.append(
                f"🚨 URGENT: {len(recent_critical_software)} software packages have {total_recent_critical} "
                f"CRITICAL vulnerabilities published {timeframe}. "
                "Immediate patching or mitigation required."
            )

        # Recent high vulnerabilities
        recent_high_software = [r for r in software_reports if r.recent_high_count > 0]
        if recent_high_software:
            total_recent_high = sum(r.recent_high_count for r in recent_high_software)
            timeframe = "before the incident" if incident_date else "recently"
            recommendations.append(
                f"⚠️ HIGH PRIORITY: {len(recent_high_software)} software packages have {total_recent_high} "
                f"HIGH severity vulnerabilities published {timeframe}. Schedule patching within 72 hours."
            )

        # Overall critical vulnerabilities
        critical_software = [r for r in software_reports if r.critical_count > 0]
        if critical_software and not recent_critical_software:
            recommendations.append(
                f"CRITICAL: {len(critical_software)} software packages have CRITICAL vulnerabilities. "
                "Immediate patching or mitigation required."
            )

        # High vulnerabilities
        high_software = [r for r in software_reports if r.high_count > 0]
        if high_software and not recent_high_software:
            recommendations.append(
                f"HIGH PRIORITY: {len(high_software)} software packages have HIGH severity vulnerabilities. "
                "Schedule patching within 72 hours."
            )

        # Most vulnerable software
        if software_reports:
            most_vulnerable = max(software_reports, key=lambda r: r.total_count)
            if most_vulnerable.total_count > 5:
                recommendations.append(
                    f"🎯 Focus on {most_vulnerable.software.name} {most_vulnerable.software.version} "
                    f"which has {most_vulnerable.total_count} known vulnerabilities "
                    f"(avg relevance: {most_vulnerable.avg_relevance_score:.2f})."
                )

        # Most recent vulnerable software
        if software_reports:
            most_recent = max(software_reports, key=lambda r: len(r.recent_cves))
            if len(most_recent.recent_cves) > 0 and most_recent.software != (
                most_vulnerable.software if "most_vulnerable" in locals() else None
            ):
                timeframe = "before the incident" if incident_date else "recently"
                recommendations.append(
                    f"📅 Monitor {most_recent.software.name} {most_recent.software.version} "
                    f"which has {len(most_recent.recent_cves)} vulnerabilities published {timeframe}."
                )

        # Asset-specific recommendations
        public_assets = incident.get_assets_by_role("public")
        if public_assets and any(
            r.critical_count > 0 or r.high_count > 0 for r in software_reports
        ):
            recommendations.append(
                "🌐 Public-facing assets detected with high/critical vulnerabilities. "
                "Consider additional network controls and monitoring."
            )

        # Incident-specific recommendations
        if incident_date:
            recommendations.append(
                "🔍 This analysis is contextualized to the incident timeline. "
                "CVEs published before the incident are prioritized as potential attack vectors."
            )

        # Analysis quality recommendations
        low_relevance_reports = [
            r
            for r in software_reports
            if r.avg_relevance_score < 0.5 and r.total_count > 0
        ]
        if low_relevance_reports:
            recommendations.append(
                f"ℹ️ {len(low_relevance_reports)} software packages have low-confidence vulnerability matches. "
                "Consider enabling strict version matching for more precise results."
            )

        # Configuration-based recommendations
        if not analysis_config.get("strict_version_matching", False):
            recommendations.append(
                "🔧 Consider enabling strict version matching to reduce false positives in vulnerability detection."
            )

        # General recommendations
        if any(r.total_count > 0 for r in software_reports):
            recommendations.extend(
                [
                    "🔄 Implement automated vulnerability scanning for all assets.",
                    "📋 Establish a patch management process with defined SLAs based on severity.",
                    "🔒 Consider implementing network segmentation to limit exposure.",
                    "👁️ Monitor for exploitation attempts of identified vulnerabilities.",
                    "📈 Set up continuous monitoring for new CVEs affecting your software inventory.",
                ]
            )

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
        return report.model_dump(mode="json")

    def serialize_report_to_json(self, report: IncidentVulnerabilityReport) -> str:
        """
        Serialize vulnerability report to JSON string

        Args:
            report: Incident vulnerability report

        Returns:
            JSON string representation of the report
        """
        return report.model_dump_json()

    def serialize_report_to_dict(
        self, report: IncidentVulnerabilityReport
    ) -> Dict[str, Any]:
        """
        Serialize vulnerability report to dictionary

        Args:
            report: Incident vulnerability report

        Returns:
            Dictionary representation of the report
        """
        return report.model_dump(mode="json")
