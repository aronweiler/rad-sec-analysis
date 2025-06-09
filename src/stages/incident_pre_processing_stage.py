import os
import re
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Set
import requests
from urllib.parse import urlencode
from pydantic import BaseModel, Field, ConfigDict

from src.models.application_config import ApplicationConfig
from src.models.incident_vulnerability_report import (
    CVEInfo,
    IncidentVulnerabilityReport,
    SoftwareVulnerabilityReport,
)
from src.models.stage_config import Stage
from src.stages.base import StageBase
from src.tools.mcp_client_manager import MCPClientManager
from src.tools.nvd_tool import NVDTool

from ..models.incident import IncidentData, SoftwareInfo


class IncidentPreProcessingStage(StageBase):
    """Workflow for incident pre-processing and initial analysis with CPE-enhanced CVE filtering."""

    def __init__(self, config: ApplicationConfig, mcp_client_manager: MCPClientManager):
        super().__init__(
            config=config,
            mcp_client_manager=mcp_client_manager,
            stage_type=Stage.INCIDENT_PRE_PROCESSING,
        )

        self.max_cves_per_software: int = int(
            self.stage_config.settings.get("max_cves_per_software", 50)
        )
        self.max_age_days: Optional[int] = int(
            self.stage_config.settings.get("max_age_days", 365)
        )
        self.prioritize_recent_days: int = int(
            self.stage_config.settings.get("prioritize_recent_days", 365)
        )
        self.strict_version_matching: bool = bool(
            self.stage_config.settings.get("strict_version_matching", False)
        )
        self.min_relevance_score: float = float(
            self.stage_config.settings.get("min_relevance_score", 0.3)
        )

        # CPE-specific settings
        self.cpe_search_priority: bool = bool(
            self.stage_config.settings.get("cpe_search_priority", True)
        )
        self.cpe_relevance_boost: float = float(
            self.stage_config.settings.get("cpe_relevance_boost", 0.3)
        )
        self.max_cpes_per_search: int = int(
            self.stage_config.settings.get("max_cpes_per_search", 10)
        )

        self.min_version_confidence: float = float(
            self.stage_config.settings.get("min_version_confidence", 0.7)
        )

        self.nvd_tool = NVDTool()

    async def run(
        self,
        incident: IncidentData,
    ) -> tuple[IncidentVulnerabilityReport, IncidentData]:
        """
        Analyze vulnerabilities for all software in an incident with CPE-enhanced filtering

        Args:
            incident: Incident data object

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
            f"max_age: {self.max_age_days}, recent_priority: {self.prioritize_recent_days}, "
            f"strict_version: {self.strict_version_matching}, min_relevance: {self.min_relevance_score}, "
            f"cpe_priority: {self.cpe_search_priority})"
        )

        # Extract all CPE data from incident for enhanced filtering
        all_cpes = incident.get_all_cpes()
        self.logger.info(
            f"Found {all_cpes['total_count']} CPE strings: "
            f"{len(all_cpes['asset_cpes'])} asset CPEs, {len(all_cpes['software_cpes'])} software CPEs"
        )

        # Store analysis configuration
        analysis_config = {
            "max_cves_per_software": self.max_cves_per_software,
            "max_age_days": self.max_age_days,
            "prioritize_recent_days": self.prioritize_recent_days,
            "strict_version_matching": self.strict_version_matching,
            "min_relevance_score": self.min_relevance_score,
            "cpe_search_priority": self.cpe_search_priority,
            "cpe_relevance_boost": self.cpe_relevance_boost,
            "incident_date": incident_date.isoformat() if incident_date else None,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_cpes_available": all_cpes["total_count"],
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
                all_cpes,
                self.max_cves_per_software,
                self.max_age_days,
                self.prioritize_recent_days,
                self.strict_version_matching,
                self.min_relevance_score,
                incident_date,
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

        return (
            IncidentVulnerabilityReport(
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
                analysis_config=analysis_config,
            ),
            incident,
        )

    def analyze_software_vulnerabilities(
        self,
        software: SoftwareInfo,
        all_cpes: Dict[str, List[str]],
        max_results: int = 50,
        max_age_days: Optional[int] = None,
        prioritize_recent_days: int = 365,
        strict_version_matching: bool = False,
        min_relevance_score: float = 0.3,
        incident_date: Optional[datetime] = None,
    ) -> SoftwareVulnerabilityReport:
        """
        Analyze vulnerabilities for a specific software with CPE-enhanced filtering

        Args:
            software: Software information object
            all_cpes: All CPE strings from the incident
            max_results: Maximum number of CVEs to retrieve
            max_age_days: Filter out CVEs older than this many days
            prioritize_recent_days: Prioritize CVEs from the last X days
            strict_version_matching: Enable strict version matching
            min_relevance_score: Minimum relevance score for including CVEs
            incident_date: Date when the incident occurred

        Returns:
            Software vulnerability report
        """
        self.logger.info(
            f"Analyzing vulnerabilities for {software.name} {software.version}"
            f"{' (CPE-enhanced)' if self.cpe_search_priority else ''}"
            f"{' (incident-contextualized)' if incident_date else ''}"
        )

        all_cves = []
        seen_cve_ids = set()

        # Calculate date filters based on incident date if available
        if incident_date:
            # Primary search: CVEs published before the incident (lookback period)
            lookback_years = int(self.stage_config.settings.get("lookback_years", 3))
            primary_start = incident_date - timedelta(days=lookback_years * 365)
            primary_end = incident_date

            # Secondary search: CVEs published shortly after incident
            post_incident_days = int(
                self.stage_config.settings.get("post_incident_days", 30)
            )
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

        # Strategy 1: CPE-based search (if enabled and CPEs available)
        cpe_only_mode = bool(self.stage_config.settings.get("cpe_only_mode", False))
        relevant_cpes = self._get_relevant_cpes_for_software(software, all_cpes)

        if self.cpe_search_priority and relevant_cpes:
            self.logger.info(
                f"CPE-based search: Found {len(relevant_cpes)} relevant CPE strings for {software.name}"
            )

            cpe_cves = self._search_cves_by_cpe_with_fallback(
                relevant_cpes,
                primary_start,
                primary_end,
                max_results,
                software,
                strict_version_matching,
                incident_date,
            )

            for cve in cpe_cves:
                if cve.cve_id not in seen_cve_ids:
                    # The relevance score is already set by _search_cves_by_cpe_with_fallback
                    if cve.relevance_score >= min_relevance_score:
                        all_cves.append(cve)
                        seen_cve_ids.add(cve.cve_id)
                        cve.age_days = (
                            datetime.now(timezone.utc) - cve.published_date
                        ).days
                        all_cves.append(cve)
                        seen_cve_ids.add(cve.cve_id)

            self.logger.info(f"CPE search found {len(all_cves)} relevant CVEs")

            # NEW: If CPE-only mode is enabled and we found sufficient results, skip keyword searches
            if cpe_only_mode and len(all_cves) >= min(max_results * 0.5, 10):
                self.logger.info(
                    f"CPE-only mode: Found {len(all_cves)} CVEs via CPE search, skipping keyword searches"
                )
                # Skip to final processing
                all_cves.sort(
                    key=lambda x: (x.relevance_score, -x.age_days), reverse=True
                )
                all_cves = all_cves[:max_results]

                # Calculate recent CVEs and return early
                if incident_date:
                    recent_threshold = incident_date - timedelta(
                        days=prioritize_recent_days
                    )
                    recent_cves = [
                        cve
                        for cve in all_cves
                        if cve.published_date >= recent_threshold
                        and cve.published_date <= incident_date
                    ]
                else:
                    recent_cves = [
                        cve
                        for cve in all_cves
                        if cve.age_days <= prioritize_recent_days
                    ]

                return self._build_software_vulnerability_report(
                    software, all_cves, recent_cves
                )

        # Continue with existing keyword search strategies only if not in CPE-only mode or insufficient CPE results
        if not cpe_only_mode or len(all_cves) < min(max_results * 0.5, 10):

            # Strategy 2: Primary keyword search (pre-incident or recent CVEs)
            remaining_results = max_results - len(all_cves)
            if remaining_results > 0:
                self.logger.info(
                    f"Keyword search: CVEs from {primary_start.strftime('%Y-%m-%d')} to {primary_end.strftime('%Y-%m-%d')}"
                )

                primary_cves = self._search_software_cves_in_date_range(
                    software,
                    primary_start,
                    primary_end,
                    remaining_results,
                    strict_version_matching,
                )

                for cve in primary_cves:
                    if cve.cve_id not in seen_cve_ids:
                        relevance_score = self._calculate_relevance_score(
                            cve,
                            software,
                            strict_version_matching,
                            incident_date,
                            cpe_matched=False,
                        )
                        if relevance_score >= min_relevance_score:
                            cve.relevance_score = relevance_score
                            cve.age_days = (
                                datetime.now(timezone.utc) - cve.published_date
                            ).days
                            all_cves.append(cve)
                            seen_cve_ids.add(cve.cve_id)

            # Strategy 3: Secondary search (post-incident discoveries) if incident date is available
            remaining_results = max_results - len(all_cves)
            if (
                incident_date
                and secondary_start
                and secondary_end
                and remaining_results > 0
            ):
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
                            cve,
                            software,
                            strict_version_matching,
                            incident_date,
                            cpe_matched=False,
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

            # Strategy 4: Broader search if we still need more results (without date filtering)
            remaining_results = max_results - len(all_cves)
            if remaining_results > 0:
                self.logger.debug(
                    "Broader search: Additional CVEs without date filtering"
                )

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

                        cves = self.nvd_tool.search_cves_by_keyword(
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
                                    cve,
                                    software,
                                    strict_version_matching,
                                    incident_date,
                                    cpe_matched=False,
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

    def _build_software_vulnerability_report(
        self,
        software: SoftwareInfo,
        all_cves: List[CVEInfo],
        recent_cves: List[CVEInfo],
    ) -> SoftwareVulnerabilityReport:
        """Helper method to build software vulnerability report"""

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

    def _get_relevant_cpes_for_software(
        self, software: SoftwareInfo, all_cpes: Dict[str, List[str]]
    ) -> List[str]:
        """
        Extract CPE strings relevant to the specific software

        Args:
            software: Software information object
            all_cpes: All CPE strings from the incident

        Returns:
            List of relevant CPE strings for this software
        """
        relevant_cpes = []
        software_name_lower = software.name.lower()
        software_version = software.version.lower() if software.version else ""

        # First priority: Use the software's own CPE string if available
        if software.cpe_string:
            relevant_cpes.append(software.cpe_string)

        # Second priority: Find matching CPE strings from software_cpes
        for cpe in all_cpes.get("software_cpes", []):
            if cpe and cpe not in relevant_cpes:
                cpe_parts = self._parse_cpe(cpe)
                if cpe_parts:
                    vendor, product, version, update, edition = cpe_parts

                    # Check if this CPE matches our software
                    if product and self._software_matches_cpe_product(
                        software_name_lower, product
                    ):
                        # If strict version matching is enabled, also check version
                        if (
                            self.strict_version_matching
                            and software_version
                            and version
                        ):
                            if self._version_matches(software_version, version):
                                relevant_cpes.append(cpe)
                        else:
                            relevant_cpes.append(cpe)

        # Limit the number of CPEs to avoid too many API calls
        return relevant_cpes[: self.max_cpes_per_search]

    def _software_matches_cpe_product(
        self, software_name: str, cpe_product: str
    ) -> bool:
        """
        Enhanced CPE product matching with better normalization and fuzzy matching

        Args:
            software_name: Software name (lowercase)
            cpe_product: CPE product field

        Returns:
            True if they match
        """
        if not software_name or not cpe_product:
            return False

        # Normalize both strings
        norm_software = self._normalize_product_name(software_name)
        norm_cpe = self._normalize_product_name(cpe_product)

        # Direct exact match
        if norm_software == norm_cpe:
            return True

        # Substring matching (both directions)
        if norm_software in norm_cpe or norm_cpe in norm_software:
            return True

        # Extract and compare core product names
        core_software = self._extract_core_product_name(software_name)
        core_cpe = self._extract_core_product_name(cpe_product)

        norm_core_software = self._normalize_product_name(core_software)
        norm_core_cpe = self._normalize_product_name(core_cpe)

        if norm_core_software == norm_core_cpe:
            return True

        if norm_core_software in norm_core_cpe or norm_core_cpe in norm_core_software:
            return True

        # Check for common product name variations
        software_variants = self._get_product_name_variants(norm_software)
        cpe_variants = self._get_product_name_variants(norm_cpe)

        for sw_variant in software_variants:
            for cpe_variant in cpe_variants:
                if sw_variant == cpe_variant:
                    return True

        return False

    def _normalize_product_name(self, name: str) -> str:
        """Normalize product name for better matching"""
        if not name:
            return ""

        # Convert to lowercase and remove special characters
        normalized = name.lower()

        # Replace common separators with spaces
        normalized = re.sub(r"[_\-\+\.]", " ", normalized)

        # Remove extra whitespace
        normalized = re.sub(r"\s+", " ", normalized).strip()

        # Remove common suffixes that don't affect matching
        suffixes_to_remove = [
            "server",
            "client",
            "enterprise",
            "professional",
            "standard",
            "community",
            "edition",
            "software",
            "application",
            "service",
            "platform",
            "framework",
            "runtime",
            "sdk",
            "api",
            "library",
        ]

        words = normalized.split()
        filtered_words = [word for word in words if word not in suffixes_to_remove]

        return " ".join(filtered_words) if filtered_words else normalized

    def _get_product_name_variants(self, name: str) -> List[str]:
        """Generate common variants of a product name"""
        variants = [name]

        # Common abbreviations and expansions
        abbreviations = {
            "microsoft": ["ms", "msft"],
            "apache": ["apache_software_foundation", "asf"],
            "postgresql": ["postgres", "pgsql"],
            "mysql": ["my_sql"],
            "javascript": ["js"],
            "typescript": ["ts"],
            "python": ["py"],
            "java": ["jdk", "jre"],
            "dotnet": ["net", "dot_net", ".net"],
            "nodejs": ["node", "node_js"],
            "tomcat": ["apache_tomcat"],
            "httpd": ["apache_httpd", "apache_http_server"],
        }

        for full_name, abbrevs in abbreviations.items():
            if full_name in name:
                for abbrev in abbrevs:
                    variants.append(name.replace(full_name, abbrev))
            for abbrev in abbrevs:
                if abbrev in name:
                    variants.append(name.replace(abbrev, full_name))

        return list(set(variants))

    def _search_cves_by_cpe_with_fallback(
        self,
        cpe_strings: List[str],
        start_date: datetime,
        end_date: datetime,
        max_results: int,
        software: SoftwareInfo,
        strict_version_matching: bool = False,
        incident_date: Optional[datetime] = None,
    ) -> List[CVEInfo]:
        """
        Search for CVEs using CPE strings with precise version matching
        """
        all_cves = []
        seen_cve_ids = set()

        for cpe_string in cpe_strings:
            if len(all_cves) >= max_results:
                break

            self.logger.debug(f"Searching CVEs for CPE: {cpe_string}")

            try:
                # Get CVEs for this CPE
                chunk_cves = self.nvd_tool.search_cves_by_cpe(
                    cpe_string, min(max_results - len(all_cves), 50)
                )

                # Filter and score CVEs based on actual version vulnerability
                for cve in chunk_cves:                    
                    if cve.cve_id not in seen_cve_ids:
                        affects_version, confidence = self._cve_affects_my_version(
                            cve, cpe_string
                        )

                        # Filter by version confidence and set relevance score
                        if affects_version and confidence >= self.min_version_confidence:
                            # Set the relevance score based on version confidence
                            cve.relevance_score = (
                                self._calculate_relevance_score_for_cpe_match(
                                    cve, cpe_string, confidence, incident_date
                                )
                            )
                            cve.age_days = (
                                datetime.now(timezone.utc) - cve.published_date
                            ).days
                            all_cves.append(cve)
                            seen_cve_ids.add(cve.cve_id)

            except Exception as e:
                self.logger.warning(f"CPE search failed for {cpe_string}: {e}")
                continue

        return all_cves[:max_results]

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

                term_cves = self.nvd_tool.search_cves_by_keyword(
                    term,
                    max_results - len(all_cves),
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

    def _cve_affects_my_version(self, cve: CVEInfo, my_cpe: str) -> tuple[bool, float]:
        """
        Determine if a CVE affects my specific version and confidence level

        Args:
            cve: CVEInfo object from your model
            my_cpe: The CPE string for my software

        Returns:
            (affects_version, confidence_score)
        """
        my_cpe_parts = self._parse_cpe(my_cpe)
        if not my_cpe_parts:
            return False, 0.0

        my_vendor, my_product, my_version, my_update, my_edition = my_cpe_parts

        max_confidence = 0.0
        affects_version = False

        # Check each vulnerable configuration in the CVE
        # Note: cve.configurations is a List[Dict[str, Any]] from your CVEInfo model
        for config in cve.configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue

                    cpe_criteria = cpe_match.get("criteria", "")
                    cpe_parts = self._parse_cpe(cpe_criteria)

                    if not cpe_parts:
                        continue

                    vendor, product, version, update, edition = cpe_parts

                    # Must match vendor and product
                    if vendor != my_vendor or product != my_product:
                        continue

                    # Check version matching with confidence scoring
                    version_affects, confidence = self._check_version_vulnerability(
                        my_version, version, cpe_match
                    )

                    if version_affects:
                        affects_version = True
                        max_confidence = max(max_confidence, confidence)

        return affects_version, max_confidence

    def _check_version_vulnerability(
        self, my_version: str, cpe_version: str, cpe_match: dict
    ) -> tuple[bool, float]:
        """
        Check if my version is vulnerable based on CPE version and range constraints

        Args:
            my_version: My software version (e.g., "1.1.1f")
            cpe_version: Version from CPE criteria (e.g., "*" or "1.1.1")
            cpe_match: The cpeMatch dictionary from CVE configurations

        Returns:
            (is_vulnerable, confidence_score)
        """
        if not my_version or my_version in ["*", "-"]:
            return False, 0.0

        # Get version range constraints from CVE
        version_start_inc = cpe_match.get("versionStartIncluding")
        version_end_exc = cpe_match.get("versionEndExcluding")
        version_start_exc = cpe_match.get("versionStartExcluding")
        version_end_inc = cpe_match.get("versionEndIncluding")

        my_version_parts = self._parse_version_parts(my_version)
        if not my_version_parts:
            return False, 0.0

        # Case 1: Exact version match in CPE
        if cpe_version and cpe_version not in ["*", "-"]:
            cpe_version_parts = self._parse_version_parts(cpe_version)
            if cpe_version_parts and my_version_parts == cpe_version_parts:
                return True, 1.0  # Highest confidence - exact match

        # Case 2: Version range specified
        if any(
            [version_start_inc, version_end_exc, version_start_exc, version_end_inc]
        ):
            in_range = True
            confidence = 0.9  # High confidence for range matches

            # Check start boundary (inclusive)
            if version_start_inc:
                start_parts = self._parse_version_parts(version_start_inc)
                if start_parts and my_version_parts < start_parts:
                    in_range = False

            # Check start boundary (exclusive)
            if version_start_exc:
                start_parts = self._parse_version_parts(version_start_exc)
                if start_parts and my_version_parts <= start_parts:
                    in_range = False

            # Check end boundary (exclusive)
            if version_end_exc:
                end_parts = self._parse_version_parts(version_end_exc)
                if end_parts and my_version_parts >= end_parts:
                    in_range = False

            # Check end boundary (inclusive)
            if version_end_inc:
                end_parts = self._parse_version_parts(version_end_inc)
                if end_parts and my_version_parts > end_parts:
                    in_range = False

            return in_range, confidence if in_range else 0.0

        # Case 3: Wildcard version in CPE (affects all versions)
        if cpe_version in ["*", "-"]:
            return True, 0.7  # Medium confidence - broad match

        # Case 4: Version family match (e.g., "1.1.1" matches "1.1.1f")
        if cpe_version:
            cpe_parts = self._parse_version_parts(cpe_version)
            if cpe_parts and len(cpe_parts) <= len(my_version_parts):
                # Check if CPE version is a prefix of my version
                if my_version_parts[: len(cpe_parts)] == cpe_parts:
                    return True, 0.8  # Good confidence - version family match

        return False, 0.0

    def _calculate_relevance_score_for_cpe_match(
        self,
        cve: CVEInfo,
        my_cpe: str,
        version_confidence: float,
        incident_date: Optional[datetime] = None,
    ) -> float:
        """
        Calculate relevance score specifically for CPE-matched CVEs

        Args:
            cve: CVEInfo object
            my_cpe: My CPE string
            version_confidence: Confidence score from version matching
            incident_date: Optional incident date for temporal scoring

        Returns:
            Relevance score between 0.0 and 1.0
        """
        # Base score from version confidence
        score = version_confidence

        # Boost for severity (using CVEInfo.cvss_v3_severity field)
        if cve.cvss_v3_severity == "CRITICAL":
            score *= 1.3
        elif cve.cvss_v3_severity == "HIGH":
            score *= 1.2
        elif cve.cvss_v3_severity == "MEDIUM":
            score *= 1.1

        # Temporal relevance
        if incident_date:
            # Use CVEInfo.published_date field
            days_before_incident = (incident_date - cve.published_date).days
            if 0 <= days_before_incident <= 30:
                score *= 1.2
            elif 0 <= days_before_incident <= 365:
                score *= 1.1
        else:
            # Use CVEInfo.age_days field if available, or calculate
            age_days = getattr(
                cve, "age_days", (datetime.now(timezone.utc) - cve.published_date).days
            )
            if age_days <= 90:
                score *= 1.1

        return min(score, 1.0)

    def _calculate_relevance_score(
        self,
        cve: CVEInfo,
        software: SoftwareInfo,
        strict_version_matching: bool = False,
        incident_date: Optional[datetime] = None,
        cpe_matched: bool = False,
    ) -> float:
        """
        Enhanced relevance scoring with stronger CPE weighting
        """
        score = 0.0
        software_name_lower = software.name.lower()
        software_version = software.version.lower() if software.version else ""

        # CPE matching bonus (significantly increased)
        if cpe_matched:
            score += self.cpe_relevance_boost
            self.logger.debug(
                f"CPE match bonus: +{self.cpe_relevance_boost} for {cve.cve_id}"
            )

        # Base score for description matching (reduced weight when CPE matched)
        description_lower = cve.description.lower()
        description_weight = (
            0.2 if cpe_matched else 0.4
        )  # Reduce description weight for CPE matches

        # Exact name match in description
        if f" {software_name_lower} " in f" {description_lower} ":
            score += description_weight
        elif software_name_lower in description_lower:
            score += description_weight * 0.5

        # Enhanced CPE matching in CVE data
        cpe_score = 0.0
        exact_cpe_matches = 0
        version_cpe_matches = 0

        for cpe in cve.cpe_matches:
            cpe_lower = cpe.lower()
            cpe_parts = self._parse_cpe(cpe)

            if cpe_parts:
                vendor, product, version, update, edition = cpe_parts

                # Enhanced product matching
                if product and self._software_matches_cpe_product(
                    software_name_lower, product
                ):
                    exact_cpe_matches += 1
                    base_cpe_score = 0.6 if cpe_matched else 0.4

                    # Enhanced version matching
                    if strict_version_matching and software_version and version:
                        if self._version_matches(software_version, version):
                            version_cpe_matches += 1
                            cpe_score = max(
                                cpe_score, base_cpe_score + 0.3
                            )  # High score for exact version match
                        elif version in ["*", "-"]:
                            cpe_score = max(
                                cpe_score, base_cpe_score + 0.1
                            )  # Medium score for wildcard
                        else:
                            cpe_score = max(
                                cpe_score, base_cpe_score * 0.7
                            )  # Reduced score for version mismatch
                    elif not strict_version_matching:
                        cpe_score = max(cpe_score, base_cpe_score + 0.2)

        # Bonus for multiple CPE matches (indicates high confidence)
        if exact_cpe_matches > 1:
            cpe_score += min(exact_cpe_matches * 0.1, 0.3)

        if version_cpe_matches > 0:
            cpe_score += min(version_cpe_matches * 0.15, 0.3)

        score += cpe_score

        # Vendor matching (reduced weight for CPE matches)
        vendor_weight = 0.05 if cpe_matched else 0.1
        core_name = self._extract_core_product_name(software.name)
        if core_name.lower() != software_name_lower:
            if core_name.lower() in description_lower:
                score += vendor_weight

        # Enhanced penalty for generic matches (stronger for non-CPE matches)
        if not cpe_matched:
            name_parts = software_name_lower.split()
            if len(name_parts) > 1:
                partial_matches = sum(
                    1
                    for part in name_parts
                    if len(part) > 3 and part in description_lower
                )
                if partial_matches < len(name_parts) and score < 0.4:
                    score *= 0.3  # Strong penalty for weak keyword matches

        # Temporal scoring (same as before)
        if incident_date:
            days_before_incident = (incident_date - cve.published_date).days
            if days_before_incident >= 0:
                if days_before_incident <= 30:
                    score *= 1.3
                elif days_before_incident <= 90:
                    score *= 1.2
                elif days_before_incident <= 365:
                    score *= 1.1
            else:
                days_after_incident = abs(days_before_incident)
                if days_after_incident <= 30:
                    score *= 1.1
                elif days_after_incident <= 90:
                    score *= 1.05
        else:
            age_days = (datetime.now(timezone.utc) - cve.published_date).days
            if age_days <= 30:
                score *= 1.2
            elif age_days <= 90:
                score *= 1.1
            elif age_days <= 365:
                score *= 1.05

        # Severity boost (same as before)
        if cve.cvss_v3_severity in ["CRITICAL", "HIGH"]:
            score *= 1.1

        return min(score, 1.0)

    def _version_matches(self, software_version: str, cpe_version: str) -> bool:
        """
        Enhanced version matching with better semantic version support

        Args:
            software_version: Version from software info
            cpe_version: Version from CPE string

        Returns:
            True if versions match
        """
        if not software_version or not cpe_version:
            return False

        # Normalize versions
        sw_version = software_version.lower().strip()
        cpe_ver = cpe_version.lower().strip()

        # Wildcard matches
        if cpe_ver in ["*", "-", "any"]:
            return True

        # Exact match
        if sw_version == cpe_ver:
            return True

        # Handle version ranges in CPE (e.g., "9.0.0:9.0.50")
        if ":" in cpe_ver:
            try:
                start_ver, end_ver = cpe_ver.split(":", 1)
                return self._version_in_range(sw_version, start_ver, end_ver)
            except:
                pass

        # Semantic version matching
        try:
            sw_parts = self._parse_version_parts(sw_version)
            cpe_parts = self._parse_version_parts(cpe_ver)

            if sw_parts and cpe_parts:
                # Compare version components
                return self._compare_version_parts(sw_parts, cpe_parts)

        except Exception as e:
            self.logger.debug(
                f"Version parsing failed for {sw_version} vs {cpe_ver}: {e}"
            )

        # Fallback: substring matching for partial versions
        if len(cpe_ver) >= 3:  # Avoid matching single digits
            return cpe_ver in sw_version or sw_version in cpe_ver

        return False

    def _parse_version_parts(self, version: str) -> Optional[List[int]]:
        """
        Parse version string into numeric components for comparison

        Args:
            version: Version string like "1.1.1f", "9.0.50", etc.

        Returns:
            List of integers representing version parts, or None if parsing fails
        """
        try:
            if not version or version in ["*", "-", "any"]:
                return None

            # Clean version string - remove common suffixes and prefixes
            version_clean = version.lower().strip()

            # Handle versions with letters (like "1.1.1f")
            # Split on dots first, then handle each part
            parts = []
            for part in version_clean.split("."):
                # Extract numeric part and any letter suffix
                match = re.match(r"^(\d+)([a-z]*).*", part)
                if match:
                    numeric_part = int(match.group(1))
                    letter_part = match.group(2)

                    parts.append(numeric_part)

                    # Convert letter suffix to number (a=1, b=2, etc.)
                    if letter_part:
                        letter_value = sum(ord(c) - ord("a") + 1 for c in letter_part)
                        parts.append(letter_value)
                else:
                    # Try to extract just numbers
                    numeric_match = re.search(r"\d+", part)
                    if numeric_match:
                        parts.append(int(numeric_match.group()))

            return parts if parts else None

        except Exception as e:
            self.logger.debug(f"Version parsing failed for '{version}': {e}")
            return None

    def _compare_version_parts(self, sw_parts: List[int], cpe_parts: List[int]) -> bool:
        """Compare version parts with flexible matching"""
        # Exact match
        if sw_parts == cpe_parts:
            return True

        # If CPE version is shorter, check if it's a prefix match
        # e.g., software "9.0.50" matches CPE "9.0"
        min_len = min(len(sw_parts), len(cpe_parts))
        if sw_parts[:min_len] == cpe_parts[:min_len]:
            # If CPE is shorter, it's likely a range/prefix match
            if len(cpe_parts) <= len(sw_parts):
                return True

        return False

    def _version_in_range(
        self, version: str, start_version: str, end_version: str
    ) -> bool:
        """Check if version falls within a range"""
        try:
            ver_parts = self._parse_version_parts(version)
            start_parts = self._parse_version_parts(start_version)
            end_parts = self._parse_version_parts(end_version)

            if not all([ver_parts, start_parts, end_parts]):
                return False

            # Normalize to same length for comparison
            max_len = max(len(ver_parts), len(start_parts), len(end_parts))
            ver_parts.extend([0] * (max_len - len(ver_parts)))
            start_parts.extend([0] * (max_len - len(start_parts)))
            end_parts.extend([0] * (max_len - len(end_parts)))

            return start_parts <= ver_parts <= end_parts
        except:
            return False

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
