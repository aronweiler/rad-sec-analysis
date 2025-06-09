"""
NVD (National Vulnerability Database) Tool

A tool for interacting with the NIST NVD API 2.0 to analyze vulnerabilities.
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

from src.models.incident_vulnerability_report import (
    CVEInfo,
    IncidentVulnerabilityReport,
    SoftwareVulnerabilityReport,
)

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
            return self.parse_cve_response(data)
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
                    return self.parse_cve_response(data)
                except Exception as fallback_e:
                    self.logger.error(
                        f"Fallback search also failed for keyword '{keyword}': {fallback_e}"
                    )
                    return []
            else:
                self.logger.error(f"Failed to search CVEs for keyword '{keyword}': {e}")
                return []

    def search_cves_by_cpe(
        self,
        cpe_name: str,
        results_per_page: int = 20,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[CVEInfo]:
        """
        Search for CVEs by CPE (Common Platform Enumeration) name with optional date filtering

        Args:
            cpe_name: CPE name (e.g., "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*")
            results_per_page: Number of results per page
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering

        Returns:
            List of CVE information objects
        """
        params = {"cpeName": cpe_name, "resultsPerPage": min(results_per_page, 2000)}

        # Add date filtering if provided (same logic as keyword search)
        if start_date and end_date:
            # Ensure end_date is not in the future
            now = datetime.now(timezone.utc)
            if end_date > now:
                end_date = now - timedelta(minutes=5)

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
            return self.parse_cve_response(data)
        except requests.RequestException as e:
            # If date filtering fails, try without dates as fallback
            if start_date or end_date:
                self.logger.warning(
                    f"Date-filtered CPE search failed for '{cpe_name}', retrying without dates: {e}"
                )
                fallback_params = {
                    "cpeName": cpe_name,
                    "resultsPerPage": min(results_per_page, 2000),
                }
                try:
                    data = self._make_request(fallback_params)
                    return self.parse_cve_response(data)
                except Exception as fallback_e:
                    self.logger.error(
                        f"Fallback CPE search also failed for '{cpe_name}': {fallback_e}"
                    )
                    return []
            else:
                self.logger.error(f"Failed to search CVEs for CPE '{cpe_name}': {e}")
                return []

    def search_cves_by_multiple_cpes(
        self,
        cpe_names: List[str],
        results_per_page: int = 20,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[CVEInfo]:
        """
        Search for CVEs using multiple CPE names (batch search)

        Args:
            cpe_names: List of CPE names to search
            results_per_page: Total number of results per CPE
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering

        Returns:
            Deduplicated list of CVE information objects
        """
        all_cves = []
        seen_cve_ids = set()

        for cpe_name in cpe_names:
            try:
                cves = self.search_cves_by_cpe(
                    cpe_name, results_per_page, start_date, end_date
                )

                for cve in cves:
                    if cve.cve_id not in seen_cve_ids:
                        all_cves.append(cve)
                        seen_cve_ids.add(cve.cve_id)

            except Exception as e:
                self.logger.warning(f"Failed to search CVEs for CPE '{cpe_name}': {e}")
                continue

        return all_cves

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
            cves = self.parse_cve_response(data)
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
            return self.parse_cve_response(data)
        except Exception as e:
            self.logger.error(f"Failed to search CVEs by date range: {e}")
            return []

    def parse_cve_response(self, data: Dict[str, Any]) -> List[CVEInfo]:
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
