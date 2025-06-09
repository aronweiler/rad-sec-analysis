from langchain.tools import tool
from typing import Optional, Dict, Any
import json
from ..nvd_tool import NVDTool
from ...models.incident import SoftwareInfo

# Initialize the NVD tool instance (shared across all tool functions once its initialized)
_nvd_tool = None


def get_nvd_tool(api_key: Optional[str] = None) -> NVDTool:
    """Get or create NVD tool instance"""
    global _nvd_tool
    if _nvd_tool is None:
        _nvd_tool = NVDTool(api_key=api_key)
    return _nvd_tool


@tool
def search_cves_by_keyword(keyword: str, results_per_page: int = 20) -> str:
    """
    Search for CVEs (Common Vulnerabilities and Exposures) by keyword.

    Args:
        keyword: Search keyword (software name, vendor, etc.)
        results_per_page: Number of results to return (max 2000)

    Returns:
        JSON string containing CVE search results with vulnerability details (limited to 5 CPE matches and references per CVE).
    """
    try:
        nvd_tool = get_nvd_tool()
        cves = nvd_tool.search_cves_by_keyword(keyword, results_per_page)

        if not cves:
            return json.dumps({"message": f"No CVEs found for keyword: {keyword}"})

        # Format results for LLM consumption
        results = []
        for cve in cves:
            result = {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_v3_score": cve.cvss_v3_score,
                "cvss_v3_severity": cve.cvss_v3_severity,
                "published_date": cve.published_date.strftime("%Y-%m-%d"),
                "references": cve.references[:5],  # Limit references
                "total_references": len(cve.references),
                "cpe_matches": cve.cpe_matches[:5],  # Limit CPE matches
                "total_cpe_matches": len(cve.cpe_matches),
            }
            results.append(result)

        return json.dumps(
            {"keyword": keyword, "total_found": len(cves), "cves": results}, indent=2
        )

    except Exception as e:
        return json.dumps({"error": f"Error searching CVEs: {str(e)}"})


@tool
def get_cve_details(cve_id: str) -> str:
    """
    Get detailed information for a specific CVE ID.

    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)

    Returns:
        JSON string containing detailed CVE information (limited to 5 CPE matches and references)
    """
    try:
        nvd_tool = get_nvd_tool()
        cve = nvd_tool.get_cve_by_id(cve_id)

        if not cve:
            return json.dumps({"error": f"CVE not found: {cve_id}"})

        result = {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "cvss_v3_score": cve.cvss_v3_score,
            "cvss_v3_severity": cve.cvss_v3_severity,
            "cvss_v2_score": cve.cvss_v2_score,
            "cvss_v2_severity": cve.cvss_v2_severity,
            "published_date": cve.published_date.strftime("%Y-%m-%d"),
            "last_modified": cve.last_modified.strftime("%Y-%m-%d"),
            "cpe_matches": cve.cpe_matches[:5],  # Limit CPE matches
            "total_cpe_matches": len(cve.cpe_matches),
            "references": cve.references[:5],  # Limit references
            "total_references": len(cve.references),
            "weaknesses": cve.weaknesses,
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Error getting CVE details: {str(e)}"})


@tool
def get_recent_cves(days: int = 7, results_per_page: int = 50) -> str:
    """
    Get recently published CVEs from the past few days.

    Args:
        days: Number of days back to search (default: 7)
        results_per_page: Number of results to return (default: 50)

    Returns:
        JSON string containing recent CVEs with severity information
    """
    try:
        nvd_tool = get_nvd_tool()
        cves = nvd_tool.get_recent_cves(days, results_per_page)

        if not cves:
            return json.dumps({"message": f"No CVEs found in the past {days} days"})

        # Format results
        results = []
        for cve in cves:
            result = {
                "cve_id": cve.cve_id,
                "severity": cve.cvss_v3_severity,
                "score": cve.cvss_v3_score,
                "description": cve.description,
                "published": cve.published_date.strftime("%Y-%m-%d"),
            }
            results.append(result)

        return json.dumps(
            {
                "days_searched": days,
                "total_found": len(cves),
                "recent_cves": sorted(
                    results,
                    key=lambda x: x.get("score", 0) if x.get("score", 0) else 0,
                    reverse=True,
                ),
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"error": f"Error getting recent CVEs: {str(e)}"})


@tool
def search_cves_by_cpe(cpe_name: str, results_per_page: int = 20) -> str:
    """
    Search for CVEs by CPE (Common Platform Enumeration) name.

    Args:
        cpe_name: CPE name (e.g., "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*")
        results_per_page: Number of results to return (max 2000)

    Returns:
        JSON string containing CVE search results for the specified CPE
    """
    try:
        nvd_tool = get_nvd_tool()
        cves = nvd_tool.search_cves_by_cpe(cpe_name, results_per_page)

        if not cves:
            return json.dumps({"message": f"No CVEs found for CPE: {cpe_name}"})

        # Format results for LLM consumption
        results = []
        for cve in cves:
            result = {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_v3_score": cve.cvss_v3_score,
                "cvss_v3_severity": cve.cvss_v3_severity,
                "published_date": cve.published_date.strftime("%Y-%m-%d"),
                "references": cve.references[:5],  # Limit references
                "total_references": len(cve.references),
                "cpe_matches": cve.cpe_matches[:5],  # Limit CPE matches
                "total_cpe_matches": len(cve.cpe_matches),
            }
            results.append(result)

        return json.dumps(
            {"cpe_name": cpe_name, "total_found": len(cves), "cves": results}, indent=2
        )

    except Exception as e:
        return json.dumps({"error": f"Error searching CVEs by CPE: {str(e)}"})


@tool
def search_cves_by_multiple_cpes(cpe_names: str, results_per_page: int = 20) -> str:
    """
    Search for CVEs using multiple CPE names (batch search).

    Args:
        cpe_names: Comma-separated list of CPE names
        results_per_page: Number of results per CPE (max 2000)

    Returns:
        JSON string containing deduplicated CVE search results
    """
    try:
        nvd_tool = get_nvd_tool()
        cpe_list = [cpe.strip() for cpe in cpe_names.split(",")]
        cves = nvd_tool.search_cves_by_multiple_cpes(cpe_list, results_per_page)

        if not cves:
            return json.dumps({"message": f"No CVEs found for CPEs: {cpe_names}"})

        # Format results for LLM consumption
        results = []
        for cve in cves:
            result = {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_v3_score": cve.cvss_v3_score,
                "cvss_v3_severity": cve.cvss_v3_severity,
                "published_date": cve.published_date.strftime("%Y-%m-%d"),
                "references": cve.references[:5],  # Limit references for batch
                "total_references": len(cve.references),
                "cpe_matches": cve.cpe_matches[:5],  # Limit CPE matches for batch
                "total_cpe_matches": len(cve.cpe_matches),
            }
            results.append(result)

        return json.dumps(
            {
                "cpe_names": cpe_list,
                "total_cpes_searched": len(cpe_list),
                "total_found": len(cves),
                "cves": results,
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"error": f"Error searching CVEs by multiple CPEs: {str(e)}"})


nvd_tools = [
    search_cves_by_keyword,
    search_cves_by_cpe,
    search_cves_by_multiple_cpes,
    get_cve_details,
    get_recent_cves,
]
