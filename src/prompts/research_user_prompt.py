# Incident Research User Prompt

RESEARCH_USER_PROMPT = """# Security Incident Research: {incident_id}

**Title**: {title}
**Description**: {description}
**Timestamp**: {timestamp}

## Assets & Software
{affected_assets_summary}

## Top CVEs (Research Priority)
{top_cves_list}

## Recent CVEs (90d)
{recent_cves_list}

## CPE Targets
{cpe_list}

## TTPs
{observed_ttps_info}

## IOCs
{indicators_info}

## Vulnerability Stats
{vulnerability_summary}

---

## Research Objectives
1. **CVE Deep Dive**: Research each listed CVE for exploitation status, PoCs, active campaigns
2. **Software Analysis**: Investigate each software component for additional vulnerabilities, configs, patches
3. **TTP Research**: Research attack patterns, related campaigns, threat actors
4. **IOC Intelligence**: Research indicators for attribution, campaigns, related incidents
5. **Context Gathering**: Environmental factors, exposure, criticality, mitigations

## Strategy
- Start with top CVEs and recent vulnerabilities
- Use CPE strings for precise searches
- Cross-reference TTPs with CVE exploitation
- Follow leads from initial findings
- Validate across multiple sources

## Submit Research
Use `submit_research` tool with:
- CVE research findings & relevance
- Software component analysis
- Threat intelligence discoveries  
- Research methodology & sources
- Key insights & gaps
- Analysis recommendations

Your response must ALWAYS be in the form of tool calls. NEVER answer directly in chat."""
