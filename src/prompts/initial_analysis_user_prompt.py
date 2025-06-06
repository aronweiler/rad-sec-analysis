# Initial Incident and CVE Analysis User Prompt

INITIAL_ANALYSIS_USER_PROMPT = """# Security Incident Analysis Request

## Incident Information:
**Incident ID**: {incident_id}
**Timestamp**: {timestamp}
**Title**: {title}
**Description**: {description}
**Initial Findings**: {initial_findings}

## Affected Assets:
{affected_assets_info}

## Observed TTPs:
{observed_ttps_info}

## Indicators of Compromise:
{indicators_info}

## Pre-processed Vulnerability Report:
{vulnerability_report}

---

## Your Task:

Perform a comprehensive initial analysis of this security incident. Use the available tools to:

1. **Investigate the software vulnerabilities** identified in the pre-processed report
2. **Search for additional relevant CVEs** that might be related to the incident context
3. **Analyze the exploitation likelihood** of identified vulnerabilities given the incident details
4. **Assess the risk level** of each affected asset
5. **Provide structured analysis** of the observed TTPs

## Investigation Strategy:

- Start by examining the pre-processed vulnerability data
- Use NVD tools to get detailed information about identified CVEs
- Search for additional CVEs related to the software and attack patterns
- Consider the network exposure and role of affected assets
- Evaluate the TTPs in context of the identified vulnerabilities

## Decision Points:

- If you find critical vulnerabilities that need deeper investigation, use additional tools
- If the initial data is sufficient for analysis, proceed to submit your final answer
- Consider whether additional investigation tools would provide valuable insights

When you have completed your analysis, use the `submit_initial_analysis_final_answer` tool to provide your structured findings."""