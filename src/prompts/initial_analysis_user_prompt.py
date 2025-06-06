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

**Note**: When submitting your analysis about affected assets, the asset name must match EXACTLY.

## Observed TTPs:
{observed_ttps_info}

## Indicators of Compromise:
{indicators_info}

**Note**: The TTPs and indicators of compromise are provided to help you understand the context of the incident. They can provide valuable insights into the attacker's methods and goals.

## Pre-processed Vulnerability Report:
{vulnerability_report}

***Note***: The pre-processed vulnerability report contains a list of software vulnerabilities by an automated tool. It should not be considered exhaustive, or even correct.  It is possible that some vulnerabilities are not relevant to the incident, or that some relevant vulnerabilities are not listed.  You should use this report as a starting point for your analysis, but you should also search for additional vulnerabilities and CVEs that may be relevant to the incident.

---

## Your Task:

Perform a comprehensive initial analysis of this security incident. Use the available tools to:

1. **Investigate the software vulnerabilities** identified in the pre-processed report
2. **Search for additional relevant CVEs** that might be related to the incident context
3. **Analyze the exploitation likelihood** of identified vulnerabilities given the incident details
4. **Assess the risk level** of each affected asset
5. **Provide structured analysis** of the observed TTPs

## Investigation Strategy:

- Start by examining the pre-processed vulnerability data for relevance to the incident
- Use the available tools to search for CVEs related to the software and attack patterns
- Consider the network exposure and role of affected assets
- Evaluate the TTPs in context of the identified vulnerabilities

## Analysis Goals:

- **Contextualize Vulnerabilities**: Map identified CVEs to the specific incident context, considering the attack timeline, affected systems, and observed behaviors
- **Assess Exploitation Likelihood**: Evaluate which vulnerabilities are most likely to have been exploited given the incident's TTPs and environmental factors
- **Prioritize by Impact**: Rank CVEs not just by CVSS scores, but by their potential impact within this specific incident scenario and organizational context
- **Identify Attack Chains**: Discover potential vulnerability chains that could support the observed attack progression and lateral movement
- **Evaluate Asset Risk**: Assess how the identified vulnerabilities affect the security posture of each compromised or at-risk asset
- **Generate Actionable Intelligence**: Provide clear recommendations for immediate response actions based on the vulnerability analysis
- **Document Reasoning Chain**: Maintain transparent reasoning for all conclusions to support analyst review and decision-making

When you have completed your analysis, use the `submit_analysis` tool to provide your structured findings.

Every answer must be in the form of a tool call. You should NEVER answer directly in the chat."""