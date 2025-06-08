# Incident Research User Prompt

RESEARCH_USER_PROMPT = """# Security Incident Research Request

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

**Important**: Pre-processed vulnerability report is starting point from automated tools. May contain false positives, miss relevant vulnerabilities, or lack context. Research should validate, expand, and contextualize findings.

---

## Research Mission:

Conduct comprehensive research on security incident to gather all relevant information for thorough analysis. Research should be systematic, thorough, and focused on actionable intelligence.

## Research Objectives:

### 1. **Vulnerability Deep Dive**
- Research each software component mentioned in incident
- Validate and expand pre-processed vulnerability data
- Search for additional CVEs relevant to incident context
- Investigate version-specific vulnerabilities and exploitation status

### 2. **Attack Pattern Research**
- Research observed TTPs to understand attack methodologies
- Look for related attack campaigns or threat actor patterns
- Investigate how identified vulnerabilities support observed attack progression
- Search for indicators of similar attacks or campaigns

### 3. **Threat Intelligence Collection**
- Gather intelligence on threat actors using similar TTPs
- Research recent campaigns targeting similar software or organizations
- Investigate indicators of compromise for additional context
- Look for attribution indicators or campaign connections

### 4. **Software Component Analysis**
- Research each affected software component for:
  - Known security issues beyond CVEs
  - Configuration vulnerabilities
  - Default credential issues
  - Update and patch status
  - End-of-life considerations

### 5. **Contextual Intelligence**
- Research environmental factors affecting exploitation
- Investigate network exposure considerations
- Look for asset criticality and business impact information
- Research detection and mitigation strategies

## Research Strategy Guidelines:

- **Start Broad, Then Focus**: Begin with general searches, drill down into specific findings
- **Follow Evidence**: Let discoveries guide additional research directions
- **Cross-Validate**: Verify important findings across multiple sources
- **Document Methodology**: Track research approach and sources
- **Assess Confidence**: Evaluate reliability and confidence of each finding
- **Identify Gaps**: Note areas where research was limited or information unavailable

## Quality Standards:

- **Relevance**: Focus on information directly applicable to incident
- **Accuracy**: Ensure findings properly sourced and verified
- **Completeness**: Aim for comprehensive coverage of all incident components
- **Timeliness**: Prioritize recent and current threat intelligence
- **Actionability**: Gather information supporting decision-making in analysis phase

## Expected Outcomes:

Research should produce:
- **Enhanced CVE Intelligence**: Detailed information about relevant vulnerabilities
- **Software Security Profiles**: Comprehensive security assessments of affected software
- **Threat Context**: Intelligence about threat actors, campaigns, attack patterns
- **Environmental Factors**: Information about incident environment and context
- **Research Documentation**: Clear methodology and source documentation
- **Gap Analysis**: Identification of research limitations and areas needing follow-up

## Submission Requirements:

When research complete, use `submit_research` tool to provide:
- All CVE research findings with relevance assessments
- Software component research results
- Threat intelligence discoveries
- Research methodology and sources consulted
- Key discoveries and insights
- Identified research gaps and limitations
- Recommended next steps for analysis stage

Analysis stage depends on research quality and comprehensiveness. Be thorough, systematic, and document clearly.

Every answer must be tool call. NEVER answer directly in chat."""