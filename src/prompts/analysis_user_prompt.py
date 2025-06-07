# Incident Analysis User Prompt

ANALYSIS_USER_PROMPT = """# Security Incident Analysis Request

## Incident Information:
**Incident ID**: {incident_id}
**Timestamp**: {timestamp}
**Title**: {title}
**Description**: {description}

## Affected Assets:
{affected_assets_info}

## Observed TTPs:
{observed_ttps_info}

## Indicators of Compromise:
{indicators_info}

## Research Findings:
{research_findings}

**Note**: The research findings above contain comprehensive intelligence gathered during the research phase. Use these findings as the primary source for your analysis, but you may conduct additional targeted research if specific gaps are identified.

---

## Your Analysis Mission:

Synthesize the research findings into a comprehensive security analysis that provides actionable insights and strategic recommendations for this incident.

## Analysis Objectives:

### 1. **Vulnerability Risk Analysis**
- Evaluate each CVE identified in the research for its relevance to this specific incident
- Assess the exploitation likelihood given the incident context and environmental factors
- Prioritize vulnerabilities based on risk, not just CVSS scores
- Identify potential vulnerability chains that could support attack progression

### 2. **Asset Risk Assessment**
- Analyze the risk profile of each affected asset
- Consider asset criticality, network exposure, and vulnerability profile
- Assess the potential for lateral movement and privilege escalation
- Identify the most critical assets requiring immediate attention

### 3. **Attack Analysis**
- Synthesize the observed TTPs into a coherent attack narrative
- Assess the sophistication and intent of the attack
- Analyze the attack progression and identify potential next steps
- Evaluate the threat actor's capabilities and objectives

### 4. **Impact and Risk Evaluation**
- Assess the current and potential impact of the incident
- Evaluate business continuity and operational risks
- Consider data confidentiality, integrity, and availability impacts
- Assess reputational and compliance implications

### 5. **Strategic Response Planning**
- Develop immediate action recommendations
- Provide short-term tactical improvements
- Suggest long-term strategic security enhancements
- Prioritize recommendations by urgency and impact

## Analysis Framework:

### **Evidence-Based Analysis**
- Base all conclusions on the research findings and incident evidence
- Clearly document the reasoning chain for major conclusions
- Assess confidence levels for all significant findings
- Identify areas where additional evidence would strengthen conclusions

### **Risk-Focused Prioritization**
- Prioritize findings by their risk and impact to the organization
- Consider both technical risk and business impact
- Account for environmental factors and organizational context
- Focus on actionable intelligence that drives decision-making

### **Contextual Assessment**
- Consider the specific environment, assets, and business context
- Evaluate the incident within the broader threat landscape
- Assess the likelihood of continued or escalated attacks
- Consider industry-specific and environmental factors

### **Actionable Recommendations**
- Provide clear, implementable recommendations
- Prioritize actions by urgency and impact
- Consider resource constraints and implementation feasibility
- Include both technical and process improvements

## Analysis Quality Standards:

- **Comprehensive**: Address all aspects of the incident and research findings
- **Accurate**: Ensure all conclusions are supported by evidence from the research
- **Actionable**: Provide clear, implementable recommendations
- **Prioritized**: Rank findings and recommendations by importance and urgency
- **Confident**: Provide confidence assessments for major conclusions
- **Clear**: Present analysis in terms that support decision-making

## Expected Analysis Outcomes:

Your analysis should produce:
- **Risk-Prioritized Vulnerability Assessment**: CVEs ranked by actual risk in this context
- **Asset-Specific Risk Profiles**: Detailed risk assessment for each affected asset
- **Attack Narrative**: Coherent analysis of the attack progression and threat actor
- **Impact Assessment**: Current and potential business and security impacts
- **Strategic Response Plan**: Immediate, short-term, and long-term recommendations
- **Confidence Assessment**: Clear confidence levels for all major conclusions

## Submission Requirements:

When your analysis is complete, use the `submit_analysis` tool to provide:
- Analysis of each affected asset with risk assessment
- Analysis of observed TTPs with confidence levels
- List of relevant CVEs with relevance scores and rationale
- Overall severity assessment
- Attack progression analysis
- Immediate actions needed
- Short-term and long-term recommendations
- Complete reasoning chain documenting your analytical process

Remember: Your analysis will drive critical security decisions. Ensure it is comprehensive, accurate, and actionable.

Every answer must be in the form of a tool call. You should NEVER answer directly in the chat."""