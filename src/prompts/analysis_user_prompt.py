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

**Note**: Research findings contain comprehensive intelligence from research phase. Use as primary source but conduct additional targeted research if gaps identified.

---

## Analysis Mission:

Synthesize research findings into comprehensive security analysis providing actionable insights and strategic recommendations.

## Analysis Objectives:

### 1. **Vulnerability Risk Analysis**
- Evaluate CVE relevance to specific incident
- Assess exploitation likelihood given incident context and environment
- Prioritize vulnerabilities by risk, not just CVSS scores
- Identify vulnerability chains supporting attack progression

### 2. **Asset Risk Assessment**
- Analyze risk profile of each affected asset
- Consider criticality, network exposure, vulnerability profile
- Assess lateral movement and privilege escalation potential
- Identify critical assets requiring immediate attention

### 3. **Attack Analysis**
- Synthesize observed TTPs into coherent attack narrative
- Assess attack sophistication and intent
- Analyze progression and identify potential next steps
- Evaluate threat actor capabilities and objectives

### 4. **Impact and Risk Evaluation**
- Assess current and potential incident impact
- Evaluate business continuity and operational risks
- Consider confidentiality, integrity, availability impacts
- Assess reputational and compliance implications

### 5. **Strategic Response Planning**
- Develop immediate action recommendations
- Provide short-term tactical improvements
- Suggest long-term strategic security enhancements
- Prioritize recommendations by urgency and impact

## Analysis Framework:

### **Evidence-Based Analysis**
- Base conclusions on research findings and incident evidence
- Document reasoning chain for major conclusions
- Assess confidence levels for significant findings
- Identify areas where additional evidence would strengthen conclusions

### **Risk-Focused Prioritization**
- Prioritize findings by risk and impact to organization
- Consider technical risk and business impact
- Account for environmental factors and organizational context
- Focus on actionable intelligence driving decision-making

### **Contextual Assessment**
- Consider specific environment, assets, business context
- Evaluate incident within broader threat landscape
- Assess likelihood of continued or escalated attacks
- Consider industry-specific and environmental factors

### **Actionable Recommendations**
- Provide clear, implementable recommendations
- Prioritize actions by urgency and impact
- Consider resource constraints and implementation feasibility
- Include technical and process improvements

## Quality Standards:

- **Comprehensive**: Address all incident and research aspects
- **Accurate**: Ensure conclusions supported by research evidence
- **Actionable**: Provide clear, implementable recommendations
- **Prioritized**: Rank findings and recommendations by importance and urgency
- **Confident**: Provide confidence assessments for major conclusions
- **Clear**: Present analysis supporting decision-making

## Expected Outcomes:

Analysis should produce:
- **Risk-Prioritized Vulnerability Assessment**: CVEs ranked by actual risk in context
- **Asset-Specific Risk Profiles**: Detailed risk assessment for each affected asset
- **Attack Narrative**: Coherent analysis of attack progression and threat actor
- **Impact Assessment**: Current and potential business and security impacts
- **Strategic Response Plan**: Immediate, short-term, and long-term recommendations
- **Confidence Assessment**: Clear confidence levels for major conclusions

## Submission Requirements:

When analysis complete, use `submit_analysis` tool to provide:
- Analysis of each affected asset with risk assessment
- Analysis of observed TTPs with confidence levels
- List of relevant CVEs with relevance scores and rationale
- Overall severity assessment
- Attack progression analysis
- Immediate actions needed
- Short-term and long-term recommendations
- Complete reasoning chain documenting analytical process

Your analysis drives critical security decisions. Ensure comprehensive, accurate, and actionable.

Every answer must be tool call. NEVER answer directly in chat."""