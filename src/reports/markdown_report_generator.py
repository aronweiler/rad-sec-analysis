"""
Markdown Report Generator

Generates comprehensive human-readable markdown reports from incident analysis results.
Designed to demonstrate AI agent capabilities and provide actionable intelligence.
"""

from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from src.tools.lc_tools.submit_analysis_tool import AnalysisVerificationResult
from src.tools.lc_tools.incident_analysis_result import (
    IncidentAnalysisResult,
    CVEAnalysis,
    AssetRiskAssessment,
    TTPAnalysis,
    VulnerabilityChain,
    ActionableRecommendation,
    RiskLevel,
    ExploitationLikelihood
)


class MarkdownReportGenerator:
    """Generates markdown reports from incident analysis results"""
    
    def __init__(self):
        self.risk_level_icons = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠", 
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢",
            RiskLevel.UNKNOWN: "⚪"
        }
        
        self.exploitation_icons = {
            ExploitationLikelihood.VERY_HIGH: "🔴",
            ExploitationLikelihood.HIGH: "🟠",
            ExploitationLikelihood.MEDIUM: "🟡", 
            ExploitationLikelihood.LOW: "🟢",
            ExploitationLikelihood.VERY_LOW: "🟢",
            ExploitationLikelihood.UNKNOWN: "⚪"
        }
    
    def generate_report(self, verification_result: AnalysisVerificationResult) -> str:
        """Generate a complete markdown report from analysis verification result"""

        analysis = verification_result.analysis

        sections = [
            self._generate_header(analysis),
            self._generate_executive_summary(analysis),
            self._generate_risk_dashboard(analysis),
            self._generate_validation_summary(verification_result),
            self._generate_vulnerability_analysis(analysis),
            self._generate_asset_impact_assessment(analysis),
            self._generate_attack_analysis(analysis),
            self._generate_remediation_roadmap(analysis),
            self._generate_ai_methodology(analysis, verification_result),
            self._generate_technical_appendix(analysis)
        ]

        # Add tool usage report if messages are provided
        if verification_result.messages:
            sections.append(self._generate_tool_usage_report(verification_result.messages))

        return "\n\n".join(sections)
    
    def _generate_header(self, analysis: IncidentAnalysisResult) -> str:
        """Generate report header with metadata"""
        
        confidence_bar = "█" * int(analysis.analyst_confidence) + "░" * (10 - int(analysis.analyst_confidence))
        
        return f"""# 🛡️ AI-Powered Incident Analysis Report

**Incident ID:** `{analysis.incident_id}`  
**Analysis Date:** {analysis.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Overall Risk:** {self.risk_level_icons[analysis.overall_risk_assessment]} **{analysis.overall_risk_assessment.value.upper()}**  
**AI Confidence:** {analysis.analyst_confidence}/10 `{confidence_bar}`

---"""
    
    def _generate_executive_summary(self, analysis: IncidentAnalysisResult) -> str:
        """Generate executive summary section"""
        
        return f"""## 📋 Executive Summary

{analysis.executive_summary}

### Key Findings

- **Attack Sophistication:** {analysis.attack_sophistication}
- **Primary Risk Level:** {self.risk_level_icons[analysis.overall_risk_assessment]} {analysis.overall_risk_assessment.value.title()}
- **CVEs Identified:** {len(analysis.prioritized_relevant_cves)}
- **Assets Analyzed:** {len(analysis.asset_risk_assessments)}
- **Critical Assets:** {len(analysis.most_critical_assets)}
- **Attack Techniques:** {len(analysis.ttp_analysis)} TTPs analyzed"""
    
    def _generate_risk_dashboard(self, analysis: IncidentAnalysisResult) -> str:
        """Generate risk assessment dashboard"""
        
        # Count CVEs by risk level
        cve_risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0} 
        
        for cve in analysis.prioritized_relevant_cves:
            if cve.exploitation_likelihood in [ExploitationLikelihood.VERY_HIGH, ExploitationLikelihood.HIGH]:
                if cve.cvss_score and cve.cvss_score >= 9.0:
                    cve_risk_counts["critical"] += 1
                elif cve.cvss_score and cve.cvss_score >= 7.0:
                    cve_risk_counts["high"] += 1
                else:
                    cve_risk_counts["medium"] += 1
            else:
                cve_risk_counts["low"] += 1
        
        # Count assets by risk level
        asset_risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for asset in analysis.asset_risk_assessments:
            if asset.overall_risk_level == RiskLevel.CRITICAL:
                asset_risk_counts["critical"] += 1
            elif asset.overall_risk_level == RiskLevel.HIGH:
                asset_risk_counts["high"] += 1
            elif asset.overall_risk_level == RiskLevel.MEDIUM:
                asset_risk_counts["medium"] += 1
            else:
                asset_risk_counts["low"] += 1
        
        return f"""## 📊 Risk Assessment Dashboard

### Vulnerability Risk Distribution
| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🔴 Critical | {cve_risk_counts['critical']} | {(cve_risk_counts['critical']/max(len(analysis.prioritized_relevant_cves), 1)*100):.1f}% |
| 🟠 High | {cve_risk_counts['high']} | {(cve_risk_counts['high']/max(len(analysis.prioritized_relevant_cves), 1)*100):.1f}% |
| 🟡 Medium | {cve_risk_counts['medium']} | {(cve_risk_counts['medium']/max(len(analysis.prioritized_relevant_cves), 1)*100):.1f}% |
| 🟢 Low | {cve_risk_counts['low']} | {(cve_risk_counts['low']/max(len(analysis.prioritized_relevant_cves), 1)*100):.1f}% |

### Asset Risk Distribution
| Risk Level | Count | Assets |
|------------|-------|--------|
| 🔴 Critical | {asset_risk_counts['critical']} | {', '.join([a.hostname for a in analysis.asset_risk_assessments if a.overall_risk_level == RiskLevel.CRITICAL]) or 'None'} |
| 🟠 High | {asset_risk_counts['high']} | {', '.join([a.hostname for a in analysis.asset_risk_assessments if a.overall_risk_level == RiskLevel.HIGH]) or 'None'} |
| 🟡 Medium | {asset_risk_counts['medium']} | {', '.join([a.hostname for a in analysis.asset_risk_assessments if a.overall_risk_level == RiskLevel.MEDIUM]) or 'None'} |
| 🟢 Low | {asset_risk_counts['low']} | {', '.join([a.hostname for a in analysis.asset_risk_assessments if a.overall_risk_level == RiskLevel.LOW]) or 'None'} |"""
    
    def _generate_validation_summary(self, verification_result: AnalysisVerificationResult) -> str:
        """Generate validation and quality summary"""
        
        validation_icon = "✅" if verification_result.validation_passed else "⚠️"
        
        validation_details = []
        if verification_result.validation_warnings:
            validation_details.append(f"- **Warnings:** {len(verification_result.validation_warnings)}")
        if verification_result.completeness_issues:
            validation_details.append(f"- **Completeness Issues:** {len(verification_result.completeness_issues)}")
        
        validation_section = f"""## {validation_icon} Analysis Validation

**Status:** {verification_result.validation_summary}

### Validation Details
{chr(10).join(validation_details) if validation_details else "- No issues identified"}"""
        
        if verification_result.validation_warnings:
            validation_section += "\n\n### Validation Warnings\n"
            for warning in verification_result.validation_warnings:
                validation_section += f"- **{warning.category}** ({warning.severity}): {warning.message}\n"
        
        if verification_result.completeness_issues:
            validation_section += "\n\n### Completeness Issues\n"
            for issue in verification_result.completeness_issues:
                validation_section += f"- **{issue.category}**: {issue.message}\n"
        
        return validation_section
    
    def _generate_vulnerability_analysis(self, analysis: IncidentAnalysisResult) -> str:
        """Generate detailed vulnerability analysis section"""
        
        section = """## 🔍 Vulnerability Analysis

### CVE Prioritization Methodology
""" + analysis.cve_prioritization_rationale
        
        if analysis.prioritized_relevant_cves:
            section += "\n\n### Critical Vulnerabilities\n"
            section += self._generate_cve_table(analysis.prioritized_relevant_cves)
    
        
        return section
    
    def _generate_cve_table(self, cves: List[CVEAnalysis]) -> str:
        """Generate a formatted table of CVE analyses"""
        
        if not cves:
            return "*No CVEs in this category*"
        
        # Sort by mitigation priority (highest first)
        sorted_cves = sorted(cves, key=lambda x: x.mitigation_priority, reverse=True)
        
        table = """| CVE ID | CVSS | Exploitation Risk | Priority | Affected Software |
|--------|------|------------------|----------|-------------------|
"""
        
        for cve in sorted_cves:
            cvss_display = f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
            exploitation_icon = self.exploitation_icons[cve.exploitation_likelihood]
            software_list = ", ".join(cve.affected_software[:2])  # Limit to first 2 for table width
            if len(cve.affected_software) > 2:
                software_list += "..."
            
            table += f"| {cve.cve_id} | {cvss_display} | {exploitation_icon} {cve.exploitation_likelihood.value} | {cve.mitigation_priority}/10 | {software_list} |\n"
        
        # Add detailed analysis for top 3 CVEs
        table += "\n### Detailed CVE Analysis\n"
        for cve in sorted_cves[:3]:
            table += f"""
#### {cve.cve_id} - Priority {cve.mitigation_priority}/10

**Attack Vector Alignment:** {cve.attack_vector_alignment}

**Contextual Risk Assessment:** {cve.contextual_risk_assessment}

**Affected Software:** {', '.join(cve.affected_software)}

**Exploitation Evidence:** {cve.exploitation_evidence or 'No direct evidence found'}
"""
        
        return table
    
    def _generate_asset_impact_assessment(self, analysis: IncidentAnalysisResult) -> str:
        """Generate asset impact assessment section"""
        
        section = """## 🏢 Asset Impact Assessment

### Most Critical Assets
"""
        
        if analysis.most_critical_assets:
            for hostname in analysis.most_critical_assets:
                asset = next((a for a in analysis.asset_risk_assessments if a.hostname == hostname), None)
                if asset:
                    section += f"- **{hostname}** ({asset.role}) - {self.risk_level_icons[asset.overall_risk_level]} {asset.overall_risk_level.value.title()}\n"
        else:
            section += "*No assets specifically flagged as most critical*\n"
        
        section += "\n### Detailed Asset Analysis\n"
        
        # Sort assets by risk level
        risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.UNKNOWN: 4}
        sorted_assets = sorted(analysis.asset_risk_assessments, key=lambda x: risk_order[x.overall_risk_level])
        
        for asset in sorted_assets:
            section += f"""
#### {self.risk_level_icons[asset.overall_risk_level]} {asset.hostname} ({asset.ip_address})

**Role:** {asset.role}  
**Risk Level:** {asset.overall_risk_level.value.title()}  
**Vulnerabilities:** {asset.vulnerability_count} total, {len(asset.critical_vulnerabilities)} critical  
**Network Exposure:** {asset.network_exposure}  
**Business Impact:** {asset.business_impact_potential}

**Critical CVEs:** {', '.join(asset.critical_vulnerabilities) if asset.critical_vulnerabilities else 'None'}

**Compromise Indicators:**
{chr(10).join([f'- {indicator}' for indicator in asset.compromise_indicators]) if asset.compromise_indicators else '- None identified'}

**Recommended Actions:**
{chr(10).join([f'- {action}' for action in asset.recommended_actions]) if asset.recommended_actions else '- No specific actions recommended'}
"""
        
        return section
    
    def _generate_attack_analysis(self, analysis: IncidentAnalysisResult) -> str:
        """Generate attack progression and TTP analysis"""
        
        section = f"""## ⚔️ Attack Analysis

### Attack Progression Timeline
{analysis.attack_progression}

### MITRE ATT&CK Technique Analysis
"""
        
        if analysis.ttp_analysis:
            for ttp in analysis.ttp_analysis:
                section += f"""
#### {ttp.ttp_id}: {ttp.ttp_name}

**Framework:** {ttp.framework}  
**Attack Stage:** {ttp.attack_stage}  
**Relevance to Vulnerabilities:** {ttp.relevance_to_vulnerabilities}

**Supporting CVEs:** {', '.join(ttp.supporting_cves) if ttp.supporting_cves else 'None identified'}

**Defensive Gaps Exploited:**
{chr(10).join([f'- {gap}' for gap in ttp.defensive_gaps]) if ttp.defensive_gaps else '- None identified'}

**Detection Opportunities:**
{chr(10).join([f'- {opportunity}' for opportunity in ttp.detection_opportunities]) if ttp.detection_opportunities else '- None identified'}
"""
        else:
            section += "*No TTP analysis available*"
        
        if analysis.potential_attack_chains:
            section += "\n### Potential Attack Chains\n"
            for chain in analysis.potential_attack_chains:
                likelihood_icon = self.exploitation_icons[chain.likelihood]
                section += f"""
#### {chain.chain_id}: {chain.description}

**Likelihood:** {likelihood_icon} {chain.likelihood.value.title()}  
**CVEs in Chain:** {', '.join(chain.cves_in_chain)}  
**Impact Assessment:** {chain.impact_assessment}

**Supporting Evidence:**
{chr(10).join([f'- {evidence}' for evidence in chain.supporting_evidence]) if chain.supporting_evidence else '- No specific evidence'}
"""
        
        if analysis.most_likely_attack_path:
            section += f"\n### Most Likely Attack Path\n{analysis.most_likely_attack_path}"
        
        return section
    
    def _generate_remediation_roadmap(self, analysis: IncidentAnalysisResult) -> str:
        """Generate remediation roadmap with prioritized actions"""
        
        section = """## 🛠️ Remediation Roadmap

### Immediate Actions (24-48 Hours)
"""
        
        section += self._generate_recommendations_table(analysis.immediate_actions)
        
        section += "\n### Short-Term Recommendations (1-4 Weeks)\n"
        section += self._generate_recommendations_table(analysis.short_term_recommendations)
        
        section += "\n### Long-Term Strategic Improvements (1-6 Months)\n"
        section += self._generate_recommendations_table(analysis.long_term_recommendations)
        
        return section
    
    def _generate_recommendations_table(self, recommendations: List[ActionableRecommendation]) -> str:
        """Generate a table of recommendations"""
        
        if not recommendations:
            return "*No recommendations in this category*\n"
        
        # Sort by priority (highest first)
        sorted_recs = sorted(recommendations, key=lambda x: x.priority, reverse=True)
        
        table = """| Priority | Action | Effort | Risk Reduction |
|----------|--------|--------|----------------|
"""
        
        for rec in sorted_recs:
            table += f"| {rec.priority}/10 | {rec.action[:50]}{'...' if len(rec.action) > 50 else ''} | {rec.estimated_effort} | {rec.risk_reduction[:30]}{'...' if len(rec.risk_reduction) > 30 else ''} |\n"
        
        # Add detailed breakdown for top recommendations
        table += "\n#### Detailed Action Plans\n"
        for rec in sorted_recs[:3]:  # Top 3 recommendations
            table += f"""
**{rec.action}** (Priority: {rec.priority}/10)

*Rationale:* {rec.rationale}

*Affected Assets:* {', '.join(rec.affected_assets) if rec.affected_assets else 'All systems'}  
*Related CVEs:* {', '.join(rec.related_cves) if rec.related_cves else 'N/A'}  
*Estimated Effort:* {rec.estimated_effort}  
*Expected Risk Reduction:* {rec.risk_reduction}
"""
        
        return table
    
    def _generate_ai_methodology(self, analysis: IncidentAnalysisResult, verification_result: AnalysisVerificationResult) -> str:
        """Generate AI methodology and reasoning transparency section"""
        
        section = f"""## 🤖 AI Analysis Methodology

### Reasoning Chain
The AI agent followed this analytical process:

{chr(10).join([f'{i+1}. {step}' for i, step in enumerate(analysis.reasoning_chain)])}

### Data Sources Consulted
{chr(10).join([f'- {source}' for source in analysis.data_sources_used])}

### Analysis Confidence Factors
- **Overall Confidence:** {analysis.analyst_confidence}/10
- **Validation Status:** {'✅ Passed' if verification_result.validation_passed else '⚠️ Issues Found'}
- **Data Quality:** {len(verification_result.validation_warnings)} warnings, {len(verification_result.completeness_issues)} completeness issues

### Limitations and Assumptions
{chr(10).join([f'- {limitation}' for limitation in analysis.limitations_and_assumptions])}"""
        
        if analysis.threat_actor_assessment:
            section += f"\n\n### Threat Actor Assessment\n{analysis.threat_actor_assessment}"
        
        if analysis.environmental_factors:
            section += f"\n\n### Environmental Factors\n{chr(10).join([f'- {factor}' for factor in analysis.environmental_factors])}"
        
        if analysis.detection_gaps:
            section += f"\n\n### Detection Gaps Identified\n{chr(10).join([f'- {gap}' for gap in analysis.detection_gaps])}"
        
        return section
    
    def _generate_technical_appendix(self, analysis: IncidentAnalysisResult) -> str:
        """Generate technical appendix with additional details"""

        section = """## 📚 Technical Appendix

### Follow-Up Investigation Recommendations
    """

        if analysis.follow_up_investigations:
            section += chr(10).join([f"- {investigation}" for investigation in analysis.follow_up_investigations])
        else:
            section += "*No specific follow-up investigations recommended*"

        section += f"""

### Report Metadata
- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Analysis Timestamp:** {analysis.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Incident ID:** {analysis.incident_id}
- **AI Confidence Level:** {analysis.analyst_confidence}/10

---
*This report was generated by an AI-powered incident analysis system. All findings should be validated by human security analysts before implementation.*"""

        return section

    def _generate_tool_usage_report(self, messages: List[Dict[str, Any]]) -> str:
        """Generate a report of AI tool usage from conversation messages"""

        import json

        section = """## 🔧 AI Tool Usage Report

This section documents all tools called by the AI agent during the analysis process, demonstrating the agent's research methodology and data gathering approach.

    """

        tool_calls = []

        # Extract tool calls from AI messages and their results from ToolMessages
        for i, message in enumerate(messages):
            # Check if this is an AI message with tool calls
            if (message.get('type') == 'ai' or 
                isinstance(message.get('content'), dict) or 
                'tool_calls' in message):

                message_tool_calls = message.get('tool_calls', [])
                if message_tool_calls:
                    for tool_call in message_tool_calls:
                        tool_info = {
                            'name': tool_call.get('name', 'Unknown'),
                            'args': tool_call.get('args', {}),
                            'id': tool_call.get('id', 'Unknown'),
                            'result': None
                        }

                        # Find corresponding ToolMessage result
                        for j in range(i + 1, len(messages)):
                            next_message = messages[j]
                            if (next_message.get('type') == 'tool' and 
                                next_message.get('tool_call_id') == tool_info['id']):
                                tool_info['result'] = next_message.get('content', 'No content')
                                break

                        tool_calls.append(tool_info)

        if not tool_calls:
            section += "*No tool calls were made during this analysis.*\n"
            return section

        section += f"**Total Tools Called:** {len(tool_calls)}\n\n"

        # Group tool calls by tool name for summary
        tool_summary = {}
        for call in tool_calls:
            tool_name = call['name']
            if tool_name not in tool_summary:
                tool_summary[tool_name] = 0
            tool_summary[tool_name] += 1

        section += "### Tool Usage Summary\n"
        section += "| Tool Name | Times Called |\n"
        section += "|-----------|-------------|\n"
        for tool_name, count in tool_summary.items():
            section += f"| {tool_name} | {count} |\n"

        section += "\n### Detailed Tool Call Log\n"

        for i, call in enumerate(tool_calls, 1):
            section += f"\n#### Tool Call #{i}: {call['name']}\n"

            # Format arguments
            if call['args']:
                section += "**Arguments:**\n```json\n"
                try:
                    # Pretty print JSON arguments, but truncate very long values
                    formatted_args = {}
                    for key, value in call['args'].items():
                        if isinstance(value, str) and len(value) > 200:
                            formatted_args[key] = value[:200] + "... [truncated]"
                        elif isinstance(value, (list, dict)) and len(str(value)) > 500:
                            formatted_args[key] = "[Large data structure - truncated for readability]"
                        else:
                            formatted_args[key] = value

                    section += json.dumps(formatted_args, indent=2, default=str)
                except Exception:
                    section += str(call['args'])
                section += "\n```\n"
            else:
                section += "**Arguments:** None\n"

            # Format result (truncated for readability)
            if call['result']:
                result_preview = call['result']
                if len(result_preview) > 300:
                    result_preview = result_preview[:300] + "... [truncated]"

                section += f"**Result Preview:**\n```\n{result_preview}\n```\n"

                # Add result length info
                section += f"*Full result length: {len(call['result'])} characters*\n"
            else:
                section += "**Result:** No result captured\n"

        section += "\n### Tool Usage Analysis\n"

        # Analyze tool usage patterns
        research_tools = [call for call in tool_calls if call['name'] not in ['submit_analysis', 'submit_initial_analysis_final_answer']]
        final_tools = [call for call in tool_calls if call['name'] in ['submit_analysis', 'submit_initial_analysis_final_answer']]

        section += f"- **Research Tools Used:** {len(research_tools)} calls\n"
        section += f"- **Final Submission Tools:** {len(final_tools)} calls\n"

        if research_tools:
            unique_research_tools = set(call['name'] for call in research_tools)
            section += f"- **Unique Research Tools:** {', '.join(unique_research_tools)}\n"

        section += f"- **Total Analysis Steps:** {len(tool_calls)} tool interactions\n"

        section += "\n*This tool usage log demonstrates the AI agent's systematic approach to gathering and analyzing security intelligence.*\n"

        return section
    
    def generate_customer_report(self, verification_result: AnalysisVerificationResult) -> str:
        """Generate a concise, customer-facing incident report"""

        analysis = verification_result.analysis

        # Calculate key metrics
        critical_cves = [cve for cve in analysis.prioritized_relevant_cves if cve.exploitation_likelihood in [ExploitationLikelihood.VERY_HIGH, ExploitationLikelihood.HIGH]]
        high_risk_assets = [asset for asset in analysis.asset_risk_assessments if asset.overall_risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]

        # Get immediate actions count
        immediate_actions_count = len(analysis.immediate_actions)

        report = f"""# Security Incident Analysis Report

**Incident ID:** {analysis.incident_id}  
**Analysis Date:** {analysis.analysis_timestamp.strftime('%B %d, %Y')}  
**Overall Risk Level:** {self.risk_level_icons[analysis.overall_risk_assessment]} **{analysis.overall_risk_assessment.value.upper()}**

---

## Executive Summary

{analysis.executive_summary}

## Key Findings

### Security Impact
- **{len(analysis.prioritized_relevant_cves)} vulnerabilities** identified across your systems
- **{len(critical_cves)} high-priority vulnerabilities** require immediate attention
- **{len(analysis.asset_risk_assessments)} systems** were analyzed for security impact
- **{len(high_risk_assets)} systems** are at elevated risk and need priority remediation

### Attack Assessment
{analysis.attack_sophistication}

## Critical Vulnerabilities Requiring Immediate Attention

"""

        if critical_cves:
            # Sort by mitigation priority
            sorted_critical = sorted(critical_cves, key=lambda x: x.mitigation_priority, reverse=True)

            report += "| Vulnerability | Risk Level | Affected Systems | Priority |\n"
            report += "|---------------|------------|------------------|----------|\n"

            for cve in sorted_critical[:5]:  # Top 5 critical CVEs
                risk_icon = self.exploitation_icons[cve.exploitation_likelihood]
                affected_systems = ", ".join(cve.affected_software[:2])
                if len(cve.affected_software) > 2:
                    affected_systems += f" (+{len(cve.affected_software)-2} more)"

                report += f"| {cve.cve_id} | {risk_icon} {cve.exploitation_likelihood.value.title()} | {affected_systems} | {cve.mitigation_priority}/10 |\n"

            if len(critical_cves) > 5:
                report += f"\n*{len(critical_cves) - 5} additional critical vulnerabilities identified in the full technical report.*\n"
        else:
            report += "*No critical vulnerabilities requiring immediate attention were identified.*\n"

        report += """

## Systems Requiring Priority Attention

    """

        if high_risk_assets:
            for asset in sorted(high_risk_assets, key=lambda x: x.overall_risk_level.value):
                risk_icon = self.risk_level_icons[asset.overall_risk_level]
                report += f"### {risk_icon} {asset.hostname}\n"
                report += f"**Function:** {asset.role}  \n"
                report += f"**Risk Level:** {asset.overall_risk_level.value.title()}  \n"
                report += f"**Business Impact:** {asset.business_impact_potential}  \n"

                if asset.critical_vulnerabilities:
                    report += f"**Critical Issues:** {len(asset.critical_vulnerabilities)} vulnerabilities need immediate patching  \n"

                report += "\n"
        else:
            report += "*All analyzed systems are at acceptable risk levels.*\n"

        report += f"""

## Recommended Actions

We have identified **{immediate_actions_count} immediate actions** to improve your security posture:

    """

        if analysis.immediate_actions:
            # Sort by priority and show top actions
            sorted_actions = sorted(analysis.immediate_actions, key=lambda x: x.priority, reverse=True)

            for i, action in enumerate(sorted_actions[:3], 1):  # Top 3 actions
                report += f"**{i}. {action.action}** (Priority: {action.priority}/10)\n"
                report += f"   - *Why this matters:* {action.rationale}\n"
                report += f"   - *Estimated effort:* {action.estimated_effort}\n"
                report += f"   - *Risk reduction:* {action.risk_reduction}\n\n"

            if len(analysis.immediate_actions) > 3:
                report += f"*{len(analysis.immediate_actions) - 3} additional recommendations are detailed in the full technical report.*\n\n"
        else:
            report += "*No immediate actions required at this time.*\n\n"

        # Add timeline if attack progression is available
        if analysis.attack_progression:
            report += f"""## Incident Timeline

    {analysis.attack_progression}

    """

        # Add next steps
        report += """## Next Steps

1. **Review and prioritize** the recommended actions based on your business requirements
2. **Implement immediate security measures** for high-priority vulnerabilities
3. **Schedule remediation activities** according to the priority levels identified
4. **Monitor systems** for any signs of ongoing compromise

    """

        # Add contact/support section
        report += f"""## Additional Information

- **Analysis Confidence Level:** {analysis.analyst_confidence}/10
- **Validation Status:** {'✅ Verified' if verification_result.validation_passed else '⚠️ Requires Review'}

For detailed technical information, implementation guidance, or questions about this analysis, please refer to the comprehensive technical report or contact your security team.

---

*Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')} using AI-powered security analysis.*  
*This analysis is based on available data at the time of assessment. Regular security reviews are recommended.*"""

        return report

    def save_customer_report(self, verification_result: AnalysisVerificationResult, output_path: str = None) -> str:
        """Generate and save the customer-facing report to a file"""

        report_content = self.generate_customer_report(verification_result)

        if output_path is None:
            # Generate default filename
            incident_id = verification_result.analysis.incident_id
            timestamp = verification_result.analysis.analysis_timestamp.strftime('%Y%m%d_%H%M%S')
            output_path = f"customer_incident_report_{incident_id}_{timestamp}.md"

        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write the report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)

        return str(output_file)
    
    def save_report(self, verification_result: AnalysisVerificationResult, output_path: str = None) -> str:
        """Generate and save the markdown report to a file"""

        report_content = self.generate_report(verification_result)

        if output_path is None:
            # Generate default filename
            incident_id = verification_result.analysis.incident_id
            timestamp = verification_result.analysis.analysis_timestamp.strftime('%Y%m%d_%H%M%S')
            output_path = f"incident_analysis_{incident_id}_{timestamp}.md"

        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write the report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)

        return str(output_file)