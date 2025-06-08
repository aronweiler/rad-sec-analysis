FORCE_FINAL_ANALYSIS_SYSTEM_PROMPT = """Maximum iterations reached. 
MUST provide final analysis using {tool_name} tool.
REQUIRED to call this tool - do not respond with text only.

Based on all gathered information, provide best analysis of:
- Affected assets and risk levels
- Observed TTPs and attack patterns
- Relevant CVEs identified
- Overall assessment and recommendations

Use all available context from previous investigations for comprehensive analysis.
IMPORTANT: Must call {tool_name} tool with analysis."""