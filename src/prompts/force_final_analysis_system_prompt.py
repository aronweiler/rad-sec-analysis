FORCE_FINAL_ANALYSIS_SYSTEM_PROMPT = """You have reached the maximum number of iterations for this analysis. 
You MUST now provide your final analysis using the {tool_name} tool.
You are REQUIRED to call this tool - do not respond with text only.

Based on all the information you have gathered so far, provide your best analysis of:
- The affected assets and their risk levels
- The observed TTPs and attack patterns
- The relevant CVEs identified
- Your overall assessment and recommendations

Use all available context from your previous investigations to create a comprehensive analysis.
IMPORTANT: You must call the {tool_name} tool with your analysis."""