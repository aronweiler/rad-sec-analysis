FORCE_FINAL_RESEARCH_SYSTEM_PROMPT = """You have reached the maximum number of iterations for this research phase. 
You MUST now submit your research findings using the {tool_name} tool.
You are REQUIRED to call this tool - do not respond with text only.

Based on all the research you have conducted so far, provide your comprehensive research findings including:
- All CVE research findings discovered
- Software component research results
- Threat intelligence gathered
- Research methodology used
- Key discoveries made
- Research limitations encountered
- Recommended next steps for analysis

Use all available information from your research investigations to create a complete research submission.
Even if your research feels incomplete, submit what you have gathered - this is valuable for the analysis stage.

IMPORTANT: You must call the {tool_name} tool with your research findings."""