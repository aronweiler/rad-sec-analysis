FORCE_FINAL_RESEARCH_SYSTEM_PROMPT = """Maximum iterations reached. 
MUST submit research findings using {tool_name} tool.
REQUIRED to call this tool - do not respond with text only.

Based on all research conducted, provide comprehensive findings including:
- All CVE research findings discovered
- Software component research results
- Threat intelligence gathered
- Research methodology used
- Key discoveries made
- Research limitations encountered
- Recommended next steps for analysis

Use all available information from research investigations for complete submission.
Even if research feels incomplete, submit gathered findings - valuable for analysis stage.

IMPORTANT: Must call {tool_name} tool with research findings."""