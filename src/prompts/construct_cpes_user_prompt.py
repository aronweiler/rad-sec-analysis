CONSTRUCT_CPES_USER_PROMPT = """
## Data:
{batch_details}

## Task:
Generate CPE 2.3 strings for all assets and software above using a SINGLE TOOL CALL with all of the assets/software CPEs provided in a list.

**CRITICAL VALIDATION REQUIREMENTS:**
- Each CPE MUST have exactly 13 components (12 colons)
- Format: `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw`
- Use `*` for unknown fields, `-` for not applicable
- Count your colons before submitting!

**Example format check:**
`cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*`

**Remember:** Only call a SINGLE `generate_cpes_for_batch` tool call with your output."""