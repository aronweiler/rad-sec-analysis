# CPE Construction User Prompt

CONSTRUCT_CPES_USER_PROMPT = """# CPE Generation - Batch {batch_number}/{total_batches}

## Batch Stats:
- Assets: {asset_count}
- Software: {software_count}

## Data:
{batch_details}

## Task:
Generate CPE 2.3 strings for all assets and software above.

## Tool Call Format:
```
generate_cpes_for_batch(asset_mappings=[
  {{
    "asset_hostname": "exact_hostname",
    "asset_ip": "exact_ip", 
    "cpe_string": "cpe:2.3:o:vendor:product:version:*:*:*:*:*:*:*",
    "cpe_type": "asset"
  }},
  {{
    "asset_hostname": "exact_hostname",
    "asset_ip": "exact_ip",
    "cpe_string": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*", 
    "cpe_type": "software",
    "software_name": "exact_software_name",
    "software_version": "exact_version"
  }}
])
```

Generate CPE mappings now."""