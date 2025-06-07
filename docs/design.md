# RAD Security Analysis

### Pre-requisites
- Python 3.10
- Running Vulnerability Intelligence Server
  - Default is configured on `localhost:8000`, but you can re-configure it in the `config/default_config.yaml`

### AI Workflow for Analyzing Security Incidents

1. Normalize / parse JSON incident data
2. Pre-process incident data
   1. Search for CVEs
   2. Search for vulnerable software versions
   3. Assess any geographical importance (i.e. IP addresses associated with incident data)
3. Provide incident data & CVE results to LLM for analysis, LLM enters agentic loop where it performs the following steps (one or more times)
   1. Reason about affected assets, observed TTPs, and initial findings (initial CVEs / pre-processing results)
   2. Identifies relevant CVEs, discard irrelevant ones
   3. Uses tools to search for additional CVEs
   4. Explores in-depth more information about the found vulnerabilities using available tools
   5. Uses configured max_iterations to determine how many times it can perform additional tool loops
4. Finally, after the iterations are exhausted or the AI is satisfied it has enough information, it will generate a final incident analysis, with a prioritized list of CVEs, assessing the risk and impact of relevant CVEs in the context of the specific incident, analysis of possible impact, exploitation likelihood
   1. Final analysis report should contain a link back to the incident (which includes all incident data)
   2. Provide recommendations for patching / fixing
   3. Provide links to NVD or other databases describing CVEs / vulnerabilities

### Tech Stack

- Python
- Docker
- OpenAI, Anthropic
- MCP Client/Server
- NVD API 2.0
- 
### Details

**Application**:
- Entrypoint: `src/main.py`
- Configuration: `config/default_config.yaml`
- Incident Data: `data/incident_data.json`

**Prompts**:
- Prompts for the application are stored in the `src/prompts` folder, each prompt stored as its own individual `.py` file

### Tools
Tools are located in the `src/tools` folder.  LangChain tools / tool wrappers are in the `src/tools/lc_tools` folder, and are registered in the `src/tools/lc_tools/tool_manager.py` file.


**MCP Integration**:
MCP (Model Context Protocol) allows the dynamic discovery and use of tools, providing the capability of adding / modifying available tools without changing the underlying code.

- The MCP Client Manager (`src/tools/mcp_client_manager.py`) manages connections to MCP Servers, such as the vulnerability intelligence server
  - The MCP Client (`src/tools/mcp_client.py`) and MCP Client Manager expose methods to retrieve langchain tools from the MCP tools discovered from the MCP server(s)

**Vulnerability Intelligence MCP Server**:
- The Vulnerability Intelligence MCP Server is used for follow-up investigation of incident data by the AI
  - The MCP Server docker container should be running prior to running the RAD Security Pipeline
  - The tools provided by the MCP server will be converted to langchain tools for use internally
  - The AI will decide which tools to use in follow-up calls in the `initial_analysis` stage to investigate the incident


#### Available Tools

**Incident Pre-Processing Tools**:
These tools are used to pre-process the incident data in order to try to load some relevant data for the AI prior to executing any queries. This helps to reduce the back and forth with the LLM and reduce the amount of tokens spent. This includes looking up any relevant CVEs or vulnerabilities early in the pipeline.

- **NVD Vulnerability Scanner**: Automatically analyzes software in incident assets using NVD API 2.0
  - Uses incident timestamp for temporal CVE prioritization (pre-incident vs post-incident)
  - Multi-strategy search: exact matching, vendor-product combos, version-specific, broad fallback
  - Relevance scoring based on description matching, CPE validation, temporal context, CVSS severity
  - Configurable filtering: max age, recency priority, strict/fuzzy version matching, relevance thresholds
  - Outputs: `IncidentVulnerabilityReport` with prioritized CVEs and actionable recommendations

- **Geographic Intelligence**: Enriches IP addresses with location data and threat reputation
- **Software Asset Inventory**: Deduplicates and normalizes software across incident assets  
- **Threat Intelligence Correlation**: Pre-matches incident indicators against known threat feeds

**Configuration**: `max_cves_per_software`, `max_age_days`, `prioritize_recent_days`, `strict_version_matching`, `min_relevance_score`, `nvd_api_key`

**NVD Tools**:
- **search_cves_by_keyword**: Search for CVEs by keyword (software name, vendor, etc.)
  - Parameters: `keyword` (string), `results_per_page` (int, max 2000, default 20)
  - Returns: JSON string with CVE search results including CVE ID, description, CVSS scores, published date, references (limited to 5), and CPE matches (limited to 5)
  
- **get_cve_details**: Get detailed information for a specific CVE ID
  - Parameters: `cve_id` (string, e.g., CVE-2021-44228)
  - Returns: JSON string with comprehensive CVE details including both CVSS v2 and v3 scores, publication/modification dates, CPE matches, references, and weakness information
  
- **get_recent_cves**: Get recently published CVEs from the past few days
  - Parameters: `days` (int, default 7), `results_per_page` (int, default 50)
  - Returns: JSON string with recent CVEs sorted by CVSS score (highest first), including severity information and publication dates

**Analysis Submission Tool**:

The analysis submission tool contains specific features that are geared towards verifying and validating that the information the LLM provides is properly formatted, contains correct data, and correctly links to the appropriate resources when applicable.  This can be done through a number of different methods depending on the needs of the tool and can include things such as string matching, vector similarity, LLM as judge, etc.  The tool used here is an example that uses simple string matching.

- **submit_analysis**: Submit and validate comprehensive incident analysis results
  - Parameters: Comprehensive analysis including incident metadata, CVE analysis, asset risk assessments, TTP analysis, attack progression, recommendations, and reasoning chains
  - Validation Features:
    - **Data Consistency**: Validates hostnames, IP addresses, and references against original incident data using exact string matching
    - **Completeness Checks**: Ensures all incident assets and TTPs have corresponding analysis components
    - **Quality Assurance**: Generates validation warnings (low/medium/high severity) and completeness issues
    - **Cross-Reference Validation**: Verifies relationships between CVEs, assets, and attack chains
  - Returns: `AnalysisVerificationResult` containing the validated analysis with validation warnings, completeness issues, validation status, and summary
  - Purpose: Final validation gate to prevent AI hallucinations and ensure analysis accuracy before report generation