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
3. Provide incident data & CVE results to LLM for analysis
   1. Reason / provide analysis of affected assets, observed TTPs, and initial findings (initial CVEs / pre-processing results)
      1. Identify relevant CVEs, discard irrelevant ones
      2. Provide the LLM with the queries used to generate the list of CVEs that it is looking at
      3. Option to allow the LLM to call CVE tool / vulnerability tooling before moving on to the next step
         1. Uses configured max_iterations to determine how many times it can perform additional tool loops
   2. Generate prioritized list of CVEs, assessing the risk and impact of relevant CVEs in the context of the specific incident
      1. Provide analysis of possible impact, exploitation likelihood
   3. Generate final incident analysis, including why certain CVEs are prioritized
      1. Final analysis report should contain a link back to the incident (which includes all incident data)
      2. Provide recommendations for patching / fixing
      3. Provide links to NVD or other databases describing CVEs / vulnerabilities

### Tech Stack

- Python
- LangGraph
- Docker
- OpenAI, Anthropic
- MCP Client/Server
- NVD API 2.0
### Details

**Application**:
- Entrypoint: `src/main.py`
- Configuration: `config/default_config.yaml`
- Incident Data: `data/incident_data.json`

**Prompts**:
- Prompts for the application are stored in the `src/prompts` folder, each prompt stored as its own individual `.py` file

### Tools
Tools are located in the `src/tools` folder.

**NVD Tool**:
- The NVD tool (`src/tools/nvd_tool.py`) is a direct-access tool using the NVD 2.0 API, requiring an API key for less rate limiting
  - The NVD tool is used to pre-process incident data and provide initial CVE and vulnerability data to the initial LLM evaluation

**MCP Integration**:
MCP (Model Context Protocol) allows the dynamic discovery and use of tools, providing the capability of adding / modifying available tools without changing the underlying code.

- The MCP Client Manager (`src/tools/mcp_client_manager.py`) manages connections to MCP Servers, such as the vulnerability intelligence server
  - The MCP Client (`src/tools/mcp_client.py`) and MCP Client Manager expose methods to retrieve langchain tools from the MCP tools discovered from the MCP server(s)

**Vulnerability Intelligence**:
- The Vulnerability Intelligence MCP Server is used for follow-up investigation of incident data by the AI
  - The MCP Server docker container should be running prior to running the RAD Security Pipeline
  - The tools provided by the MCP server will be converted to langchain tools for use by LangGraph
  - The AI will decide which tools to use in follow-up calls in the `initial_incident_and_cve_analysis` stage to investigate the incident

#### Stage Tools

Stage tools are used to constrain the output of the AI to specific formats and content, ensuring clear reasoning, traceability, and accuracy.

**Stage Tool Design**
Stage tools contain specific design features that are geared towards verifying and validating that the information the LLM provides is properly formatted, contains correct data, and correctly links to the appropriate resources when applicable.  This can be done through a number of different methods depending on the needs of the tool and can include things such as string matching, vector similarity, LLM as judge, etc.


**Initial incident and CVE analysis output tools**:
- These tools will constrain the output of the initial incident and CVE analysis stage to one of two types of responses-
  - A: Tool calls to the Vulnerability Intelligence MCP server to perform additional incident investigations
  - B: Final answer tool with output fields containing analysis of affected assets, observed TTPs, and initial findings, and list of relevant CVEs

**Prioritized risk and impact assessment tools**:
- Tool constrains the output of the LLM to a prioritized list of CVEs, along with their risk, impact assessment, and exploitation likelihood in the context of the current incident

**Final incident analysis tools**:
- Tool to constrain the output of the LLM with respect to the final incident analysis, so that it includes the following:
  - Reference to the incident
  - Final analysis of the incident
  - Recommendations for fixing / patching
  - Relevant links to external sources