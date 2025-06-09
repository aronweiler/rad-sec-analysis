"""
Example LangChain Tool

Example tool that demonstrates how to use the `InjectedToolArg` to pass a list of `IncidentData` objects to the tool.
"""

from typing import List, Annotated
from langchain_core.tools import tool, InjectedToolArg
from ...models.incident import IncidentData


# The langchain signature to use should look something like this when you want to make use of IncidentData:
@tool
def tool_function_name(
    argument: dict[int, str],
    # This list of incident data is passed to all of the tools.
    incident_data: Annotated[List[IncidentData], InjectedToolArg],
    # The tool should return a list of IncidentData objects with any modifications desired.
) -> List[IncidentData]:
    """
    Create docstrings with instructions for the tool, and specifications for the arguments (except for any InjectedToolArg).
    """
