# Agentic Stage Framework

This package provides reusable components for building agentic stages that use LLM loops with tools, error recovery, and iteration management.

## Components

### AgenticStageBase
Abstract base class that provides the main framework for agentic stages. Inherit from this class to create new agentic stages.

**Key Features:**
- Tool initialization and management
- Agentic loop execution
- Error recovery and retry logic
- Iteration limit handling
- Forced termination when max iterations reached

### AgenticToolManager
Manages tool initialization, execution, and result handling.

**Key Features:**
- Supports both LangChain tools and MCP tools
- Automatic argument injection
- Validation error handling
- Tool execution error recovery

### AgenticLoopController
Controls the core agentic loop execution with error recovery and iteration management.

**Key Features:**
- Iteration counting and max iteration enforcement
- No-tool-call error recovery
- Validation error retry logic
- Termination condition checking

### ErrorRecoveryMixin
Provides common error recovery patterns that can be reused across different components.

**Key Features:**
- Standardized error message formatting
- Retry message generation
- Validation error handling
- Tool execution error handling

## Usage

To create a new agentic stage:

1. Inherit from `AgenticStageBase`
2. Implement the required abstract methods:
   - `_prepare_initial_messages()`: Create initial conversation messages
   - `_should_terminate()`: Define termination conditions
   - `_handle_forced_termination()`: Handle max iteration scenarios
   - `_inject_stage_specific_args()`: Inject stage-specific data into tool calls
   - `get_required_tools()`: Specify required tools
3. Optionally override `get_termination_tool_names()` if you have specific termination tools
4. Call `execute_agentic_workflow()` to run the stage

## Example

```python
from src.stages.agents import AgenticStageBase

class MyResearchStage(AgenticStageBase):
    def get_required_tools(self) -> List[str]:
        return []  # No required tools
    
    async def _prepare_initial_messages(self, **kwargs) -> List[BaseMessage]:
        # Create initial system and user messages
        pass
    
    async def _should_terminate(self, response: AIMessage, termination_result, **kwargs) -> Tuple[bool, Any]:
        # Check if research is complete
        pass
    
    async def _handle_forced_termination(self, **kwargs) -> Any:
        # Return gathered research data
        pass
    
    def _inject_stage_specific_args(self, tool_args: dict, **kwargs) -> dict:
        # Inject research context
        pass
```

## Architecture Benefits

- **Reusability**: Core logic shared across all agentic stages
- **Consistency**: Standardized error handling and recovery patterns
- **Maintainability**: Bug fixes and improvements benefit all stages
- **Testability**: Components can be unit tested independently
- **Extensibility**: Easy to add new stages or modify behavior