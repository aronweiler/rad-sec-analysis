"""
Base classes for incident parsers

Provides the foundation for pluggable incident parsing with different data formats.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union, Type
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from enum import Enum

from ..models.incident import IncidentData, IncidentBatch

logger = logging.getLogger(__name__)


class ParseSeverity(str, Enum):
    """Severity levels for parse issues"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ParseIssue(BaseModel):
    """Represents an issue encountered during parsing"""
    severity: ParseSeverity = Field(..., description="Issue severity")
    field: Optional[str] = Field(None, description="Field where issue occurred")
    message: str = Field(..., description="Issue description")
    raw_value: Optional[Any] = Field(None, description="Raw value that caused the issue")
    suggested_fix: Optional[str] = Field(None, description="Suggested fix for the issue")
    
    class Config:
        schema_extra = {
            "example": {
                "severity": "warning",
                "field": "timestamp",
                "message": "Invalid timestamp format, using current time",
                "raw_value": "2023-13-45T99:99:99Z",
                "suggested_fix": "Use ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ"
            }
        }


class ParseResult(BaseModel):
    """Result of parsing operation"""
    success: bool = Field(..., description="Whether parsing was successful")
    incident: Optional[IncidentData] = Field(None, description="Parsed incident data")
    issues: List[ParseIssue] = Field(default_factory=list, description="Issues encountered during parsing")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Original raw data")
    parser_used: str = Field(..., description="Parser that was used")
    parse_time_ms: Optional[int] = Field(None, description="Time taken to parse in milliseconds")
    
    @property
    def has_critical_issues(self) -> bool:
        """Check if there are any critical issues"""
        return any(issue.severity == ParseSeverity.CRITICAL for issue in self.issues)
    
    @property
    def has_errors(self) -> bool:
        """Check if there are any errors"""
        return any(issue.severity in [ParseSeverity.ERROR, ParseSeverity.CRITICAL] for issue in self.issues)
    
    @property
    def warnings_count(self) -> int:
        """Count of warning-level issues"""
        return sum(1 for issue in self.issues if issue.severity == ParseSeverity.WARNING)
    
    @property
    def errors_count(self) -> int:
        """Count of error-level issues"""
        return sum(1 for issue in self.issues if issue.severity in [ParseSeverity.ERROR, ParseSeverity.CRITICAL])
    
    def add_issue(self, severity: ParseSeverity, message: str, field: str = None, 
                  raw_value: Any = None, suggested_fix: str = None) -> None:
        """Add a parse issue"""
        issue = ParseIssue(
            severity=severity,
            field=field,
            message=message,
            raw_value=raw_value,
            suggested_fix=suggested_fix
        )
        self.issues.append(issue)
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "incident": {},  # IncidentData object
                "issues": [],
                "parser_used": "json_v1",
                "parse_time_ms": 45
            }
        }


class ParseError(Exception):
    """Exception raised when parsing fails critically"""
    
    def __init__(self, message: str, field: str = None, raw_value: Any = None):
        self.message = message
        self.field = field
        self.raw_value = raw_value
        super().__init__(message)


class IncidentParser(ABC):
    """Abstract base class for incident parsers"""
    
    def __init__(self, parser_name: str):
        self.parser_name = parser_name
        self.logger = logging.getLogger(f"{__name__}.{parser_name}")
    
    @abstractmethod
    def can_parse(self, data: Any) -> bool:
        """
        Check if this parser can handle the given data format.
        
        Args:
            data: Raw input data to check
            
        Returns:
            True if this parser can handle the data format
        """
        pass
    
    @abstractmethod
    def parse_single(self, data: Any) -> ParseResult:
        """
        Parse a single incident from raw data.
        
        Args:
            data: Raw incident data
            
        Returns:
            ParseResult containing the parsed incident or errors
        """
        pass
    
    def parse_batch(self, data: Any) -> List[ParseResult]:
        """
        Parse multiple incidents from raw data.
        
        Default implementation assumes data is a list and parses each item.
        Override for custom batch parsing logic.
        
        Args:
            data: Raw batch data
            
        Returns:
            List of ParseResult objects
        """
        if not isinstance(data, list):
            # Try to parse as single incident
            return [self.parse_single(data)]
        
        results = []
        for i, item in enumerate(data):
            try:
                result = self.parse_single(item)
                results.append(result)
            except Exception as e:
                # Create a failed parse result
                failed_result = ParseResult(
                    success=False,
                    parser_used=self.parser_name,
                    raw_data=item if isinstance(item, dict) else {"raw": str(item)}
                )
                failed_result.add_issue(
                    ParseSeverity.CRITICAL,
                    f"Failed to parse item {i}: {str(e)}",
                    suggested_fix="Check data format and structure"
                )
                results.append(failed_result)
        
        return results
    
    def _safe_extract(self, data: Dict[str, Any], field: str, 
                     default: Any = None, required: bool = False) -> Any:
        """
        Safely extract a field from data with error handling.
        
        Args:
            data: Source data dictionary
            field: Field name to extract
            default: Default value if field is missing
            required: Whether field is required
            
        Returns:
            Field value or default
            
        Raises:
            ParseError: If required field is missing
        """
        if field not in data:
            if required:
                raise ParseError(f"Required field '{field}' is missing", field=field)
            return default
        
        value = data.get(field, default)
        if required and (value is None or value == ""):
            raise ParseError(f"Required field '{field}' is empty", field=field, raw_value=value)
        
        return value
    
    def _safe_parse_datetime(self, value: Any, field: str = None) -> datetime:
        """
        Safely parse datetime with fallback to current time.
        
        Args:
            value: Raw datetime value
            field: Field name for error reporting
            
        Returns:
            Parsed datetime or current time as fallback
        """
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, str):
            try:
                # Try ISO format first
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                try:
                    # Try common formats
                    for fmt in [
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d",
                        "%m/%d/%Y %H:%M:%S",
                        "%m/%d/%Y"
                    ]:
                        return datetime.strptime(value, fmt)
                except ValueError:
                    pass
        
        # Fallback to current time
        self.logger.warning(f"Could not parse datetime '{value}' for field '{field}', using current time")
        return datetime.now(timezone.utc)
    
    def _safe_parse_list(self, value: Any, field: str = None) -> List[Any]:
        """
        Safely parse list with fallback to empty list.
        
        Args:
            value: Raw list value
            field: Field name for error reporting
            
        Returns:
            Parsed list or empty list as fallback
        """
        if isinstance(value, list):
            return value
        
        if value is None:
            return []
        
        if isinstance(value, str):
            # Try to parse as comma-separated values
            try:
                return [item.strip() for item in value.split(',') if item.strip()]
            except Exception:
                return [value]  # Single item list
        
        # Convert single item to list
        return [value]
    
    def _validate_required_fields(self, data: Dict[str, Any], required_fields: List[str]) -> List[ParseIssue]:
        """
        Validate that required fields are present and not empty.
        
        Args:
            data: Data to validate
            required_fields: List of required field names
            
        Returns:
            List of validation issues
        """
        issues = []
        
        for field in required_fields:
            if field not in data:
                issues.append(ParseIssue(
                    severity=ParseSeverity.ERROR,
                    field=field,
                    message=f"Required field '{field}' is missing",
                    suggested_fix=f"Add '{field}' field to the data"
                ))
            elif data[field] is None or data[field] == "":
                issues.append(ParseIssue(
                    severity=ParseSeverity.ERROR,
                    field=field,
                    message=f"Required field '{field}' is empty",
                    raw_value=data[field],
                    suggested_fix=f"Provide a value for '{field}'"
                ))
        
        return issues


class ParserRegistry:
    """Registry for managing incident parsers"""
    
    def __init__(self):
        self._parsers: Dict[str, Type[IncidentParser]] = {}
        self._instances: Dict[str, IncidentParser] = {}
    
    def register(self, parser_name: str, parser_class: Type[IncidentParser]) -> None:
        """
        Register a parser class.
        
        Args:
            parser_name: Unique name for the parser
            parser_class: Parser class to register
        """
        if not issubclass(parser_class, IncidentParser):
            raise ValueError(f"Parser class must inherit from IncidentParser")
        
        self._parsers[parser_name] = parser_class
        logger.info(f"Registered parser: {parser_name}")
    
    def get_parser(self, parser_name: str) -> Optional[IncidentParser]:
        """
        Get a parser instance by name.
        
        Args:
            parser_name: Name of the parser to get
            
        Returns:
            Parser instance or None if not found
        """
        if parser_name not in self._parsers:
            return None
        
        # Create instance if not cached
        if parser_name not in self._instances:
            parser_class = self._parsers[parser_name]
            self._instances[parser_name] = parser_class(parser_name)
        
        return self._instances[parser_name]
    
    def list_parsers(self) -> List[str]:
        """Get list of registered parser names"""
        return list(self._parsers.keys())
    
    def find_compatible_parser(self, data: Any) -> Optional[IncidentParser]:
        """
        Find a parser that can handle the given data.
        
        Args:
            data: Raw data to parse
            
        Returns:
            Compatible parser instance or None
        """
        for parser_name in self._parsers:
            parser = self.get_parser(parser_name)
            if parser and parser.can_parse(data):
                return parser
        
        return None


# Global parser registry instance
parser_registry = ParserRegistry()