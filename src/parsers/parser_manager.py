"""
Incident Parser Manager

Manages parser selection and orchestrates parsing operations.
"""

import logging
from typing import Any, List, Optional, Dict
from .base import IncidentParser, ParseResult, parser_registry, ParseSeverity
from .json_parser import JSONIncidentParser

logger = logging.getLogger(__name__)


class IncidentParserManager:
    """Manages incident parsing operations"""

    def __init__(self, parser_name: str = "json_v1"):
        self.logger = logging.getLogger(__name__)

        # Register available parsers
        self._register_parsers()

        # Get configured parser
        self.default_parser_name = parser_name
        self.default_parser = self._get_configured_parser()

    def _register_parsers(self) -> None:
        """Register all available parsers"""
        # Register JSON parser
        parser_registry.register("json_v1", JSONIncidentParser)

        # Future parsers can be registered here:
        # parser_registry.register("csv_v1", CSVIncidentParser)
        # parser_registry.register("xml_v1", XMLIncidentParser)
        # parser_registry.register("syslog", SyslogIncidentParser)

        self.logger.info(f"Registered parsers: {parser_registry.list_parsers()}")

    def _get_configured_parser(self) -> Optional[IncidentParser]:
        """Get the parser specified in configuration"""
        parser = parser_registry.get_parser(self.default_parser_name)
        if not parser:
            self.logger.error(
                f"Configured parser '{self.default_parser_name}' not found"
            )
            # Fallback to JSON parser
            parser = parser_registry.get_parser("json_v1")
            if parser:
                self.logger.warning("Falling back to json_v1 parser")

        return parser

    def parse_single_incident(
        self, data: Any, parser_name: Optional[str] = None
    ) -> ParseResult:
        """
        Parse a single incident using specified or configured parser.

        Args:
            data: Raw incident data
            parser_name: Optional parser name to use (overrides config)

        Returns:
            ParseResult with parsed incident or errors
        """
        # Determine which parser to use
        if parser_name:
            parser = parser_registry.get_parser(parser_name)
            if not parser:
                # Create error result
                result = ParseResult(
                    success=False,
                    parser_used=parser_name,
                    raw_data=data if isinstance(data, dict) else {"raw": str(data)},
                )
                result.add_issue(
                    ParseSeverity.CRITICAL,
                    f"Parser '{parser_name}' not found",
                    suggested_fix=f"Use one of: {parser_registry.list_parsers()}",
                )
                return result
        else:
            parser = self.default_parser
            if not parser:
                # Create error result
                result = ParseResult(
                    success=False,
                    parser_used=self.default_parser_name,
                    raw_data=data if isinstance(data, dict) else {"raw": str(data)},
                )
                result.add_issue(
                    ParseSeverity.CRITICAL,
                    f"No parser available (configured: '{self.default_parser_name}')",
                    suggested_fix="Check parser configuration and registration",
                )
                return result

        # Validate parser can handle the data
        if not parser.can_parse(data):
            result = ParseResult(
                success=False,
                parser_used=parser.parser_name,
                raw_data=data if isinstance(data, dict) else {"raw": str(data)},
            )
            result.add_issue(
                ParseSeverity.ERROR,
                f"Parser '{parser.parser_name}' cannot handle this data format",
                suggested_fix="Check data format or try a different parser",
            )
            return result

        # Parse the data
        try:
            result = parser.parse_single(data)
            self.logger.debug(
                f"Parsed incident with {len(result.issues)} issues "
                f"(success: {result.success})"
            )
            return result

        except Exception as e:
            # Create error result for unexpected failures
            result = ParseResult(
                success=False,
                parser_used=parser.parser_name,
                raw_data=data if isinstance(data, dict) else {"raw": str(data)},
            )
            result.add_issue(
                ParseSeverity.CRITICAL,
                f"Unexpected error in parser '{parser.parser_name}': {e}",
                suggested_fix="Check data format and contact support",
            )
            return result

    def parse_batch_incidents(
        self, data: Any, parser_name: Optional[str] = None
    ) -> List[ParseResult]:
        """
        Parse multiple incidents from batch data.

        Args:
            data: Raw batch data (list or single item)
            parser_name: Optional parser name to use

        Returns:
            List of ParseResult objects
        """
        # Determine which parser to use
        if parser_name:
            parser = parser_registry.get_parser(parser_name)
            if not parser:
                # Create error result
                error_result = ParseResult(
                    success=False,
                    parser_used=parser_name,
                    raw_data=data if isinstance(data, dict) else {"raw": str(data)},
                )
                error_result.add_issue(
                    ParseSeverity.CRITICAL,
                    f"Parser '{parser_name}' not found",
                    suggested_fix=f"Use one of: {parser_registry.list_parsers()}",
                )
                return [error_result]
        else:
            parser = self.default_parser
            if not parser:
                # Create error result
                error_result = ParseResult(
                    success=False,
                    parser_used=self.default_parser_name,
                    raw_data=data if isinstance(data, dict) else {"raw": str(data)},
                )
                error_result.add_issue(
                    ParseSeverity.CRITICAL,
                    f"No parser available (configured: '{self.default_parser_name}')",
                    suggested_fix="Check parser configuration and registration",
                )
                return [error_result]

        # Parse batch data
        try:
            results = parser.parse_batch(data)

            # Log summary
            successful = sum(1 for r in results if r.success)
            total = len(results)
            self.logger.info(
                f"Batch parsing completed: {successful}/{total} successful "
                f"using parser '{parser.parser_name}'"
            )

            return results

        except Exception as e:
            # Create error result for unexpected failures
            error_result = ParseResult(
                success=False,
                parser_used=parser.parser_name,
                raw_data=data if isinstance(data, dict) else {"raw": str(data)},
            )
            error_result.add_issue(
                ParseSeverity.CRITICAL,
                f"Unexpected error in batch parsing with '{parser.parser_name}': {e}",
                suggested_fix="Check data format and contact support",
            )
            return [error_result]

    def auto_detect_and_parse(self, data: Any) -> ParseResult:
        """
        Auto-detect the appropriate parser and parse the data.

        Args:
            data: Raw incident data

        Returns:
            ParseResult with parsed incident or errors
        """
        # Try to find a compatible parser
        parser = parser_registry.find_compatible_parser(data)

        if not parser:
            # No compatible parser found
            result = ParseResult(
                success=False,
                parser_used="auto_detect",
                raw_data=data if isinstance(data, dict) else {"raw": str(data)},
            )
            result.add_issue(
                ParseSeverity.ERROR,
                "No compatible parser found for this data format",
                suggested_fix=f"Available parsers: {parser_registry.list_parsers()}",
            )
            return result

        # Parse with detected parser
        self.logger.info(f"Auto-detected parser: {parser.parser_name}")
        return parser.parse_single(data)

    def get_parser_info(self) -> Dict[str, Any]:
        """Get information about available parsers"""
        return {
            "available_parsers": parser_registry.list_parsers(),
            "configured_parser": self.default_parser_name,
            "default_parser_available": self.default_parser is not None,
        }

    def validate_parser_config(self) -> List[str]:
        """
        Validate parser configuration.

        Returns:
            List of validation issues (empty if valid)
        """
        issues = []

        # Check if configured parser exists
        if not parser_registry.get_parser(self.default_parser_name):
            issues.append(f"Configured parser '{self.default_parser_name}' not found")

        # Check if any parsers are registered
        if not parser_registry.list_parsers():
            issues.append("No parsers are registered")

        return issues
