import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List


from src.core.config_loader import ConfigLoader
from src.parsers.base import ParseResult
from src.parsers import IncidentParserManager
from src.tools.nvd_tool import NVDTool

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def _parse_incidents_from_file(
    file_path: str | None = None, parser_name: str = "json_v1"
) -> tuple[dict, List[ParseResult]]:
    """Parsing multiple incidents from a file with detailed statistics"""
    logger.info("Incident parsing from file...")

    try:
        # Default file path if not provided
        if file_path is None:
            file_path = "data/incident_data.json" 

        # Check if file exists
        from pathlib import Path

        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            logger.error(f"Incidents file not found: {file_path}")
            logger.info(
                "Please provide a valid file path or place incidents.json in the project root"
            )
            return {}, []

        logger.info(f"Loading incidents from: {file_path}")
        
        parser_manager = IncidentParserManager(parser_name)

        # Load file content
        import json
        import time

        start_time = time.time()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read()

            # Try to parse as JSON
            try:
                incidents_data = json.loads(file_content)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in file: {e}")
                return {}, []

        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return {}, []

        load_time = time.time() - start_time
        logger.info(
            f"File loaded in {load_time:.3f} seconds"
        )  # Determine if it's a single incident or batch
        if isinstance(incidents_data, dict):
            logger.info("File contains a single incident")
            incidents_list = [incidents_data]
        elif isinstance(incidents_data, list):
            logger.info(f"File contains {len(incidents_data)} incidents")
            incidents_list = incidents_data
        else:
            logger.error(f"Unexpected data format: {type(incidents_data)}")
            return {}, []

        # Parse incidents
        logger.info("Starting batch parsing...")
        parse_start_time = time.time()

        results = parser_manager.parse_batch_incidents(incidents_list)

        parse_time = time.time() - parse_start_time

        # Calculate statistics
        total_incidents = len(results)
        successful_parses = sum(1 for r in results if r.success)
        failed_parses = total_incidents - successful_parses

        # Issue statistics
        total_issues = sum(len(r.issues) for r in results)
        critical_issues = sum(
            1 for r in results for issue in r.issues if issue.severity == "critical"
        )
        error_issues = sum(
            1 for r in results for issue in r.issues if issue.severity == "error"
        )
        warning_issues = sum(
            1 for r in results for issue in r.issues if issue.severity == "warning"
        )
        info_issues = sum(
            1 for r in results for issue in r.issues if issue.severity == "info"
        )

        # Parse time statistics
        parse_times = [r.parse_time_ms for r in results if r.parse_time_ms is not None]
        avg_parse_time = sum(parse_times) / len(parse_times) if parse_times else 0
        min_parse_time = min(parse_times) if parse_times else 0
        max_parse_time = max(parse_times) if parse_times else 0

        # Data quality statistics (for successful parses only)
        successful_incidents = [r.incident for r in results if r.success and r.incident]

        if successful_incidents:
            total_assets = sum(inc.asset_count for inc in successful_incidents)
            total_ttps = sum(inc.ttp_count for inc in successful_incidents)
            total_iocs = sum(inc.ioc_count for inc in successful_incidents)
            avg_assets = total_assets / len(successful_incidents)
            avg_ttps = total_ttps / len(successful_incidents)
            avg_iocs = total_iocs / len(successful_incidents)
        else:
            total_assets = total_ttps = total_iocs = 0
            avg_assets = avg_ttps = avg_iocs = 0

        # Print comprehensive statistics
        logger.info("=" * 60)
        logger.info("INCIDENT PARSING STATISTICS")
        logger.info("=" * 60)

        # Overall results
        logger.info(f"📊 OVERALL RESULTS:")
        logger.info(f"   Total incidents processed: {total_incidents}")
        logger.info(
            f"   ✅ Successfully parsed: {successful_parses} ({successful_parses/total_incidents*100:.1f}%)"
        )
        logger.info(
            f"   ❌ Failed to parse: {failed_parses} ({failed_parses/total_incidents*100:.1f}%)"
        )
        logger.info(f"   📁 File size: {file_path_obj.stat().st_size:,} bytes")
        logger.info(f"   ⏱️  Total processing time: {parse_time:.3f} seconds")

        # Performance metrics
        logger.info(f"\n⚡ PERFORMANCE METRICS:")
        logger.info(f"   Average parse time: {avg_parse_time:.1f}ms per incident")
        logger.info(f"   Fastest parse: {min_parse_time:.1f}ms")
        logger.info(f"   Slowest parse: {max_parse_time:.1f}ms")
        logger.info(f"   Throughput: {total_incidents/parse_time:.1f} incidents/second")

        # Issue analysis
        logger.info(f"\n🔍 ISSUE ANALYSIS:")
        logger.info(f"   Total issues found: {total_issues}")
        logger.info(f"   🔴 Critical issues: {critical_issues}")
        logger.info(f"   🟠 Error issues: {error_issues}")
        logger.info(f"   🟡 Warning issues: {warning_issues}")
        logger.info(f"   🔵 Info issues: {info_issues}")

        if total_incidents > 0:
            logger.info(
                f"   Average issues per incident: {total_issues/total_incidents:.1f}"
            )

        # Data quality metrics
        logger.info(f"\n📈 DATA QUALITY METRICS:")
        logger.info(f"   Total assets extracted: {total_assets}")
        logger.info(f"   Total TTPs identified: {total_ttps}")
        logger.info(f"   Total IOCs found: {total_iocs}")

        if successful_incidents:
            logger.info(f"   Average assets per incident: {avg_assets:.1f}")
            logger.info(f"   Average TTPs per incident: {avg_ttps:.1f}")
            logger.info(f"   Average IOCs per incident: {avg_iocs:.1f}")

        # Sample of failed incidents (if any)
        failed_results = [r for r in results if not r.success]
        if failed_results:
            logger.info(f"\n❌ FAILED INCIDENTS SAMPLE (showing first 5):")
            for i, failed_result in enumerate(failed_results[:5]):
                incident_id = "Unknown"
                if failed_result.raw_data and isinstance(failed_result.raw_data, dict):
                    incident_id = failed_result.raw_data.get("incident_id", "Unknown")

                logger.info(f"   {i+1}. Incident ID: {incident_id}")
                if failed_result.issues:
                    critical_errors = [
                        issue
                        for issue in failed_result.issues
                        if issue.severity in ["critical", "error"]
                    ]
                    if critical_errors:
                        logger.info(f"      Error: {critical_errors[0].message}")

        # Sample of successful incidents
        if successful_incidents:
            logger.info(f"\n✅ SUCCESSFUL INCIDENTS SAMPLE (showing first 3):")
            for i, incident in enumerate(successful_incidents[:3]):
                logger.info(
                    f"   {i+1}. {incident.incident_id}: {incident.title[:50]}..."
                )
                logger.info(
                    f"      Assets: {incident.asset_count}, TTPs: {incident.ttp_count}, IOCs: {incident.ioc_count}"
                )

        # Recommendations
        logger.info(f"\n💡 RECOMMENDATIONS:")
        if failed_parses > 0:
            logger.info(
                f"   • Review {failed_parses} failed incidents for data quality issues"
            )

        if warning_issues > total_incidents:
            logger.info(f"   • High warning count suggests data standardization needed")

        if avg_parse_time > 100:
            logger.info(f"   • Parse times are high, consider data preprocessing")

        success_rate = successful_parses / total_incidents * 100
        if success_rate < 95:
            logger.info(
                f"   • Success rate ({success_rate:.1f}%) below 95%, review data format"
            )
        else:
            logger.info(f"   • Excellent success rate ({success_rate:.1f}%)!")

        logger.info("=" * 60)

        # Return summary for programmatic use
        return {
            "total_incidents": total_incidents,
            "successful_parses": successful_parses,
            "failed_parses": failed_parses,
            "success_rate": success_rate,
            "total_issues": total_issues,
            "parse_time_seconds": parse_time,
            "avg_parse_time_ms": avg_parse_time,
            "total_assets": total_assets,
            "total_ttps": total_ttps,
            "total_iocs": total_iocs,
        }, results

    except Exception as e:
        logger.error(f"File parsing failed: {e}", exc_info=True)
        raise


async def main():
    """Main entry point for the application."""
    try:
        

        # Parse command line arguments
        parser = argparse.ArgumentParser(
            description="Parse security incidents from a file"
        )
        parser.add_argument(
            "--file",
            "-f",
            type=str,
            default="incidents.json",
            help="Path to the incidents file (default: incidents.json)",
        )
        parser.add_argument(
            "--config",
            "-c",
            type=str,
            default="config/default_config.yaml",
            help="Path to the configuration file (default: config/default_config.yaml)",
        )
        args = parser.parse_args()

        # Initialize configuration loader
        config_loader = ConfigLoader()
        config = config_loader.load_from_file(args.config)
        if not config:
            logger.error(
                "Failed to load configuration. Please check the config file path and format."
            )
            sys.exit(1)

        # TODO: Configure these
        # # Configure cache
        # configure_cache()

        # # Initialize token manager
        # token_manager = TokenManager()

        # Create the NVD tool instance
        nvd = NVDTool()

        # Parse incidents from file
        statistics, parsed_incidents = await _parse_incidents_from_file(args.file, config.incident_parser)

        # Evaluate each of the parsed incidents
        for parsed in parsed_incidents:
            if not parsed.success:
                logger.warning(f"Skipping incident due to parsing errors: {'\n'.join([i.message for i in parsed.issues])}")
                continue
            
            incident_vulnerability_report = nvd.analyze_incident_vulnerabilities(parsed.incident)
            
            logger.info(json.dumps(nvd.export_report_to_dict(incident_vulnerability_report), indent=2))
            
            

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())
