"""
Pytest plugin for automatic results export.
"""
import pytest
from tests.utils.results import get_collector


def pytest_addoption(parser):
    """Add command-line options for results export."""
    parser.addoption(
        "--latency-results",
        action="store",
        default=None,
        help="Path to export latency results JSON file"
    )
    parser.addoption(
        "--latency-results-csv",
        action="store",
        default=None,
        help="Path to export latency results CSV file"
    )


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """Export results after all tests complete."""
    results_json = session.config.getoption("--latency-results")
    results_csv = session.config.getoption("--latency-results-csv")
    
    collector = get_collector()
    
    if results_json:
        collector.export_json(results_json)
        print(f"\n✓ Latency results exported to {results_json}")
    
    if results_csv:
        collector.export_csv(results_csv)
        print(f"✓ Latency results exported to {results_csv}")
    
    # Also print summary if results exist
    stats = collector.get_all_statistics()
    if stats:
        print("\n=== Latency Measurement Summary ===")
        for name, stat in sorted(stats.items()):
            if stat:
                print(f"\n{name}:")
                print(f"  Mean: {stat.get('mean', 0):.2f} ms")
                print(f"  Median: {stat.get('median', 0):.2f} ms")
                print(f"  P95: {stat.get('p95', 0):.2f} ms")
                print(f"  P99: {stat.get('p99', 0):.2f} ms")
                print(f"  Min: {stat.get('min', 0):.2f} ms")
                print(f"  Max: {stat.get('max', 0):.2f} ms")
                print(f"  Count: {stat.get('count', 0)}")

