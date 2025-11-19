"""
Result collection and statistics calculation for latency measurements.
"""
import json
import csv
from typing import Dict, List, Optional, Any
from pathlib import Path
from collections import defaultdict


class ResultsCollector:
    """Collects and aggregates latency, resource, and security test measurements."""
    
    def __init__(self):
        # Store measurements as lists of numbers (float or int)
        self.measurements: Dict[str, List[float]] = defaultdict(list)
        # Store security test results (pass/fail, attack success rates)
        self.security_results: Dict[str, Dict[str, Any]] = {}
    
    def add_measurement(self, name: str, value: float):
        """Add a single measurement (latency, CPU time, memory, DB time, etc.)."""
        self.measurements[name].append(value)
    
    def add_measurements(self, name: str, values: List[float]):
        """Add multiple measurements."""
        self.measurements[name].extend(values)
    
    def get_statistics(self, name: str) -> Dict[str, float]:
        """Calculate statistics for a measurement name."""
        values = self.measurements.get(name, [])
        if not values:
            return {}
        
        # Convert to float for calculations (handles int values like query counts)
        float_values = [float(v) for v in values]
        sorted_values = sorted(float_values)
        n = len(sorted_values)
        
        stats = {
            "count": n,
            "mean": sum(float_values) / n,
            "median": sorted_values[n // 2] if n > 0 else 0,
            "min": min(float_values),
            "max": max(float_values),
        }
        
        # Add percentiles if we have enough data
        if n > 0:
            stats["p50"] = sorted_values[int(n * 0.50)] if n > 0 else 0
            stats["p75"] = sorted_values[int(n * 0.75)] if n > 0 else 0
            stats["p95"] = sorted_values[int(n * 0.95)] if n > 0 else 0
            stats["p99"] = sorted_values[int(n * 0.99)] if n > 0 else 0
        
        return stats
    
    def get_all_statistics(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all measurements."""
        return {
            name: self.get_statistics(name)
            for name in self.measurements.keys()
        }
    
    def export_json(self, filepath: str):
        """Export results to JSON file."""
        stats = self.get_all_statistics()
        with open(filepath, 'w') as f:
            json.dump(stats, f, indent=2)
    
    def export_csv(self, filepath: str):
        """Export results to CSV file."""
        stats = self.get_all_statistics()
        
        if not stats:
            return
        
        # Get all unique metric names
        all_metrics = set()
        for stat_dict in stats.values():
            all_metrics.update(stat_dict.keys())
        
        metric_names = sorted(all_metrics)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            # Header row
            writer.writerow(['measurement'] + metric_names)
            
            # Data rows
            for measurement_name, stat_dict in sorted(stats.items()):
                row = [measurement_name] + [stat_dict.get(metric, '') for metric in metric_names]
                writer.writerow(row)
    
    def clear(self):
        """Clear all measurements."""
        self.measurements.clear()
    
    def merge(self, other: 'ResultsCollector'):
        """Merge another ResultsCollector into this one."""
        for name, values in other.measurements.items():
            self.measurements[name].extend(values)
        self.security_results.update(other.security_results)
    
    def add_security_result(self, test_name: str, passed: bool, details: Optional[Dict[str, Any]] = None):
        """
        Record a security test result.
        
        Args:
            test_name: Name of the security test
            passed: Whether the test passed (True) or failed (False)
            details: Optional additional details about the test result
        """
        self.security_results[test_name] = {
            "passed": passed,
            "details": details or {}
        }
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get summary of security test results."""
        if not self.security_results:
            return {}
        
        total = len(self.security_results)
        passed = sum(1 for r in self.security_results.values() if r["passed"])
        failed = total - passed
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / total if total > 0 else 0,
            "tests": self.security_results
        }


# Global results collector instance
_global_collector = ResultsCollector()


def get_collector() -> ResultsCollector:
    """Get the global results collector."""
    return _global_collector


def reset_collector():
    """Reset the global results collector."""
    _global_collector.clear()


