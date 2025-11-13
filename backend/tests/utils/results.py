"""
Result collection and statistics calculation for latency measurements.
"""
import json
import csv
from typing import Dict, List, Optional
from pathlib import Path
from collections import defaultdict


class ResultsCollector:
    """Collects and aggregates latency measurements."""
    
    def __init__(self):
        self.measurements: Dict[str, List[float]] = defaultdict(list)
    
    def add_measurement(self, name: str, value_ms: float):
        """Add a single measurement."""
        self.measurements[name].append(value_ms)
    
    def add_measurements(self, name: str, values_ms: List[float]):
        """Add multiple measurements."""
        self.measurements[name].extend(values_ms)
    
    def get_statistics(self, name: str) -> Dict[str, float]:
        """Calculate statistics for a measurement name."""
        values = self.measurements.get(name, [])
        if not values:
            return {}
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        
        return {
            "count": n,
            "mean": sum(values) / n,
            "median": sorted_values[n // 2] if n > 0 else 0,
            "min": min(values),
            "max": max(values),
            "p50": sorted_values[int(n * 0.50)] if n > 0 else 0,
            "p75": sorted_values[int(n * 0.75)] if n > 0 else 0,
            "p95": sorted_values[int(n * 0.95)] if n > 0 else 0,
            "p99": sorted_values[int(n * 0.99)] if n > 0 else 0,
        }
    
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


# Global results collector instance
_global_collector = ResultsCollector()


def get_collector() -> ResultsCollector:
    """Get the global results collector."""
    return _global_collector


def reset_collector():
    """Reset the global results collector."""
    _global_collector.clear()


