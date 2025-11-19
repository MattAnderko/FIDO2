"""
Resource measurement utilities for tracking CPU time, memory usage, and database operations.
"""
import time
import os
import threading
from contextlib import contextmanager
from typing import Dict, Optional
import psutil


# Thread-local storage for database query tracking
_thread_local = threading.local()


def get_db_metrics() -> Dict[str, int]:
    """Get current thread's database query metrics."""
    if not hasattr(_thread_local, 'db_metrics'):
        _thread_local.db_metrics = {
            'query_count': 0,
            'query_time_ms': 0.0
        }
    return _thread_local.db_metrics


def reset_db_metrics():
    """Reset database query metrics for current thread."""
    _thread_local.db_metrics = {
        'query_count': 0,
        'query_time_ms': 0.0
    }


def increment_db_query(time_ms: float):
    """Increment database query count and add to total time."""
    metrics = get_db_metrics()
    metrics['query_count'] += 1
    metrics['query_time_ms'] += time_ms


class ResourceContext:
    """Context manager for measuring resource usage (CPU, memory, DB queries)."""
    
    def __init__(self, name: str, measurements: Optional[Dict[str, list]] = None):
        self.name = name
        if measurements is None:
            self.measurements = {}
        else:
            self.measurements = measurements
        self.start_cpu_time = None
        self.end_cpu_time = None
        self.start_memory_mb = None
        self.end_memory_mb = None
        self.start_db_metrics = None
        self.end_db_metrics = None
        self.process = None
        
    def __enter__(self):
        # CPU time (process time, not wall-clock)
        self.start_cpu_time = time.process_time()
        
        # Memory usage
        self.process = psutil.Process(os.getpid())
        self.start_memory_mb = self.process.memory_info().rss / 1024 / 1024  # Convert to MB
        
        # Database metrics
        self.start_db_metrics = get_db_metrics().copy()
        reset_db_metrics()  # Reset for this measurement
        
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # CPU time
        self.end_cpu_time = time.process_time()
        cpu_time_ms = (self.end_cpu_time - self.start_cpu_time) * 1000
        
        # Memory delta
        self.end_memory_mb = self.process.memory_info().rss / 1024 / 1024
        memory_delta_mb = self.end_memory_mb - self.start_memory_mb
        
        # Database metrics
        self.end_db_metrics = get_db_metrics().copy()
        db_query_count = self.end_db_metrics['query_count']
        db_time_ms = self.end_db_metrics['query_time_ms']
        
        # Store measurements
        cpu_key = f"{self.name}_cpu_ms"
        memory_key = f"{self.name}_memory_mb"
        db_queries_key = f"{self.name}_db_queries"
        db_time_key = f"{self.name}_db_time_ms"
        
        for key, value in [
            (cpu_key, cpu_time_ms),
            (memory_key, memory_delta_mb),
            (db_queries_key, db_query_count),
            (db_time_key, db_time_ms)
        ]:
            if key not in self.measurements:
                self.measurements[key] = []
            self.measurements[key].append(value)
        
        return False
    
    @property
    def cpu_time_ms(self) -> float:
        """Get CPU time in milliseconds."""
        if self.start_cpu_time is None or self.end_cpu_time is None:
            return 0.0
        return (self.end_cpu_time - self.start_cpu_time) * 1000
    
    @property
    def memory_delta_mb(self) -> float:
        """Get memory delta in MB."""
        if self.start_memory_mb is None or self.end_memory_mb is None:
            return 0.0
        return self.end_memory_mb - self.start_memory_mb
    
    @property
    def db_query_count(self) -> int:
        """Get database query count."""
        if self.end_db_metrics is None:
            return 0
        return self.end_db_metrics['query_count']
    
    @property
    def db_time_ms(self) -> float:
        """Get total database query time in milliseconds."""
        if self.end_db_metrics is None:
            return 0.0
        return self.end_db_metrics['query_time_ms']


@contextmanager
def measure_resources(name: str, measurements: Optional[Dict[str, list]] = None):
    """
    Context manager for measuring resource usage.
    
    Args:
        name: Name identifier for this measurement
        measurements: Optional dict to store measurements
    
    Example:
        with measure_resources("database_query", measurements):
            result = db.query(User).all()
    """
    ctx = ResourceContext(name, measurements)
    with ctx:
        yield ctx



