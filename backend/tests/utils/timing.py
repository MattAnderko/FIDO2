"""
Timing utilities for precise latency measurement.
"""
import time
from contextlib import contextmanager
from functools import wraps
from typing import Dict, List, Optional
from tests.utils.resources import ResourceContext


class TimingContext:
    """Context manager for measuring execution time."""
    
    def __init__(self, name: str, measurements: Optional[Dict[str, List[float]]] = None):
        self.name = name
        # Use the provided dict if given, otherwise create a new one
        # Important: Don't use 'or {}' as it creates a new dict even when measurements={}
        if measurements is None:
            self.measurements = {}
        else:
            self.measurements = measurements
        self.start_time = None
        self.end_time = None
        
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        elapsed = (self.end_time - self.start_time) * 1000  # Convert to milliseconds
        
        if self.name not in self.measurements:
            self.measurements[self.name] = []
        self.measurements[self.name].append(elapsed)
        
        return False
    
    @property
    def elapsed_ms(self) -> float:
        """Get elapsed time in milliseconds."""
        if self.start_time is None or self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time) * 1000


@contextmanager
def measure_time(name: str, measurements: Optional[Dict[str, List[float]]] = None):
    """
    Context manager for measuring execution time.
    
    Args:
        name: Name identifier for this measurement
        measurements: Optional dict to store measurements (key -> list of times in ms)
    
    Example:
        with measure_time("database_query", measurements):
            result = db.query(User).all()
    """
    ctx = TimingContext(name, measurements)
    with ctx:
        yield ctx


def timed_function(name: Optional[str] = None, measurements: Optional[Dict[str, List[float]]] = None):
    """
    Decorator for measuring function execution time.
    
    Args:
        name: Optional name for the measurement (defaults to function name)
        measurements: Optional dict to store measurements
    
    Example:
        @timed_function("password_verification", measurements)
        def verify_password(password, hash):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            func_name = name or f"{func.__module__}.{func.__name__}"
            with measure_time(func_name, measurements):
                return func(*args, **kwargs)
        return wrapper
    return decorator


def get_current_time_ns() -> int:
    """Get current time in nanoseconds for high-precision timing."""
    return time.time_ns()


def get_current_time_ms() -> float:
    """Get current time in milliseconds."""
    return time.perf_counter() * 1000


class CombinedContext:
    """Context manager that combines timing and resource measurement."""
    
    def __init__(self, name: str, measurements: Optional[Dict[str, list]] = None):
        self.name = name
        if measurements is None:
            self.measurements = {}
        else:
            self.measurements = measurements
        self.timing_ctx = TimingContext(name, measurements)
        self.resource_ctx = ResourceContext(name, measurements)
        
    def __enter__(self):
        self.timing_ctx.__enter__()
        self.resource_ctx.__enter__()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.resource_ctx.__exit__(exc_type, exc_val, exc_tb)
        self.timing_ctx.__exit__(exc_type, exc_val, exc_tb)
        return False
    
    @property
    def elapsed_ms(self) -> float:
        """Get elapsed wall-clock time in milliseconds."""
        return self.timing_ctx.elapsed_ms
    
    @property
    def cpu_time_ms(self) -> float:
        """Get CPU time in milliseconds."""
        return self.resource_ctx.cpu_time_ms
    
    @property
    def memory_delta_mb(self) -> float:
        """Get memory delta in MB."""
        return self.resource_ctx.memory_delta_mb
    
    @property
    def db_query_count(self) -> int:
        """Get database query count."""
        return self.resource_ctx.db_query_count
    
    @property
    def db_time_ms(self) -> float:
        """Get total database query time in milliseconds."""
        return self.resource_ctx.db_time_ms


@contextmanager
def measure_time_with_resources(name: str, measurements: Optional[Dict[str, list]] = None):
    """
    Context manager for measuring both execution time and resource usage.
    
    Measures:
    - Wall-clock latency (ms)
    - CPU time (ms)
    - Memory delta (MB)
    - Database query count
    - Database query time (ms)
    
    Args:
        name: Name identifier for this measurement
        measurements: Optional dict to store measurements
    
    Example:
        with measure_time_with_resources("password_login", measurements):
            response = await client.post("/api/v1/password/login", json=...)
    """
    ctx = CombinedContext(name, measurements)
    with ctx:
        yield ctx

