"""
Timing utilities for precise latency measurement.
"""
import time
from contextlib import contextmanager
from functools import wraps
from typing import Dict, List, Optional


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

