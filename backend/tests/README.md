# Latency Measurement Tests

This directory contains latency measurement tests for FIDO2, password, and TOTP authentication methods.

## Overview

The tests measure latencies across multiple dimensions:
1. **Backend Processing Time**: Server-side processing only
2. **Network Round-Trips**: Number of HTTP requests
3. **End-to-End Flow Time**: Total user experience time
4. **Cryptographic Operation Time**: Crypto overhead

## Running Tests

### Basic execution:
```bash
pytest backend/tests/ -v --asyncio-mode=auto
```

### With results export:
```bash
pytest backend/tests/ -v --asyncio-mode=auto --latency-results=results.json
```

### Export to both JSON and CSV:
```bash
pytest backend/tests/ -v --asyncio-mode=auto \
  --latency-results=results.json \
  --latency-results-csv=results.csv
```

## Test Files

- `test_latency_password.py`: Password registration and login latency tests
- `test_latency_totp.py`: TOTP setup and login latency tests
- `test_latency_fido2.py`: FIDO2 registration and login latency tests

## Results Format

Results are exported as JSON with statistics for each measurement:

```json
{
  "password_login_total": {
    "count": 10,
    "mean": 45.2,
    "median": 43.1,
    "min": 38.5,
    "max": 52.3,
    "p50": 43.1,
    "p75": 47.8,
    "p95": 51.2,
    "p99": 52.1
  }
}
```

## Fairness Considerations

The tests are designed to provide fair comparisons:
- Each method is measured under similar conditions
- Multiple dimensions are measured separately
- Results acknowledge that FIDO2 provides stronger security (higher latency may be acceptable)
- Breakdowns show where time is spent in each method

## Notes

- FIDO2 tests use mocked authenticator responses. For full cryptographic validity, use fido2's software authenticator.
- Tests use in-memory SQLite and fake Redis for isolation.
- Each test runs multiple iterations (typically 10) for statistical significance.


