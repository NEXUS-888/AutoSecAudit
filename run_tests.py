#!/usr/bin/env python3
"""
Unified Test Runner for AutoSecAudit.
Runs all test modules (test_*.py) and reports comprehensive pass/fail metrics.
Exits with status code 0 if all tests pass, or status code 1 if any test fails.
"""

import sys
import os
import unittest
import time
import tempfile
import shutil


def main():
    print("=" * 60)
    print("       AUTOSECAUDIT UNIFIED TEST SUITE RUNNER")
    print("=" * 60)
    
    start_time = time.time()
    
    # AUD-46: Isolate test runs to a temporary data directory so repo data/ is never polluted
    created_temp = False
    temp_data_dir = os.environ.get("AUTOSEC_DATA_DIR")
    if not temp_data_dir:
        temp_data_dir = tempfile.mkdtemp(prefix="autosec_test_data_")
        os.environ["AUTOSEC_DATA_DIR"] = temp_data_dir
        created_temp = True
    os.makedirs(os.path.join(temp_data_dir, "reports"), exist_ok=True)

    try:
        # Discover all test_*.py files in root directory
        loader = unittest.TestLoader()
        suite = loader.discover(start_dir=".", pattern="test_*.py")
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        elapsed = time.time() - start_time
        
        print("\n" + "=" * 60)
        print("                  TEST RESULTS SUMMARY")
        print("=" * 60)
        print(f"Total Tests Executed : {result.testsRun}")
        print(f"Total Failures       : {len(result.failures)}")
        print(f"Total Errors         : {len(result.errors)}")
        print(f"Total Skipped        : {len(result.skipped)}")
        print(f"Execution Time       : {elapsed:.2f} seconds")
        print("=" * 60)
        
        if result.wasSuccessful():
            print("SUCCESS: All tests passed successfully!")
            return 0
        else:
            print("FAILURE: Some tests failed or encountered errors.")
            return 1
    finally:
        if created_temp:
            os.environ.pop("AUTOSEC_DATA_DIR", None)
            shutil.rmtree(temp_data_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
