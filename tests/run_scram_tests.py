#!/usr/bin/env python3
"""Run SCRAM tests.

Assumes truenas_api_client is installed (e.g., via pip install -e .)
"""

import sys
import unittest


if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.discover('tests/scram', pattern='test_*.py')

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
