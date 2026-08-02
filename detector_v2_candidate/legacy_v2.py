# -*- coding: utf-8 -*-
"""Run tests/test_detector.py verbatim, but with scamshield.detector swapped
for detector_v2. Same 7 assertions, no edits to the test file."""
import importlib.util
import sys
import os
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

spec = importlib.util.spec_from_file_location("detector_v2", os.path.join(HERE, "detector_v2.py"))
v2 = importlib.util.module_from_spec(spec)
sys.modules["detector_v2"] = v2
spec.loader.exec_module(v2)

# Shim scamshield.detector -> detector_v2 before the test module imports it.
pkg = types.ModuleType("scamshield")
pkg.__path__ = [os.path.join(ROOT, "scamshield")]
sys.modules["scamshield"] = pkg
sys.modules["scamshield.detector"] = v2

spec2 = importlib.util.spec_from_file_location(
    "test_detector", os.path.join(ROOT, "tests", "test_detector.py"))
tm = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(tm)

suite = unittest.defaultTestLoader.loadTestsFromModule(tm)
res = unittest.TextTestRunner(verbosity=2).run(suite)
print("LEGACY-SUITE-AGAINST-V2:", "OK" if res.wasSuccessful() else "FAILED",
      f"({res.testsRun} tests, {len(res.failures)} failures, {len(res.errors)} errors)")
