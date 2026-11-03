"""Standalone stdlib unittest runner emitting a case-level JUnit report.

Executed by the selected interpreter through testexec's existing process boundary.
All imports precede adding the test working directory to Python's module path.
"""
from __future__ import annotations

import os
import sys
import traceback
import unittest
import xml.etree.ElementTree as ET

__all__ = ["main"]


class _JUnitResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = []
        self.subtest_parents = set()

    def _record(self, test, status=None, detail="", parent=None):
        owner = parent if parent is not None else test
        cls = type(owner).__module__ + "." + type(owner).__qualname__
        identity = test.id()
        name = identity[len(cls) + 1:] if identity.startswith(cls + ".") else identity
        case = ET.Element("testcase", classname=cls, name=name)
        if status:
            message = "collection failure" if cls in (
                "unittest.loader._FailedTest", "unittest.suite._ErrorHolder") else status
            ET.SubElement(case, status, message=message).text = detail
        self.cases.append(case)

    def addSuccess(self, test):
        super().addSuccess(test)
        if test not in self.subtest_parents:
            self._record(test)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "failure", "".join(traceback.format_exception(*err)))

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "error", "".join(traceback.format_exception(*err)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, "skipped", reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._record(test, "skipped", "expected failure\n" + "".join(traceback.format_exception(*err)))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, "failure", "unexpected success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        self.subtest_parents.add(test)
        status = None if err is None else "failure" if issubclass(err[0], test.failureException) else "error"
        self._record(subtest, status, "" if err is None else "".join(traceback.format_exception(*err)), parent=test)


class _JUnitRunner(unittest.TextTestRunner):
    resultclass = _JUnitResult
    report_path = None

    def run(self, test):
        result = super().run(test)
        suite = ET.Element("testsuite", name="unittest", tests=str(len(result.cases)))
        for status, attr in (("failure", "failures"), ("error", "errors"), ("skipped", "skipped")):
            suite.set(attr, str(sum(case.find(status) is not None for case in result.cases)))
        suite.extend(result.cases)
        with open(self.report_path, "wb") as output:
            ET.ElementTree(suite).write(output, encoding="utf-8", xml_declaration=True)
        return result


def main():
    _JUnitRunner.report_path = sys.argv[1]
    sys.path.insert(0, os.getcwd())
    unittest.main(module=None, argv=["python -m unittest", *sys.argv[2:]], testRunner=_JUnitRunner)


if __name__ == "__main__":
    main()
