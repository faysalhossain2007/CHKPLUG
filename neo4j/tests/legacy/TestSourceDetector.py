import unittest

import pandas as pd

from DataFlows import *
from DataFlowTracking import *
from NeoGraph import *
from SourceDetector import SinkDetector


def PrintNodeTable(nodeList: List[DataNode]):
    tuple_list = [l.toTuple() for l in nodeList]
    return pd.DataFrame(
        data=tuple_list,
        columns=(
            "Node_ID",
            "AST_Type",
            "Variable",
            "Caller",
            "Callee",
            "Filename",
            "Line_Num",
            "Score_Type",
        ),
    )


# class SourceDetectorTests(unittest.TestCase):
#     def setUp(self):
#         # Called before every test case.
#         header_print(f"Testing {self._testMethodName}")

#     def tearDown(self):
#         # Called after every test case.
#         pass

#     def testActionSourceTest(self):
#         print("===Test for locating action hook related sources.")
#         print(
#             "-------Source list without personal data filter. Check if the list contains the personal data variables"
#         )
#         temp = SourceDetector.locateActionSource(disablePersonalFilter=True)
#         print(PrintNodeTable(temp))

#         print(
#             "-------Source list with personal data filter. Compare with results above to check if the filter is too strong."
#         )
#         temp2 = SourceDetector.locateActionSource()
#         print(PrintNodeTable(temp2))

#         print("=" * 50)

#     def testWordPressSourceTest(self):
#         print("===Test for locating wordpress related sources.")
#         print("-------Source list")
#         temp = SourceDetector.locateWordPressSource()
#         print(PrintNodeTable(temp))

#         print("=" * 50)

#     def testWooCommerceSourceTest(self):
#         print("===Test for locating WooCommerce related sources.")
#         print("-------Source list")
#         temp = SourceDetector.locateWooCommerceSource()
#         print(PrintNodeTable(temp))
#         print("=" * 50)

#     def testRequestSourceTest(self):

#         print("===Test for locating Request related sources.")
#         print("-------Source list")
#         temp = SourceDetector.locateRequestSource()
#         print(PrintNodeTable(temp))
#         print("=" * 50)

#     def testPersonalFilterTest(self):
#         print("===Test for personal filter.")
#         print(
#             "-------Below is the list of nodes that are found as source but filtered out as non-personal data"
#         )
#         temp = SourceDetector.locateRequestSource()
#         temp.extend(SourceDetector.locateWooCommerceSource())
#         temp.extend(SourceDetector.locateWordPressSource())
#         temp.extend(SourceDetector.locateActionSource())

#         filteredOut = []
#         for i in temp:
#             if not i.personal:
#                 filteredOut.append(i)
#         # print(PrintNodeTable(filteredOut))
#         # print("=" * 50)
class TestSinkDetector(unittest.TestCase):
    def testThirdPartyDetector(self):
        SinkDetector.locateThirdPartySink()


def __run():
    unittest.main()


if __name__ == "__main__":
    __run()
