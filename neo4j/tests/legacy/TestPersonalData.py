import unittest

from DataFlowTracking import *
from NeoGraph import *
from PersonalData import *
from Preproccess import *


class TestPersonalData(unittest.TestCase):
    def testDetermineCategory(self):
        print(PersonalDataMatcher.determine_category("random"))

    def testPIILabelling(self):
        trackDataFlow([None])
        # reverseTrackDataFlow()

        for node in dataflowGraph.nodes:
            print("node with varName: " + dataflowGraph.nodes[node].varName)
            print(
                "expected: "
                + str(PersonalDataMatcher.determine_category(dataflowGraph.nodes[node].varName))
                + " || actual label: "
                + str(dataflowGraph.nodes[node].personal)
            )


if __name__ == "__main__":
    unittest.main()
