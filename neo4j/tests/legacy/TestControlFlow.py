import unittest

from ControlFlowTracking import *
from DataFlows import *


class ControlFlowTest(unittest.TestCase):
    def testPrintPath(self):
        pass
        # ControlFlowTracking.flowsCondition(DataNode(10686,"1"),DataNode(10725,"2"))
        # pass

    def testTrackControlFlow(self):
        pass

    def testGetPropositionNode(self):
        # test on a switch node with code: switch ( strtolower( $format ) )
        print()
        # prop = ControlFlowTracking.getPropositionNode(6197)[0]
        # print(prop)
        # prop2 = ControlFlowTracking.getPropositionNode(6645)[0]
        # print(prop2)

        pass

    def testFlowsCondition(self):
        print("Test on Flow Condition")
        print()
        temp = ControlFlowTracking.flowsCondition(6093, 6124)

        for i in temp:
            print(i)

    def testFlowsCondition2(self):
        print("Test on Flow Condition2")
        # graph = getGraph()
        # query = """
        # MATCH (n)-[:PHP_REACHES]->(m)
        # RETURN n.id,m.id LIMIT 200
        # """
        # result = graph.run(cypher=query).data()
        # for r in result:

        #     temp = ControlFlowTracking.flowsCondition(r['n.id'],r['m.id'])
        #     if temp and temp[0]:
        #         print()
        #         print(temp)

        print()
        temp = ControlFlowTracking.flowsCondition(6174, 6391)
        for i in temp:
            print("Path: " + "=" * 10)
            print(i)
        pass

    def testGetControlFlowNode(self):
        pass

    def testGetCallFlag(self):
        # sample flags and see if we have a good coverage for the useful function calls
        pass

    def testConsentMatching(self):
        print("Test on Consent Matching")
        ControlFlowWPFunctions.getConsentRetrievalCall()
        pass


if __name__ == "__main__":
    unittest.main()
