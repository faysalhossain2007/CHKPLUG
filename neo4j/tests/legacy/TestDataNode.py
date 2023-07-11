# from NeoHelper import *
# scrape("https://www.boldgrid.com/software-privacy-policy/")

import unittest

import pandas as pd

from DataFlows import *
from DataFlowTracking import *
from Detectors.Manager import DetectorManager
from Detectors.Scores import Score
from NeoGraph import *
from NeoHelper import *
from Utls import header_print

# Set Pandas options for printing dataframes.
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)
pd.set_option("display.max_colwidth", None)

"""
test = DataFlowPath(DataNode(1,1,1,1,None,None))
node = DataNode(2,2,2,2,None,None)
test.insert(node)
print(test.head.id)
print(test.tail.id)
test.printPathInfo(True)
test2 = DataFlowPath(DataNode(3,3,3,3,None,None))
test2.insertPath(test)
test2.printPathInfo(True)


test = DataFlowPath(DataNode(1,1,1,1,None,None))
test2 = copy.deepcopy(test)
node = DataNode(2,2,2,2,None,None)
test.insert(node)
test.printPathInfo()
test2.printPathInfo()
"""


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


class GraphTests(unittest.TestCase):
    def setUp(self):
        # Called before every test case.
        header_print(f"Testing {self._testMethodName}")

    def tearDown(self):
        # Called after every test case.
        pass

    def testDataFlowGraphTest1(self):
        testGraph = DataFlowGraph()
        self.assertFalse(testGraph.insertEdge(DataNode(1, ""), DataNode(2, "")))

    def testDataFlowGraphTest2(self):
        testGraph = DataFlowGraph()
        testNode = DataNode(3013, "test1", "test1", "node", None, None)
        testNode2 = DataNode(3016, "test2", "test2", "node", None, None)
        testNode3 = DataNode(3013, "test3", "test1", "node", None, None)
        testNode.setPersonal("email")
        testNode2.setPersonal("email")
        testNode3.setPersonal("email")

        self.assertTrue(testGraph.insertNode(testNode))
        self.assertFalse(testGraph.insertNode(testNode))
        self.assertTrue(testGraph.insertNode(testNode2))
        self.assertEqual((testGraph.getNode(3013).id), 3013)
        self.assertEqual((testGraph.getNode(3013).personal), ["email"])
        self.assertFalse(testGraph.insertNode(testNode3))

    def testDataFlowGraphTest3(self):

        testGraph = DataFlowGraph()
        testNode = DataNode(3013, "test1", "test1", "node", None, None)
        testNode2 = DataNode(3016, "test2", "test2", "node", None, None)
        testNode3 = DataNode(3019, "test3", "test3", "node", None, None)
        testNode.setPersonal("email")
        testNode2.setPersonal("email")
        testNode3.setPersonal("email")

        self.assertTrue(testGraph.insertNode(testNode))
        self.assertFalse(testGraph.insertNode(testNode))
        self.assertTrue(testGraph.insertNode(testNode2))
        self.assertTrue(testGraph.insertEdge(testNode, testNode2))
        self.assertFalse(testGraph.insertEdge(testNode2, DataNode(3017, "test2")))
        self.assertTrue(testGraph.insertNode(testNode3))
        self.assertTrue(testGraph.insertEdge(testNode2, testNode3))

        # self.assertFalse(testGraph.getNewFringe([(3013,'test3')])
        # self.assertTrue(testGraph.getNewFringe([(3013,'test1')])==[(3016,'test2')]
        # testGraph.importGraphToNeo4j([testNode])

    def testDataFlowGraphTest4(self):
        testGraph = DataFlowGraph()
        testNode = DataNode(3013, "test1", "test1", "node", None, None)
        testNode2 = DataNode(3016, "test2", "test2", "node", None, None)
        testNode3 = DataNode(3019, "test3", "test3", "node", None, None)
        testNode4 = DataNode(3022, "test4", "test4", "node", None, None)
        testNode.setPersonal("email")
        testNode2.setPersonal("email")
        testNode3.setPersonal("email")
        testNode4.setPersonal("email")
        self.assertTrue(testGraph.insertNode(testNode))
        self.assertTrue(testGraph.insertNode(testNode2))
        self.assertTrue(testGraph.insertNode(testNode3))
        self.assertTrue(testGraph.insertEdge(testNode, testNode2))
        self.assertTrue(testGraph.insertEdge(testNode2, testNode3))
        testGraph.insertNode(testNode4)
        testGraph.insertEdge(testNode2, testNode4)
        # print(testGraph.nodes)
        # print(testGraph.edges)
        # self.assertTrue(testGraph.getNewFringe([(3013,'test1')])==[(3016,'test2')]
        testresult = testGraph.getAllPathsFromSource([testNode])
        print(testresult)
        for i in testresult:
            for j in testresult[i]:
                print(j)
        # for i in testresult["email"][0].path:
        #     print(i)

    def testDataFlowGraphTest5(self):
        testGraph = DataFlowGraph()
        testNode = DataNode(3013, "test1", "test1", "node", None, None)
        testNode2 = DataNode(3016, "test2", "test2", "node", None, None)
        testNode3 = DataNode(3019, "test3", "test3", "node", None, None)
        testNode4 = DataNode(3022, "test4", "test4", "node", None, None)
        testNode.setPersonal("email")
        testNode2.setPersonal("email")
        testNode3.setPersonal("email")
        testNode4.setPersonal("email")
        self.assertTrue(testGraph.insertNode(testNode))
        self.assertTrue(testGraph.insertNode(testNode2))
        self.assertTrue(testGraph.insertNode(testNode3))
        self.assertTrue(testGraph.insertNode(testNode4))
        self.assertTrue(testGraph.insertEdge(testNode, testNode2))
        self.assertTrue(testGraph.insertEdge(testNode2, testNode3))
        self.assertTrue(testGraph.insertEdge(testNode2, testNode4))
        print("All sources:" + str(testGraph.getAllSources()))
        allPaths = testGraph.getAllPaths()
        print("All paths:" + str(allPaths))
        # path_list: List[List[DataNode]] = [l.toDataNodeList() for l in testGraph.getAllPaths()]

        for personalDataType in allPaths:
            print("=" * 10 + "paths for personal data type: '" + personalDataType + "'")
            path_list: List[List[DataNode]] = [
                l.toDataNodeList() for l in allPaths[personalDataType]
            ]
            print(path_list)

    def testgetAssignLocationFromSink(self):
        testGraph = DataFlowGraph()
        testNode = DataNode(1129, "test1", "test1", "node", None, None)
        testNode2 = DataNode(1203, "test2", "test2", "node", None, None)
        testNode3 = DataNode(1190, "test3", "test3", "node", None, None)
        testNode.setPersonal("email")
        testNode2.setPersonal("email")
        testNode3.setPersonal("email")
        self.assertTrue(testGraph.insertNode(testNode))
        self.assertTrue(testGraph.insertNode(testNode2))
        self.assertTrue(testGraph.insertNode(testNode3))
        self.assertTrue(testGraph.insertEdge(testNode, testNode2))
        self.assertTrue(testGraph.insertEdge(testNode2, testNode3))
        print("All sources:" + str(testGraph.getAllSources()))
        allPaths = testGraph.getAllPaths()
        print("All paths:" + str(allPaths))
        for i in testGraph.getAssignLocationFromSink(1190):
            print(i)

    # def testPreprocessTest1(self):
    #     print("===Preprocess test 1")
    #     TestPreprocessGraph()
    #     self.assertTrue(True)
    # def testPreprocessTest2(self):
    #     print("===Preprocess test 1")
    #     TestPreprocessGraph2()
    #     self.assertTrue(True)
    # def testPreprocessTest3(self):
    #     print("===Preprocess test 1")
    #     TestPreprocessGraph3()
    #     self.assertTrue(True)

    # NeoHelper Test section
    def testConcatChild(self):
        print(concatChildString(21284))

    # def testDataFlowTracking1(self):
    #     temp = DataNode(13891, "email")
    #     if temp == -1:
    #         self.fail()
    #     temp.setPersonal("email")
    #     sinks = trackDataFlowFromNode(temp)
    #     paths = dataflowGraph.getAllPathsFromSource([temp])

    #     # print(sinks)
    #     print(paths)
    #     for i in paths["email"]:
    #         i.printPathInfo()


class MiscFunctionsTestCases(unittest.TestCase):
    def setUp(self):
        # Called before every test case.
        global SECURITY_DETECTOR_MANAGER
        d = SECURITY_DETECTOR_MANAGER.detector_dict["WordPressStorageDetector"]
        header_print(f"Testing {self._testMethodName}")
        d.new_finding(
            {"id": 1, "lineno": 10},
            Score(1.0, {}, score_type=ScoreType.STORAGE),
            "Test storage finding",
        )
        f = list(d.findings)[0]
        SECURITY_DETECTOR_MANAGER._rebuild_maps()
        SECURITY_DETECTOR_MANAGER.allFindings.update(d.findings)
        SECURITY_DETECTOR_MANAGER.findingChildrenMap[f] = [1]
        SECURITY_DETECTOR_MANAGER.findingPrecedenceMap[f] = 1

    def tearDown(self):
        # Called after every test case.
        global SECURITY_DETECTOR_MANAGER
        SECURITY_DETECTOR_MANAGER = DetectorManager(getGraph(), silent=True)

    def testIsStorageDataNode(self):
        n1 = DataNode(1, "hello")
        n2 = DataNode(2, "not_storage")
        self.assertTrue(isStorage(n1))
        self.assertFalse(isStorage(n2))

    def testIsAssignee(self):
        self.assertTrue(isNodeAssignee(1129))
        self.assertFalse(isNodeAssignee(1203))


if __name__ == "__main__":
    unittest.main()
