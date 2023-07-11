# from NeoHelper import *
# scrape("https://www.boldgrid.com/software-privacy-policy/")

import unittest

import pandas as pd

from DataFlows import *
from DataFlows import DataFlowGraph
from DataFlowTracking import *
from Detectors.Manager import DetectorManager
from Detectors.Scores import Score
from Errors import DetectorManagerUninitializedException
from NeoGraph import *
from NeoGraph import getGraph
from NeoHelper import concatTree, getCallName, getNodeType
from Preproccess import *
from SourceDetector import *
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


class MiscFunctionsTestCases(unittest.TestCase):
    def setUp(self):
        # Called before every test case.
        global SECURITY_DETECTOR_MANAGER
        if not SECURITY_DETECTOR_MANAGER:
            raise DetectorManagerUninitializedException()

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
        SECURITY_DETECTOR_MANAGER.findingChildrenMap[f] = {1}
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

    def testConcatChild(self):
        # tested using GDPR Plugin
        print(concatChildString(21284))

    def testConcatTree(self):
        graph = getGraph()
        randomCallQuery = """
        MATCH (n) WHERE n.type in ['AST_METHOD_CALL','AST_STATIC_CALL'] RETURN n.id LIMIT 5
        """
        result = graph.run(cypher=randomCallQuery).data()
        for i in result:
            print(concatTree(i["n.id"]))

    def testConcatTree2(self):
        graph = getGraph()
        randomCallQuery = """
        MATCH (n) WHERE n.type in ['AST_DIM','AST_STATIC_CALL'] RETURN n.id LIMIT 5
        """
        result = graph.run(cypher=randomCallQuery).data()
        for i in result:
            print(concatTree(i["n.id"]))

    def testConcatTree3(self):
        graph = getGraph()
        randomCallQuery = """
        MATCH (n) WHERE n.type in ['AST_RETURN'] RETURN n.id LIMIT 5
        """
        result = graph.run(cypher=randomCallQuery).data()
        for i in result:
            print(concatTree(i["n.id"]))

    def testEliminateNodes(self):
        graph = getGraph()
        randomCallQuery = """
        MATCH (n) WHERE n.type in ['AST_ASSIGN'] RETURN n.id LIMIT 1
        """
        result = graph.run(cypher=randomCallQuery).data()
        print(result[0]["n.id"])
        testResult = eliminateUselessNodes(result[0]["n.id"])
        for i in testResult:
            print(getNodeType(i))

    # def testASTAssignHierarchyHelper(self):
    #     graph = getGraph()
    #     assignQuery = """
    #     MATCH (n)-[:PARENT_OF]->(m) WHERE n.type in ["AST_ASSIGN","AST_ASSIGN_OP"] AND m.childnum = 1 RETURN m.id LIMIT 5
    #     """
    #     result = graph.run(cypher=assignQuery).data()

    #     for assignNode in result:
    #         print("Test on node"+str(assignNode['m.id']))
    #         currentTier = assignNode['m.id']
    #         currentTier = eliminateUselessNodes(currentTier)
    #         for x in currentTier:
    #             help_ast_connect_assign_hierarchy(x)
    #         print("="*10)
    # def testASTAssignHierarchyHelper2(self):
    #     graph = getGraph()
    #     assignQuery = """
    #     MATCH (n)-[:PARENT_OF]->(m)
    #     WHERE n.type in ["AST_ASSIGN","AST_ASSIGN_OP"] AND m.childnum = 1
    #     WITH m
    #     MATCH (m)-[:PARENT_OF*0..5]->(x)
    #     WHERE x.type in ['AST_CALL','AST_METHOD_CALL','AST_STATIC_CALL']
    #     WITH m,x
    #     MATCH (x)-[:CALLS]->(y)
    #     WITH m,x,y
    #     MATCH (return)
    #     WHERE return.type = 'AST_RETURN' AND return.funcid = y.id
    #     RETURN m.id,x,return LIMIT 5
    #     """
    #     result = graph.run(cypher=assignQuery).data()

    #     for assignNode in result:
    #         print("Test on node"+str(assignNode['m.id']))
    #         currentTier = assignNode['m.id']
    #         currentTier = eliminateUselessNodes(currentTier)
    #         for x in currentTier:
    #             help_ast_connect_assign_hierarchy(x)
    #         print("="*10)
    def testConcatTree4(self):
        graph = getGraph()
        query = """
        MATCH (n)-[:PARENT_OF]->(m)
        WHERE n.type in ['AST_CALL','AST_STATIC_CALL','AST_METHOD_CALL'] AND m.type = 'AST_NAME' 
        RETURN m.id LIMIT 5
        """
        result = graph.run(cypher=query).data()
        for node in result:
            print("Test on node" + str(node["m.id"]))
            print(concatTree(node["m.id"]))

    def testGetCallName(self):
        # test on AST_CALL
        graph = getGraph()
        query = """
        MATCH (n)
        WHERE n.type in ['AST_CALL'] 
        RETURN n.id LIMIT 20
        """
        result = graph.run(cypher=query).data()
        for node in result:
            print("Test on node" + str(node["n.id"]))
            print(getCallName(node["n.id"]))

    def testGetCallName2(self):
        # test on AST_CALL
        graph = getGraph()
        query = """
        MATCH (n)-[:PARENT_OF]->(m)
        WHERE n.type in ['AST_METHOD_CALL','AST_STATIC_CALL']
        RETURN DISTINCT n.id LIMIT 20
        """
        result = graph.run(cypher=query).data()
        for node in result:
            print("Test on node" + str(node["n.id"]))
            print(getCallName(node["n.id"]))


def __run():
    unittest.main()


if __name__ == "__main__":
    __run()
