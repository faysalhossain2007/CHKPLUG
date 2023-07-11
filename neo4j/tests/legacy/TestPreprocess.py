import unittest

from DataFlowTracking import *
from NeoGraph import *
from Preproccess import *
from NeoHelper import *
import numpy
import math
from ClassStructure import determineObjectType
from ClassStructure import getClassHierarchy
from AdminAccessChecker import isNodeAdmin

def fiveNumberSummary(x):
    print("Sample size")
    print(len(x))
    print("Min")
    print(numpy.min(x))
    print("Max")
    print(numpy.max(x))
    print("STD")
    print(numpy.std(x))
    print("Mean")
    print(numpy.mean(x))
    print("Median")
    print(numpy.median(x))
class TestPreprocess(unittest.TestCase):
    def setUp(self):
        # Called before every test case.
        header_print(f"Testing {self._testMethodName}")

    def tearDown(self):
        # Called after every test case.
        pass
    # def testDataFlowTrackingLength(self):
    #     graph = getGraph()
    #     query = f"""
    #     MATCH (n:AST{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(m:AST{{childnum:0}})
    #     RETURN m.id
    #     """
    #     result = graph.run(cypher = query).data()
    #     length1s = []
    #     length2s = []
    #     for i in progress_bar(result):
    #         length1,length2 = reverseTrackDataFlowToParamORAssignNoRecord(i['m.id'])
    #         if length1:
    #             if not type(length1)==int:
    #                 print((length1))
    #             length1s.append(length1)
                
    #         if length2:
    #             if not type(length2)==int:
    #                 print((length2))
    #             length2s.append(length2)
    #     fiveNumberSummary(length1s)
    #     print()
    #     fiveNumberSummary(length2s)
    # def testPreprocessTest(self):
    #     print("===Preprocess test 1")
    #     preprocess_graph()
    #     self.assertTrue(True)
    # def testPreprocessTest1(self):
    #     print("===Preprocess test 1")
    #     TestPreprocessGraph()
    #     self.assertTrue(True)
    # def testPreprocessTest2(self):
    #     print("===Preprocess test 2")
    #     TestPreprocessGraph2()
    #     self.assertTrue(True)

    # def testPreprocessTest3(self):
    #     print("===Preprocess test 3")
    #     TestPreprocessGraph3()
    #     self.assertTrue(True)

    # def testPreprocessTestAssign(self):
    #     print("===Preprocess test 4")
    #     TestPreprocessGraph4()
    # def testPreprocessTestHierarchy(self):
    #     print("===Preprocess test 5")
    #     TestPreprocessGraph5()
    # def testPreprocessTestReturn(self):
    #     print("===Preprocess test 6")
    #     TestPreprocessGraph6()
    #     graph = getGraph()
    #     testQuery = """
    #     MATCH (assign:AST)-[:PARENT_OF]->(assignee:AST)
    #     WHERE assign.type = "AST_ASSIGN" AND assignee.childnum = 0 AND assignee.type = 'AST_VAR'
    #     WITH assign, assignee
    #     OPTIONAL MATCH (assignee)<-[:PHP_REACHES]-(assigner)
    #     RETURN assignee, assigner
    #     """

    #     result = graph.run(cypher = testQuery).data()
    #     for i in result:
    #         if not i['assigner']:
    #             self.assertTrue(False)
    # def testPreprocessTestClassHierarchy(self):
    #     print("===Preprocess test 7")
    #     TestPreprocessGraph7()
    # def testPreprocessCycle(self):
    #     print("===Preprocess test cycling")
    #     TestPreprocessCycle()
    # def testGetClassHierarchy(self):
    #     classHierarchy = getClassHierarchy()
    #     print("second time")
    #     classHierarchy2 = getClassHierarchy()
    #     print(classHierarchy==classHierarchy2)
    #     determineObjectType({'type':1})
    # def testAdminAccess(self):
    #     print(isNodeAdmin(18891))


def __run():
    unittest.main()


if __name__ == "__main__":
    __run()
