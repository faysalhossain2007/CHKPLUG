import unittest

from DataFlowTracking import *
from NeoGraph import *
from Preproccess import *


class DataFlowTrackingTest(unittest.TestCase):
    def testDataFlowTracking1(self):
        temp = DataNode(13891, "email")
        temp.setPersonal("email")
        # sinks = trackDataFlowFromNode(temp)
        # paths = dataflowGraph.getAllPathsFromSource([temp])

        # print(sinks)
        # print(paths)
        # for i in paths["email"]:
        #    i.printPathInfo()

    # def testDataFlowTracking2(self):
    #     temp = SourceDetector.locateRequestSource()
    #     sinks = trackDataFlow(temp)
    #     paths = dataflowGraph.getAllPathsFromSource(temp)
    #     for i in paths:
    #         for j in paths[i]:
    #            j.printPathInfo()
    def testPrintPath(self):
        temp = SourceDetector.locateSource()
        print("All sources" + str(temp))
        print("=" * 15)
        for x in temp:
            sinks = trackDataFlowFromNode(x)

        paths = dataflowGraph.getAllPathsFromSource(temp)
        # print(sinks)
        for i in paths:
            for j in paths[i]:
                print("Paths for:" + str(i))
                j.printPathInfo()


if __name__ == "__main__":
    unittest.main()
