# from DataFlows import DataNode
import time

from NeoGraph import getGraph

# class JSFlowDetector:

NODE_PARAMETER_CHILDNUM = "childnum"
NODE_PARAMETER_CODE = "code"
NODE_PARAMETER_ID = "id"
NODE_PARAMETER_TYPE = "type"
NODE_PARAMETER_FUNCID = "funcid"
NODE_PARAMETER_LABELS = "labels"
NODE_PARAMETER_CLASSNAME = "classname"
NODE_PARAMETER_NAME = "name"

TAG_AST_JS_STRING = "AST_JS_string"
TAG_AST_JS_AST_ARG_LIST = "AST_JS_AST_ARG_LIST"
TAG_AST_JS_AST_CLOSURE = "AST_JS_AST_CLOSURE"
TAG_AST_JS_AST_METHOD_CALL = "AST_JS_AST_METHOD_CALL"
TAG_AST_JS_AST_ASSIGN = "AST_JS_AST_ASSIGN"
TAG_AST_JS_AST_VAR = "AST_JS_AST_VAR"
TAG_AST_JS_string = "AST_JS_string"
TAG_AST_JS_AST_CALL = "AST_JS_AST_CALL"
TAG_AST_JS_AST_ARRAY = "AST_JS_AST_ARRAY"

TAG_ACTION_TYPE_POST = "post"
TAG_ACTION_TYPE_GET = "get"
TAG_ACTION_TYPE_PUT = "put"

TAG_DATA_FLOW = "dataflow"
TAG_VAR_NAME = "varname"
TAG_DATA = "data"
TAG_REQUEST_TYPE = "requesttype"
TAG_URL = "url"
TAG_FUNCID = "funcID"
TAG_NODE = "node"
TAG_STEP = "step"


class DataNodeJS:
    def __init__(self):
        self.id = 0
        self.labels = ""
        self.type = ""
        self.flags = ""  # no data
        self.lineno = 0  # no data
        self.code = ""
        self.childnum = 0
        self.funcid = 0  # no data
        self.classname = ""
        self.name = ""
        self.classname = ""  # no data
        self.namespace = ""  # no data
        self.endlineno = ""  # no data
        self.doccomment = ""  # no data


class DataFlowPath:
    def __init__(self):
        self.startNode = ""  # for example - var formData = $(this).serialize();. here, formData will be source node.
        self.endNode = ""  # for example, 	$.post(GDPR.ajaxurl,. here, node containing 'post' will be used at sinkNode
        self.PIIInfo = ""
        self.linkerKeyword = ""
        self.requestType = ""  # it can be either POST/GET/REQ
        self.path = []  # it will contain list of datanodes from source to sink
        self.violationOccur = False

    def print_path(self):
        print(
            "Complete Path--> Start Node:",
            self.startNode,
            "End Node:",
            self.endNode,
            "PII",
            self.PIIInfo,
            ",Linker Keyword",
            self.linkerKeyword,
            ",Request Type",
            self.requestType,
            ",Path",
            self.path,
            ",Violation Result",
            self.violationOccur,
        )


"""
return all the function nodes for a specific class name (from HTML) and operation type
"""
"""
in future the following should be in the preprocess connecting html with JS
"""


def locateSourceInJS(idName, className, operation, graph):
    """
    :param className: HTML class name
    :param operation: submit, click
    :return: associated javascript function or -1 (no function found)
    """
    type = TAG_AST_JS_STRING

    nodes = -1
    if idName != "":
        nodes = getNodesByCode(idName, type, graph)
    if nodes == -1:
        print("Can't find with ID")
        nodes = getNodesByCode(className, type, graph)
    if nodes == -1:
        print("Can't find with classname")
        return -1

    funcNodes = []

    for node in nodes:
        childNum = node["a"][NODE_PARAMETER_CHILDNUM]
        id = node["a"][NODE_PARAMETER_ID]

        # 'first child (1 index) will contain the class name'
        if childNum == 1:
            immediateParentNode = getImediateParentNode(id, graph)
            # print(immediateParentNode)

            if immediateParentNode != -1:
                if immediateParentNode["a"][NODE_PARAMETER_TYPE] == TAG_AST_JS_AST_ARG_LIST:
                    parentID = immediateParentNode["a"][NODE_PARAMETER_ID]
                    child = getSpecificChildOfANodeByCode(parentID, operation, graph)

                    if child != -1:
                        funcNode = getSpecificChildOfANodeByType(
                            parentID, TAG_AST_JS_AST_CLOSURE, graph
                        )
                        funcNodes += funcNode

    # helperPrint("func nodes", funcNodes)

    if len(funcNodes) > 0:
        return funcNodes

    return -1


def startTraversing(nodes, passedData, graph):
    """
    :param nodes: list of node to traverse
    :param passedData: passedData from HTML
    :param graph:
    :return: list of dataflow or -1 (when no data flow has beeen found)
    """
    dataFlows = []  # list all the data flow dict: [ (dataflow, variable_name, [data]) ]

    for node in nodes:
        cfgNodes = getAllCFGEdgesFromClosureFuncNode(node["a"][NODE_PARAMETER_ID], graph)
        # helperPrint("visited cfg nodes", cfgNodes)

        visitedNodeIDs = []
        """
        graph traversal using BFS approach
        """
        while len(cfgNodes) > 0:
            nodeToExplore = cfgNodes.pop()
            nodeToExploreID = nodeToExplore["a"][NODE_PARAMETER_ID]
            nodeToExploreCode = nodeToExplore["a"][NODE_PARAMETER_CODE]
            nodeToExploreFunctionType = nodeToExplore["a"][NODE_PARAMETER_TYPE]

            if nodeToExploreID in visitedNodeIDs:
                continue
            visitedNodeIDs.append(nodeToExploreID)

            # elif nodeToExploreFunctionType == TAG_AST_JS_AST_CALL:
            #     '''
            #         if it is a call_node then it should have a reaches incoming edge -> track that
            #         calls outgoing edge will indicate where the data is flowing (it can be more fine-graned by checking the data attributes, but now focus on the object instead)
            #     '''
            #
            #     argListNode = getSpecificChildOfANodeByType(nodeToExploreID, TAG_AST_JS_AST_ARG_LIST, graph)
            #     data = []
            #     for argNode in argListNode:
            #         tag = argNode['a'][NODE_PARAMETER_CODE]
            #         if isPIIData(tag) != -1:
            #             data.append((tag, tag))
            #
            #     if len(data) == 0:
            #         continue
            #     else:
            #         helperPrint("need to handle cases where there pii data in the success response", "")

            if nodeToExploreFunctionType == TAG_AST_JS_AST_CLOSURE:

                # need to expand requestFuncNode and add it to the dataflow
                requestCFGNodes = getAllCFGEdgesFromClosureFuncNode(nodeToExploreID, graph)
                # helperPrint("closure function id", requestFuncNode['a'][NODE_PARAMETER_ID])
                print("*" * 100)
                print("requestCFGNODES", len(requestCFGNodes))
                print("cfgNodes", len(cfgNodes))
                cfgNodes += requestCFGNodes
                print("cfgNodes", len(cfgNodes))
                print("*" * 100)

            elif nodeToExploreFunctionType == TAG_AST_JS_AST_ASSIGN:

                variableDeclNode = getSpecificChildOfANodeByType(
                    nodeToExploreID, TAG_AST_JS_AST_VAR, graph
                )[0]
                variableNameNode = getSpecificChildOfANodeByType(
                    variableDeclNode["a"][NODE_PARAMETER_ID], TAG_AST_JS_string, graph
                )[0]

                # variableNameNode = getVarInOutgoingReachesEdge(nodeToExploreID, getGraph())
                # variableNameNode[0]['r']['var']

                piiData = -1
                if "serialize" in nodeToExploreCode:
                    tupleList = handleSerialize(passedData)
                    if tupleList != -1:
                        # needs to find where these tupleList flows
                        piiData = tupleList
                        # dataFlows = addEntryInDataflows(variableNameNode['a'][NODE_PARAMETER_FUNCID], variableNameNode['a'][NODE_PARAMETER_CODE], variableNameNode, data, dataFlows)
                        # startNode = constructDataNode(nodeToExploreID, graph)
                        # continue #we don't want to visit child node of serilize node as the ultimate flow is already determined in this node
                else:
                    dataNode = getSpecificChildOfANodeByChildNo(
                        nodeToExploreID, 1, graph
                    )  # 1 child will contain the code of the PII
                    if dataNode != -1:
                        # helperPrint("Datanode", dataNode)
                        probablePiiData = dataNode["a"][NODE_PARAMETER_CODE]
                        if probablePiiData != -1:
                            piiData = detectPIIData(probablePiiData)
                            # helperPrint("PIIDATA", piiData)
                            # dataFlows = updateEntryInDataflowByVarName(variableNameNode['a'][NODE_PARAMETER_FUNCID], variableNameNode['a'][NODE_PARAMETER_CODE], variableNameNode, data, dataFlows)

                if piiData == -1:
                    continue
                # startDataNode = constructDataNode(nodeToExploreID, graph)
                dataflow = DataFlowPath()
                dataflow.PIIInfo = piiData

                reachesNodesToExplore = []
                reachesNodesToExplore.append(nodeToExplore)

                while len(reachesNodesToExplore) > 0:

                    reachesNodeToExplore = reachesNodesToExplore.pop()
                    outgoingDDGNodes = getOutgoingDDGEdges(
                        reachesNodeToExplore["a"][NODE_PARAMETER_ID], graph
                    )

                    intermediateNode = constructDataNode(
                        reachesNodeToExplore["a"][NODE_PARAMETER_ID], graph
                    )
                    dataflow.path.append(intermediateNode)

                    if outgoingDDGNodes != -1:
                        for outgoingNode in outgoingDDGNodes:
                            reachesNodesToExplore.append(outgoingNode)

                    if reachesNodeToExplore["a"][NODE_PARAMETER_TYPE] == TAG_AST_JS_AST_METHOD_CALL:
                        isUseless = checkUselessFunctions(
                            reachesNodeToExplore["a"][NODE_PARAMETER_CODE]
                        )
                        if isUseless != -1:
                            print(
                                "Useless Function Detected",
                                reachesNodeToExplore,
                                isUseless,
                            )
                            continue

                        requestType = getRequestTypeOfAMethodCall(
                            reachesNodeToExplore["a"][NODE_PARAMETER_ID], graph
                        )
                        # requestNode = getSpecificChildOfANodeByChildNo(reachesNodeToExplore['a'][NODE_PARAMETER_ID], 1, graph)

                        if requestType != -1:
                            """
                            handle cases when the request type is either POST/GET/PUT
                            """
                            dataflow.requestType = requestType

                            argListNode = getSpecificChildOfANodeByType(
                                reachesNodeToExplore["a"][NODE_PARAMETER_ID],
                                TAG_AST_JS_AST_ARG_LIST,
                                graph,
                            )[0]

                            # 			$.post(
                            # 				GDPR.ajaxurl,
                            # 				formData,
                            requestUrlNode = getSpecificChildOfANodeByChildNo(
                                argListNode["a"][NODE_PARAMETER_ID], 0, graph
                            )

                            requestFuncNode = getSpecificChildOfANodeByChildNo(
                                argListNode["a"][NODE_PARAMETER_ID], 2, graph
                            )

                            # requestVarNode can be either a single data or an array of elements
                            requestVarNode = getSpecificChildOfANodeByChildNo(
                                argListNode["a"][NODE_PARAMETER_ID], 1, graph
                            )  # it can be eitehr array or single data

                            if requestVarNode["a"][NODE_PARAMETER_TYPE] == TAG_AST_JS_AST_ARRAY:
                                arrayVarNodes = getAllChildOfANode(
                                    requestVarNode["a"][NODE_PARAMETER_ID], graph
                                )
                                for varNode in arrayVarNodes:
                                    keyOfVarNode = getSpecificChildOfANodeByChildNo(
                                        varNode["a"][NODE_PARAMETER_ID], 0, graph
                                    )
                                    valueOfVarNode = getSpecificChildOfANodeByChildNo(
                                        varNode["a"][NODE_PARAMETER_ID], 1, graph
                                    )
                                print("if need to track individual variable")

                            else:
                                print("if need to track individual variable")
                                requestVarName = getImediateChildNode(
                                    requestVarNode["a"][NODE_PARAMETER_ID], graph
                                )["a"][
                                    NODE_PARAMETER_CODE
                                ]  # if it is single data

                if len(dataflow.path) > 0:
                    dataflow.startNode = dataflow.path[0]
                    dataflow.endNode = dataflow.path[-1]

                    dataFlows.append(dataflow)

            if nodeToExploreCode:
                if "cookie" in nodeToExploreCode.lower():
                    handleCookiesOperation()

    if len(dataFlows) > 0:
        return dataFlows

    return -1


""" auxiliary functions"""


def constructDataNode(nodeID, graph):
    """
    :param nodeID:
    :param graph:
    :return:
    """
    node = getNodeByID(nodeID, graph)
    if node != -1:
        dataNode = DataNodeJS()
        dataNode.id = node["a"][NODE_PARAMETER_ID] if node["a"][NODE_PARAMETER_ID] else 0
        dataNode.labels = (
            node["a"][NODE_PARAMETER_LABELS][0] if node["a"][NODE_PARAMETER_LABELS] else ""
        )
        dataNode.type = node["a"][NODE_PARAMETER_TYPE] if node["a"][NODE_PARAMETER_TYPE] else ""
        dataNode.flags = ""  # no data
        dataNode.lineno = 0  # no data
        dataNode.code = node["a"][NODE_PARAMETER_CODE] if node["a"][NODE_PARAMETER_CODE] else ""
        dataNode.childnum = (
            node["a"][NODE_PARAMETER_CHILDNUM] if node["a"][NODE_PARAMETER_CHILDNUM] else 0
        )
        dataNode.funcid = (
            node["a"][NODE_PARAMETER_FUNCID] if node["a"][NODE_PARAMETER_FUNCID] else 0
        )
        dataNode.classname = (
            node["a"][NODE_PARAMETER_CLASSNAME] if node["a"][NODE_PARAMETER_CLASSNAME] else 0
        )
        dataNode.name = node["a"][NODE_PARAMETER_NAME] if node["a"][NODE_PARAMETER_NAME] else ""
        dataNode.classname = ""  # no data
        dataNode.namespace = ""  # no data
        dataNode.endlineno = ""  # no data
        dataNode.doccomment = ""  # no data

        return dataNode

    return -1


# passedData = 'name=FirstLast&email=dummy@gmail.com&phone=2343221'
def handleSerialize(passedData):
    """
    :param passedData:
    :return:
    """
    tokens = passedData.split("&")
    dataList = []
    for token in tokens:
        tmp = token.split("=")
        tag = tmp[0].strip()
        val = tmp[1].strip()

        if isPIIData(tag) != -1:
            tpl = (tag, val)
            dataList.append(tpl)

    if len(dataList) > 0:
        return dataList
    return -1


def getRequestTypeOfAMethodCall(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """

    children = getSpecificChildOfANodeByType(id, TAG_AST_JS_STRING, graph)[0]
    code = children["a"][NODE_PARAMETER_CODE]
    if TAG_ACTION_TYPE_POST in code:
        return TAG_ACTION_TYPE_POST
    elif TAG_ACTION_TYPE_GET in code:
        return TAG_ACTION_TYPE_GET
    elif TAG_ACTION_TYPE_PUT in code:
        return TAG_ACTION_TYPE_PUT
    else:
        return -1


def handleCookiesOperation():
    print("cookie node found!")
    return -1


""" dataflows helper functions """


def getPIIToTrack():
    """
    :return:
    """
    piiToTrack = {
        "EMAIL": ["email", "mail"],
        "NAME": ["name"],
        "FIRST_NAME": ["firstName", "first_name", "fname"],
        "LAST_NAME": ["lastName", "last_name", "lname"],
        "USERNAME": ["username", "uname"],
        "PASSWORD": ["password", "pass", "pwd"],
        "ADDRESS": ["address", "add"],
        "COUNTRY": ["country"],
        "STATE": ["state", "st"],
        "ZIPCODE": ["zipCode", "zip", "zcode"],
        "POSTCODE": ["postCode", "pcode"],
        "CITY": ["city"],
        "COUNTY": ["county"],
        "AGE": ["age"],
        "LOCATION": ["location", "loc"],
        "BIRTH": ["birth", "birthday", "birthdate"],
        "IP": ["IP"],
    }

    return piiToTrack


def isPIIData(tag):
    """
    :param tag:
    :return:
    """

    piiToTrack = getPIIToTrack()

    for k, vals in piiToTrack.items():
        for v in vals:
            if v.lower() == tag:
                return v

    return -1


"""
if func present in the untrackable function list then don't need to traverse it. And return 1
"""


def checkUselessFunctions(func):
    """
    :param func: name of the function
    :return: 1: useless  -1: not use less
    """
    if func is None:
        return -1

    TYPE_UNTRACKABLE_HTML = 1

    func = func.lower().strip()
    htmlLst = [
        "scrollTop",
        "hide",
        "show",
        "html",
        "fadein",
        "addclass",
        "css",
        "removeclass",
        "fadeout",
        "delay",
        "slideup",
        "slidedown",
        "reload",
        "preventdefault",
        "toggleclass",
        "removeattr",
        "trigger",
        "parents",
        "remove",
        "log",
        "parent",
    ]

    for elem in htmlLst:
        if elem.lower() in func:
            return TYPE_UNTRACKABLE_HTML
    return -1


def detectPIIData(text):
    """
    :param text:
    :return: return PII or -1 when nothing found
    """
    pIIList = getPIIToTrack()
    for k, vals in pIIList.items():
        for v in vals:
            if v.lower() in text.lower():
                helperPrint("PII FOUND", v.lower())
                return v
    return -1


"""depreciated"""


def addEntryInDataflows(funcID, varName, startNode, data, dataflows):
    """
    :param funcID:
    :param varName:
    :param startNode:
    :param data:
    :param dataflows:
    :return:
    """
    tmpDict = {}
    tmpDict[TAG_VAR_NAME] = varName
    tmpDict[TAG_NODE] = [startNode]
    tmpDict[TAG_DATA] = [data]
    tmpDict[TAG_FUNCID] = funcID

    dataflows.append(tmpDict)
    return dataflows


"""depreciated"""


def updateEntryInDataflowByVarName(funcID, varName, endNode, data, dataflows):
    """
    :param funcID:
    :param varName:
    :param endNode:
    :param dataflows:
    :return:
    """
    updatedDataflows = []
    isEntryFound = False
    for dataflow in dataflows:
        if dataflow[TAG_FUNCID] == funcID and dataflow[TAG_VAR_NAME] == varName:
            dataflow[TAG_NODE].append(endNode)
            if len(data) > 0:
                dataflow[TAG_DATA] += data
            isEntryFound = True
        updatedDataflows.append(dataflow)

    if isEntryFound == False:
        updatedDataflows = addEntryInDataflows(funcID, varName, endNode, data, dataflows)

    return updatedDataflows


"""js graph helper functions"""


def getAllCFGEdgesFromClosureFuncNode(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    entryNode = getCFGEntryNode(id, graph)
    entryNodeID = entryNode["a"][NODE_PARAMETER_ID]
    cfgNodes = getControlFlowEdges(entryNodeID, graph)
    return cfgNodes


"""graph db functions"""


def getNodeByID(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (a)  
    WHERE  a.id = """
        + str(id)
        + """  
    RETURN a"""
    )
    results = graph.run(cypher=query).data()
    if len(results) > 0:
        return results[0]
    return -1


def getImediateParentNode(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (a)-[:PARENT_OF]->(b) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )
    results = graph.run(cypher=query).data()
    if len(results) > 0:
        return results[0]
    return -1


def getImediateChildNode(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:PARENT_OF]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )
    results = graph.run(cypher=query).data()
    if len(results) > 0:
        return results[0]
    return -1


def getAllChildOfANode(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:PARENT_OF]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getSpecificChildOfANodeByCode(id, code, graph):
    """
    :param id:
    :param code:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:PARENT_OF]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  and  a.code = '"""
        + str(code)
        + """' 
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results[0]
    else:
        return -1


def getSpecificChildOfANodeByType(node_id, node_type, graph):
    """
    :param id:
    :param type:
    :param graph:
    :return:
    """
    query = f"""MATCH (b{{id:{node_id}}})-[:PARENT_OF]->(a{{type:"{node_type}"}}) RETURN a"""

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getSpecificChildOfANodeByChildNo(id, childnum, graph):
    """
    :param id:
    :param type:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:PARENT_OF]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  and  a.childnum = """
        + str(childnum)
        + """
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results[0]
    else:
        return -1


def getNodesByCode(code, type, graph):
    """
    :param code:
    :param type:
    :param graph:
    :return:
    """
    query = (
        """
    match (a) where a.code = '"""
        + str(code)
        + """' 
    and a.type = '"""
        + str(type)
        + """'
    return a
    """
    )
    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getControlFlowEdges(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:FLOWS_TO*1..]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getOutgoingDDGEdges(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:REACHES]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getIncomingDDGEdges(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (a)-[:REACHES]->(b) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getVarInOutgoingReachesEdge(id, graph):

    query = (
        """MATCH (a)-[r:REACHES]->(b) 
    WHERE  a.id = """
        + str(id)
        + """  
    RETURN r"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getOutgoingCallEdges(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:CALLS]->(a) 
    WHERE  b.id = """
        + str(id)
        + """  
    RETURN a"""
    )

    results = graph.run(cypher=query).data()
    if results:
        return results
    else:
        return -1


def getCFGEntryNode(id, graph):
    """
    :param id:
    :param graph:
    :return:
    """
    query = (
        """MATCH (b)-[:ENTRY]->(a) 
     WHERE  b.id = """
        + str(id)
        + """  
     RETURN a"""
    )

    result = graph.run(cypher=query).data()
    if result:
        return result[0]
    else:
        return -1


def helperPrint(tag, value):
    print("*" * 100)
    print(tag)
    print(value)
    print("*" * 100)


"""
assumption: all the call to JAVASCRIPT will be from HTML form call
"""


def trackJSDF(idName, className, operationType, passedData):
    """
    :param className: html form class name
    :param operationType: html form operation type - submit/click
    :param passedData: this data will be seperated by &. For Example- passedData = 'name=FirstLast&email=dummy@gmail.com&phone=2343221'
    :return:
    """

    graph = getGraph()
    funcNodes = locateSourceInJS(idName, className, operationType, graph)
    if funcNodes != -1:
        dataFlows = startTraversing(funcNodes, passedData, graph)
        print("dataflows", dataFlows)

        if dataFlows != -1:
            for dataflow in dataFlows:
                dataflow.print_path()
                # helperPrint("Dataflow -> ", dataflow)


def integrateJSReachEdges(jsReachNode):

    count = 0
    graph = getGraph()
    for reachNode in jsReachNode:
        #     MATCH
        #     (charlie:Person {name: 'Charlie Sheen'}),
        #     (oliver:Person {name: 'Oliver Stone'})
        # MERGE(charlie) - [r: KNOWS]-(oliver)
        # RETURN
        # r

        query = """
        
        MATCH (n:AST)-[:REACHES]->(m)
        WITH n, m
        MATCH (n)-[:PARENT_OF*0..]->(nChild:AST{type:"AST_VAR"})-[:PARENT_OF]->(nName:AST{childnum:0, type:"string"})
        MATCH (m)-[:PARENT_OF*0..]->(mChild:AST{type:"AST_VAR"})-[:PARENT_OF]->(mName:AST{childnum:0, type:"string"})
        WHERE nName.code = mName.code
        WITH nChild, mChild, nName.code as relVarName
        MERGE (nChild)-[r:JS_REACHES{varName:relVarName}]->(mChild)
        RETURN COUNT(r)
        """
        count = graph.evaluate(query)


def run():

    idName = ""
    className = ".gdpr-privacy-preferences-frm"
    operationType = "submit"
    passedData = "name=FirstLast&email=dummy@gmail.com&phone=2343221"

    idName = ""
    # className = '.gdpr-reassign-content'
    # operationType = 'submit'
    # passedData = 'name=FirstLast&email=dummy@gmail.com&phone=2343221'
    jsReachNode = locateSourceInJS(idName, className)
    integrateJSReachEdges(jsReachNode)

    trackJSDF(idName, className, operationType, passedData)

    return 0


if __name__ == "__main__":
    # d = getVarInOutgoingReachesEdge(31688, getGraph())
    # print(d[0]['r']['var'])

    start_time = time.time()
    run()
    print("--- Total time for the execution %s seconds ---" % (time.time() - start_time))
