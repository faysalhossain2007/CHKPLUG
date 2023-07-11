# GDPR Checker project
# Written and maintained by Jerry Su
#This file is rewritten to contain functions that trace data flows by Neo4j node IDs.

import logging
import re
from traceback import print_exc
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

#from ActionHook import ActionHook
#from DataFlows import ALL_PATHS, DataFlowGraph, DataFlowPath, DataNode

from Errors import SourceDetectorException
from NeoGraph import getGraph
# from NeoHelper import (
#     ASTAssignGetName,
#     ASTMethodGetParameterList,
#     SQLInfo,
#     SQLParentNodeOperations,
#     concatTree,
#     getASTCallName,
#     getASTMethodName,
#     getNode,
#     getNodeName,
#     getNodeType,
#     getRootOfLine,
#     getStatementSQLInfo,
# )

#from SourceDetector import DATABASE_DELETE_API, DATABASE_STORE_API, SourceDetector
from Utls import progress_bar



"""
API_CONST stores the keywords for searching APIs for deleting data. It includes 1) Database Queries 2) Wordpress APIs 3) HTML requests
"""
API_CONST = ["delete_meta_data", "delete_post_meta", "delete_user_meta", "delete"]

# Note: anonymize data+update data also works
UNWANTED_SINKS: List[str] = [""]
USELESS_SINK_TYPE: List[str] = [
    "AST_UNARY_OP",
    "AST_BINARY_OP",
    "AST_EMPTY",
    "AST_INSTANCEOF",
]

#These types define all traversal types we want to trace
RELATIONSHIP_TYPES = ["PHP_REACHES", "HTML_REACHES","STORE_REACHES","PHP_TO_HTML_REACHES","JS_REACHES","JS_TO_PHP_REACHES","HTML_TO_PHP_REACHES","PHP_TO_JS_REACHES","HTML_TO_JS_REACHES"]

ERROR_FRINGE = ("", None)

# used for linear programming. format: {(sourceID,varName):[path1,path2,...]}
#storePath: Dict[Tuple[int, str], List[DataFlowPath]] = dict()

# Keep track of traverseStorage end points to prevent infinite loops.
__STORAGE_TRAVERSAL_TRAVELLED: Dict[Tuple[int, str], int] = dict()
maxTraversalLength = 15

#dataflowGraph = DataFlowGraph()
sources = []
def allTraversalTypeAPOC():
    return ">|".join(RELATIONSHIP_TYPES)+">"

def allTraversalType():
    return ":"+"|".join(RELATIONSHIP_TYPES)

def getMaxTraversalLength():
    return f"*0..{maxTraversalLength}"

def hasDataflowPath(nodeID1,nodeID2):
    """
    Check if there exists a dataflow path from node 1 to node 2
    """
    graph = getGraph()
    query = f"""
    MATCH p = shortestPath((n{{id:{nodeID1}}})-[{allTraversalType()}*]->(m{{id:{nodeID2}}}))
    RETURN p
    """
    result = graph.evaluate(cypher=query)
    if result:
        return True
    return False

def getSources(nodeID:int,no_constraint=False):
    """
    Track a node until it cannot be backtraced any further.
    Returns a list of dicts of the traced nodes.
    """
    graph = getGraph()
    query = None
    if no_constraint:
        query = f"""
        MATCH p=((n:AST)-[{allTraversalType()}*]->(m:AST{{id:{nodeID}}}))
        WHERE NOT ()-[{allTraversalType()}]->(n)
        RETURN n ORDER BY length(p) ASC
        """
    else:
        query = f"""
        MATCH p=((n:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(m:AST{{id:{nodeID}}}))
        WHERE NOT ()-[{allTraversalType()}]->(n)
        RETURN n ORDER BY length(p) ASC
        """
    result = graph.run(cypher=query).data()
    sources = []
    if result:
        for r in result:
            sources.append(r['n'])
    return sources

def getSinks(nodeID:int):
    """
    Track a node until it cannot be traced forward any further.
    Returns a list of dicts of the traced nodes.
    """
    graph = getGraph()
    query = f"""
    MATCH p=((n:AST{{id:{nodeID}}})-[{allTraversalType()}{getMaxTraversalLength()}]->(m:AST))
    WHERE NOT (m)-[{allTraversalType()}]->()
    RETURN m ORDER BY length(p) ASC
    """
    result = graph.run(cypher=query).data()
    sinks = []
    if result:
        for r in result:
            sinks.append(r['m'])
    return sinks
def reverseTrackDataFlowToAssignNoRecord(nodeID:int):
    """
    Track variable until it reaches where the variable is assigned. Returns the assignee. Does not record the node or the path in the dataflow graph.
    """
    graph = getGraph()
    query = f"""
    MATCH p=((n:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(m:AST{{id:{nodeID}}}))
    WHERE (n)<-[:PARENT_OF]-({{type:'AST_ASSIGN'}}) AND n.childnum = 1
    RETURN n ORDER BY length(p) ASC LIMIT 1
    """
    rst = graph.run(cypher=query).data()
    if rst:
        return rst[0].get('n',None)
    else:
        return None
def reverseTrackDataFlowToParamORAssignNoRecord(nodeID:int,q=None):
    """
    Track variable until it reaches where the variable is assigned or the parameter in a function declaration. Returns the assignee ID or the parameter ID, whichever has shorter data flow path to the given node. Does not record the node or the path in the dataflow graph.
    """
    graph = getGraph()
    query = f"""
    MATCH p=((n:AST)-[:PHP_REACHES{getMaxTraversalLength()}]->(m:AST{{id:{nodeID}}}))
    WHERE (n)<-[:PARENT_OF]-({{type:'AST_ASSIGN'}}) AND n.childnum = 1
    RETURN length(p) AS len,n ORDER BY length(p) ASC LIMIT 1
    """
    result = graph.run(cypher=query).data()
    query2 = f"""
    MATCH p=((n:AST{{type:'AST_PARAM'}})-[:PHP_REACHES{getMaxTraversalLength()}]->(m:AST{{id:{nodeID}}}))
    WHERE n.funcid = m.funcid
    RETURN length(p) AS len,n ORDER BY length(p) ASC LIMIT 1
    """
    result2 = graph.run(cypher=query2).data()

    returnValue = [None,None]
    #if we can find data flow path to both a param and an assign, we compare which one has shorter path
    if result and result2:
        #return [result[0]['len'],result2[0]['len']]
        if result[0]['len']>result2[0]['len']:
            returnValue = ['Param',result2[0]['n']]
        else:
            returnValue = ['Assign',result[0]['n']]
    
    #else, just return whichever gives a valid result.
    elif result:
        #return [result[0]['len'],None]
        returnValue = ['Assign',result[0]['n']]
    elif result2:
        #return [None,result2[0]['len']]
        returnValue = ['Param',result2[0]['n']]
    if q:
        q.put(returnValue)
    else:
        return returnValue


def coverAllDataFlows():
    pass


def trackDataFlow(sourceList: List[Union[str, None]]):
    """Main method to track data flows. Prints all of the sinks that it finds.

    Args:
            sourceList (List[Union[str, None]]): a list of source types
    """
    pass

    # allPath = []

    # for sourceType in sourceList:
    #     print("=Finding sources of type: "+str(sourceType))
    #     try:
    #         allSource = SourceDetector.locateSource(sourceType)
    #     except SourceDetectorException as e:
    #         # Catch fatal errors or exceptions that otherwise halt the program.
    #         print_exc()
    #         allSource = []
    #         return
    #     print(f"=Total of {len(allSource)} source located")
    #     logging.info(f"Total of {len(allSource)} source located")
    #     print("=Tracking dataflows...")
    #     for s in progress_bar(allSource):
    #         # All source nodes have to contain personal data
    #         if s.personal != "other":
    #             sources.append(s)
    #             trackDataFlowFromNode(s)


def reverseTrackDataFlow(sinkList):
    """Main method to reversely track data flows. Prints all of the sources that corresponds to the given nodes.

    Args:
            sinkList (list of DataNode objects): a list of sink nodes that we want to trace back.
    """

    logging.info(f"Total of {len(sinkList)} sinks supplied.")
    for k in sinkList:
        reverseTrackDataFlowFromNode(k)


def trackDataFlowFromNode(sourceNodeID:int):
    """Track variable until it reaches all the sinks
    Argument:
            sourceNode: source node, of type DataNode. The node corresponds to an AST node in Neo4j, which can be of type:
            AST_VAR, AST_PARAM, AST_CALL, AST_RETURN
    Output:
            a list of all paths, of type DataFlowPath
    """
    pass
    # DP: used a previously stored path with
    # DP: if the search is in progress, the stored value is -1
    # if
    # 	logging.info("Returned a stored path")
    # 	return copy.deepcopy(storePath[(sourceNode.id,sourceNode.varName)])
    # logging.info(f"Started tracking node from source with id {sourceNode.id} and name {sourceNode.varName}")
    
    # fringes = [sourceNode]
    # # visitedID = set()
    # dataflowGraph.insertNode(sourceNode)
    # sinks = []
    # depth = 0
    # while fringes:
    #     print("At depth: "+str(depth))
    #     currentFringe = fringes.pop(0)
    #     newFringe = getNewFringe(currentFringe)
    #     if not newFringe and currentFringe.id in dataflowGraph.nodes:
    #         sinks.append(currentFringe)
    #     elif newFringe:
    #         fringes.extend(newFringe)
    #     depth+=1
    # return sinks

    # logging.info(f"Finished tracking node from source with id {sourceNode.id} and name {sourceNode.varName}")
    # storePath[(sourceNode.id,sourceNode.varName)] = copy.deepcopy(paths)
    # return paths


def reverseTrackDataFlowFromNode(sinkNodeID, traceVariableAssignedLocation=False):
    """Track variable until it reaches all the sources
    Argument:
            sinkNode: sink node, of type DataNode
    Output:
            a list of all paths from source to the sink nodes, of type DataFlowPath
    """

    pass



"""(deprecated) Helper function: get a list of labels for all visited nodes
Argument:
	currentVariableID: the list of current variable IDs
	newVariableID: the list of new variable IDs (new fringe)
Output:
	visited: labels of 0s and 1s for respective variables in the newVariableID. 
	0 means that the variable has not been visited. 1 means that the variable has been visited
"""


def checkVisited(visitedID, newVariableID):
    visited = []
    for i in newVariableID:
        # does not compare at specific index because variable orders might be different
        if i in visitedID:
            visited.append(1)
        else:
            visited.append(0)
    return visited


"""Traverse through one node 
Input:
	fringe: a node that we want to traverse through (DataNode object)
Output:
	a list of node id for new fringes for the variable we are tracking. Changes nothing if all nodes reach their sinks.
	Multiple situations: AST_METHOD_CALL, AST_ASSIGN, AST_CALL, AST_STATIC_CALL, AST_PARAM
	Sinks: AST_CALL
	Special case: encode add_action 
	order of the parameters passed into a function? use id to get the order.
"""


# def getNewFringe(fringe: DataNode):
#     # logging.info(f"getNewFringe for paths starting at {paths[0].head.id} with name {paths[0].head.varName}")
#     if not SECURITY_DETECTOR_MANAGER:
#         raise Exception("Security detector manager not initialized")

#     graph = getGraph()
#     security_finding = SECURITY_DETECTOR_MANAGER.lookup_node_id(fringe.id)
#     for finding in security_finding:
#         SECURITY_USES.add(fringe.id)
#         SECURITY_MAP_USES_TO_FINDINGS[fringe.id] = finding
#         SECURITY_DETECTOR_MANAGER.mark_as_found(finding)
#     # if the node has been traversed before and is in the graph, then return *nothing to prevent infinite loop

#     if fringe.id in dataflowGraph.edges:
#         return []
#         newfringes = []
#         allEdge = dataflowGraph.edges[fringe.id]

#         for edge in allEdge:
#             newfringes.append(dataflowGraph.nodes[edge])
#         return newfringes

#     newfringes = []
#     # check PHP reaches:
#     PHPreachQuery = f"""
# 	MATCH (n)-[r:PHP_REACHES]->(m)
# 	WHERE n.id = {fringe.id}
# 	RETURN r.varName, m.id, m.classname
# 	"""
#     PHPreachResult = graph.run(cypher=PHPreachQuery).data()
#     if PHPreachResult:
#         for resultTemp in PHPreachResult:
#             # update varName if it is wrongly set before. Also
#             if resultTemp["r.varName"] != dataflowGraph.nodes[fringe.id].varName:
#                 dataflowGraph.nodes[fringe.id].varName = resultTemp["r.varName"]
#                 # dataflowGraph.nodes[fringe.id].setPersonal(
#                 #     isPersonalString(resultTemp["r.varName"])
#                 # )
#             # here we don't know the varName of the next node, so we assume it's the same as the current node (and so it's the same personal data type as well)
#             tempDataNode = DataNode(resultTemp["m.id"], dataflowGraph.nodes[fringe.id].varName)
#             tempDataNode.personal = fringe.personal
#             # if resultTemp["m.classname"]:
#             #     tempDataNode.admin = ActionHook.isAdminClass(resultTemp["m.classname"])

#             dataflowGraph.insertNode(tempDataNode)
#             dataflowGraph.insertEdge(fringe, tempDataNode)
#             newfringes.append(tempDataNode)

#     # integrate HTML Reaches and others

#     return newfringes


# def getPreviousFringe(fringe: DataNode) -> List[DataNode]:
#     # logging.info(f"getPreviousFringe for paths ending at {paths[0].tail.id} with name {paths[0].tail.varName}")

#     graph = getGraph()

#     newfringes = []
#     # check PHP reaches:
#     query = f"""
# 	MATCH (n)-[r:PHP_REACHES]->(m{{id:{fringe.id}}})
# 	RETURN COLLECT(DISTINCT [n.id, r.varName, m.classname])
# 	"""
#     result = graph.evaluate(query)
#     if not result:
#         return []
#     for n_id, r_varname, m_classname in result:
#         # Update varName if it is wrongly set before
#         dn = DataNode(n_id, r_varname)
#         # dn.personal = (
#         #     fringe.personal if dn.varName == fringe.varName else isPersonalString(dn.varName)
#         # )

#         # if m_classname:
#         #     dn.admin = ActionHook.isAdminClass(m_classname)
#         dataflowGraph.insertNode(dn)
#         dataflowGraph.insertEdge(dn, fringe)
#         newfringes.append(dn)

#     # Integrate HTML Reaches and others

#     return newfringes

#     # handle AST_METHOD_CALL, AST_STATIC_CALL here

#     # fringeType = reverseClassifyFringe(fringe)
#     # if fringeType[0] == 'USELESS':
#     # 	dataflowGraph.deleteNode(fringe)
#     # 	return False

#     # elif fringeType[0] == 'PARAM':

#     # 	previousNodes = ASTParamGetPrevious(fringe)
#     # 	for previousNodeTemp in previousNodes:
#     # 		dataflowGraph.insertNode(previousNodeTemp)
#     # 		dataflowGraph.insertEdge(previousNodeTemp,fringe)
#     # 	return previousNodes

#     # elif fringeType[0] == 'REACH_NO_ASSIGN':

#     # 	result = fringeType[1]
#     # 	container = fringe.container
#     # 	newfringes = []
#     # 	for tempNode in result:

#     # 		#This would mean that the variable name is not changed
#     # 		if verifyReachNode(fringe.varName,tempNode['n']['id'],container=container):
#     # 			newNode = DataNode(tempNode['n']['id'],fringe.varName)
#     # 			newNode.personal = fringe.personal
#     # 			newNode.admin = fringe.admin

#     # 			dataflowGraph.insertNode(newNode)
#     # 			dataflowGraph.insertEdge(newNode,fringe)
#     # 			newfringes.append(newNode)
#     # 	return newfringes

#     # #This means that the current node is an AST_ASSIGN and the variable name has likely changed
#     # elif fringeType[0] == 'REACH_ASSIGN':
#     # 	result = fringeType[1]
#     # 	allPassInVarName = ASTAssignGetPassInVar(fringe.id)
#     # 	newfringes = []
#     # 	for tempNode in result:
#     # 		#current assign var can flow from multiple previous vars. We need to verify which var tempNode is
#     # 		verifyReach = verifyMultipleReachNode(allPassInVarName,tempNode['n']['id'])
#     # 		if verifyReach:
#     # 			newNode = DataNode(tempNode['n']['id'],verifyReach)
#     # 			newNode.personal = fringe.personal
#     # 			newNode.admin = fringe.admin

#     # 			dataflowGraph.insertNode(newNode)
#     # 			dataflowGraph.insertEdge(newNode,fringe)
#     # 			newfringes.append(newNode)
#     # 	return newfringes
#     # elif fringeType[0] == 'SOURCE':
#     # 	#Do nothing if we reach a source
#     # 	return False


# def getAllPreviousFringes(fringe: DataNode) -> Tuple[Set[int], List[DataNode]]:
#     graph = getGraph()

#     newfringes = []
#     # check PHP reaches:
#     query = f"""
# 	MATCH p=(s)-[:PHP_REACHES|STORE_REACHES*]->(e{{id:{fringe.id}}})
# 	UNWIND relationships(p) as r
# 	WITH s, r ORDER BY endNode(r).id DESC
# 	RETURN COLLECT(DISTINCT s.id), COLLECT(DISTINCT [startNode(r), r.varName, endNode(r)])
# 	"""
#     result = graph.run(query)
#     if not result:
#         return (set(), list())

#     sources = set()
#     for result in result:
#         if not result:
#             continue
#         s, rels = result
#         sources.update(s)
#         for start, varname, end in rels:
#             start = dict(start)
#             end = dict(end)

#             # Update varName if it is wrongly set before
#             start_data_node = dataflowGraph.nodes.get(start["id"], DataNode(start["id"], varname))
#             end_data_node = dataflowGraph.nodes.get(
#                 end["id"], DataNode(end["id"], concatTree(end["id"]))
#             )

#             # start_data_node.personal = (
#             #     fringe.personal
#             #     if start_data_node.varName == fringe.varName
#             #     # else isPersonalString(start_data_node.varName)
#             # )
#             # if end.get("classname", ""):
#             #     start_data_node.admin = ActionHook.isAdminClass(end.get("classname", ""))

#             dataflowGraph.insertNode(start_data_node)
#             dataflowGraph.insertNode(end_data_node)
#             dataflowGraph.insertEdge(start_data_node, end_data_node)
#             newfringes.append(start_data_node)

#     return sources, newfringes


"""Deprecated
Input:
	fringe: the current fringe
	innerCallNode: after traversing through REACHES, we find a method/function call within the reached line of code that involves the fringe. The innercallnode is the call.
Output:
	returns a list of all sinks in the middle
"""


# def interPath(fringe, innerCallNode):
#     logging.info("start interpath")

#     newVar = ASTCallGetNext(innerCallNode.varName, innerCallNode.id)
#     if newVar == -1:
#         dataflowGraph.insertNode(innerCallNode)
#         dataflowGraph.insertEdge(fringe, innerCallNode)
#         return [innerCallNode]
#     elif newVar == -2:
#         return []
#     dataflowGraph.insertNode(innerCallNode)
#     dataflowGraph.insertEdge(fringe, innerCallNode)
#     dataflowGraph.insertNode(newVar)
#     dataflowGraph.insertEdge(innerCallNode, newVar)
#     allSinks = trackDataFlowFromNode(newVar)
#     logging.debug(
#         f"trackDataflowFromNode returns within interPath() for nodes starting at {innerCallNode.id}"
#     )

#     returnSinks = []
#     for i in allSinks:
#         # data goes back
#         if i.getType() == "AST_RETURN":
#             returnSinks.append(i)
#         # data cannot be tracked to go back

#     logging.info("end interpath")
#     return returnSinks


"""(deprecated) Verify if a variable appears in a given line identified by nodeID

"""


def verifyReachNode(varName: str, nodeID: int, container=None):
    if not varName or varName == "None":
        return False

    graph = getGraph()
    if not container:
        queryVerify = f"""
		MATCH (n:AST)-[:PARENT_OF*1..]->(var:AST)-[:PARENT_OF]->(name:AST)
		WHERE n.id = {nodeID} AND var.type = 'AST_VAR' AND name.type = 'string' AND name.code = '{varName}'
		RETURN var
		"""
        verifyResult = graph.run(cypher=queryVerify).data()
        if verifyResult:
            return True
        else:
            return False
    else:
        queryVerify = f"""
		MATCH (n:AST)-[:PARENT_OF*1..]->(temp:AST) WHERE n.id = {nodeID} AND temp.type in ['AST_DIM','AST_PROP']
		WITH temp
		MATCH (varName)<-[:PARENT_OF]-(temp)-[:PARENT_OF]->(var:AST)-[:PARENT_OF]->(container:AST)
		WHERE  var.type = 'AST_VAR' AND varName.type = 'string' AND container.type = 'string' AND container.code = '{container}' AND varName.code = '{varName}'
		RETURN varName,container
		"""
        verifyResult = graph.run(cypher=queryVerify).data()
        if verifyResult:
            return True
        else:
            return False


# (deprecated) varNameList is a list of possible varNames
def verifyMultipleReachNode(varNameList, nodeID):

    graph = getGraph()
    for varName in varNameList:
        queryVerify = f"""
		MATCH (n:AST)-[:PARENT_OF*1..]->(var:AST)-[:PARENT_OF]->(name:AST)
		WHERE n.id = {nodeID} AND var.type = 'AST_VAR' AND name.type = 'string' AND name.code = '{varName}'
		RETURN var
		"""
        verifyResult = graph.run(cypher=queryVerify).data()
        if verifyResult:
            return varName

    return False


# def classifySink(node: DataNode):
#     if node.getType() == "AST_CALL":
#         methodName = getASTMethodName(node.id)
#         if methodName and "eraser" in methodName:
#             print("A Potential deletion method: ")
#             printNodeInfo(node.id)
#         if node.getCallName() in DATABASE_STORE_API:
#             return "DB_STORE"
#         elif node.getCallName() in DATABASE_DELETE_API:
#             return "DB_DELETE"
#     elif node.getType() in USELESS_SINK_TYPE:
#         return "USELESS"
#     else:
#         return "OTHER"


"""(deprecated)
Input:
	node: a DataNode object
Output:
	1: fringe type (note that they are mutually exclusive)
			a) CALL: AST_METHOD_CALL or AST_STATIC_CALL
			b) REACH: node that reaches another node
			c) UPDATE_OPTION: wordpress update_option() call
			d) SINK: a data flow sink
	2: (optional) specific query data. None if no data is present.
"""

###Faysal: implement
###Read the current implementations below. You need to decide if you just need
###the current node information to classify it, or need to do some more Neo4j query to classify it.
###Find a suitable place to return your classification in the format [type,(optional data)]
# def classifyFringe(node: DataNode) -> Tuple[str, Optional[Iterable[Any]]]:
#     # if it is a variable, need to track where it is retrieved
#     graph = getGraph()
#     if useless(node):
#         return ("USELESS", None)

#     # Validate input.
#     if isinstance(node, DataNode):
#         node_id, node_var_name = node.to_path_repr()
#     # else:
#     # 	# Unpack tuple.
#     # 	node_id, node_var_name = node
#     node_type = getNodeType(node_id)

#     if node_type == "AST_METHOD_CALL" or node_type == "AST_STATIC_CALL":
#         return ("CALL", None)
#     elif node_type == "AST_CALL":
#         call_name = getASTCallName(node_id)
#         if not call_name:
#             logging.warning(f"Error! AST_CALL has no name! Node ID: {node_id}")
#             return ERROR_FRINGE
#         if call_name == "update_option":
#             query = f""" 
# 			MATCH (n)-[:PARENT_OF]->(x)-[:PARENT_OF]->(m) 
# 			WHERE n.id = {node_id} AND x.type = 'AST_ARG_LIST' AND m.childnum = 0
# 			RETURN m.code
# 			"""
#             result = graph.evaluate(query)
#             # get the parameter of the update_option call
#             return ("UPDATE_OPTION", result)
#         elif call_name == "do_action":
#             query = f""" 
# 			MATCH (n)-[:PARENT_OF]->(x)-[:PARENT_OF]->(m) 
# 			WHERE n.id = {node_id} AND x.type = 'AST_ARG_LIST' AND m.childnum = 0
# 			RETURN m.code
# 			"""

#             result = graph.run(cypher=query).data()
#             return ("DO_ACTION", result[0]["m.code"])

#         #!!!!!!!!!!!For Patrick: handle all storage nodes here
#         # classify the storage nodes and find the corresponding key

#         # if callName=='update_option':
#         # 	query1 = f"""
#         # 	MATCH (n)-[:PARENT_OF]->(x)-[:PARENT_OF]->(m)
#         # 	WHERE n.id = {str(node.id)} AND x.type = 'AST_ARG_LIST' AND m.childnum = 0
#         # 	RETURN m.code
#         # 	"""
#         # 	result1 = graph.run(cypher = query1).data()
#         # 	#get the parameter of the update_option call
#         # 	return ['UPDATE_OPTION',result1[0]['m.code']]
#         elif isStorage(node):
#             return ("STORAGE", None)
#         else:
#             return ("SINK", None)

#     # This both checks the fringe type and gets the necessary data.
#     query = f""" MATCH (n)-[:REACHES]->(m) WHERE n.id = {node_id} RETURN COLLECT(m)"""
#     result = graph.evaluate(query)
#     if result and len(result) > 0:  # type: ignore
#         l = [dict(r) for r in result]
#         return ("REACH", l)
#     else:
#         # It's not a call nor has any reaches edges, so by default it's a sink
#         return ("SINK", None)


# def isStorage(node: DataNode) -> bool:
#     """Return if the node is a storage node (Wordpress Call, SQL Call, Wordpress user object, etc)

#     Args:
#             node (DataNode): DataNode to test.

#     Returns:
#             bool: True if the node is a storage node, false otherwise.
#     """
#     # Make sure that the DataNode is not actually a ID, var name pair
#     assert isinstance(node, DataNode)
#     findings = node.getAllFindings()
#     sql_info = getStatementSQLInfo(node.id)
#     is_sql_storage: bool = bool(
#         sql_info
#         and sql_info.start_id > 0
#         and ("AST_SQL_INSERT" in sql_info.operations or "AST_SQL_UPDATE" in sql_info.operations)
#     )

#     # Process the findings.
#     return bool(findings) and any([f.score.is_storage() for f in findings]) or is_sql_storage


# def traverseStorage(node: DataNode) -> List[DataNode]:
#     """Return a list of nodes that potentially retrieves data stored by the given storage node 'node'

#     The 'personal' field of the new nodes to be the same as the 'personal' field of 'node'.

#     Args:
#             node (Union[DataNode, Tuple[int, str]]): DataNode to traverse. Either a DataNode object or a node ID, varname pair.

#     Returns:
#             List[DataNode]: a list of DataNode objects that potentially retrieves data stored by the given storage node 'node'
#     """
#     if not SECURITY_DETECTOR_MANAGER:
#         raise Exception("SECURITY_DETECTOR_MANAGER is not initialized.")

#     # Make sure that the DataNode is not actually a ID, var name pair
#     assert isinstance(node, DataNode)

#     # Get the storage node since it contains information on what is stored in the node.
#     findings = node.getAllFindings()
#     sql_info = getStatementSQLInfo(node.id)

#     # Get the modified data types from the storage call.
#     modified_types: Set[str] = set()
#     for f in findings:
#         modified_types.update(f.score.get_data_types())

#     # Exit if incomplete.
#     if not modified_types and (not sql_info or (not sql_info.table_name and not sql_info.fields)):
#         return []

#     # Now look for retrieval nodes of the same type.
#     possible_retrievers: Set[int] = set()
#     for f in SECURITY_DETECTOR_MANAGER.allFindings:
#         if f.score.is_retrieval() and f.score.matches_data_type(modified_types):
#             possible_retrievers.add(f.node["id"])
#             __STORAGE_TRAVERSAL_TRAVELLED[node.to_path_repr()] = f.node["id"]

#     if sql_info:
#         select_statements: List[int] = [
#             i for i, o in SQLParentNodeOperations.items() if "AST_SQL_SELECT" in o
#         ]
#         for i in select_statements:
#             select_sql_info = getStatementSQLInfo(i)
#             if not select_sql_info:
#                 continue
#             if SQLInfo.table_equals(select_sql_info, sql_info) and SQLInfo.field_equals(
#                 select_sql_info, sql_info
#             ):
#                 possible_retrievers.add(i)

#     # Convert nodes to new DataNodes and return built list of nodes.
#     newNodes: List[DataNode] = []
#     for r in possible_retrievers:
#         newNode = DataNode(r, node.varName)
#         newNode.personal = node.personal
#         tempNode = newNode.getNode()
#         # try:
#         #     if tempNode["classname"]:
#         #         newNode.admin = ActionHook.isAdminClass(tempNode["classname"])
#         # except:
#         #     pass
#         newNodes.append(newNode)

#     return newNodes


# def isRetrieval(node: DataNode) -> bool:
#     """Return if the node is a data retrieval node (Wordpress Call, SQL Call, Wordpress user object, etc)

#     Args:
#             node (DataNode): DataNode to test.

#     Returns:
#             bool: True if the node is a storage node, false otherwise.
#     """
#     # Make sure that the DataNode is not actually a ID, var name pair
#     assert isinstance(node, DataNode)
#     findings = node.getAllFindings()
#     sql_info = getStatementSQLInfo(node.id)
#     sql_is_retrieval = bool(sql_info and "AST_SQL_SELECT" in sql_info.operations)

#     # Process the findings.
#     return bool(findings and any([f.score.is_retrieval() for f in findings])) or sql_is_retrieval


# def reverseTraverseRetrieval(node: DataNode) -> List[DataNode]:
#     """Return a list of nodes that potentially stores data retrieved by the given storage node 'node'

#     The 'personal' field of the new nodes to be the same as the 'personal' field of 'node'.

#     Args:
#             node (DataNode): DataNode to reverse search.

#     Raises:
#             Exception: Raised if security detector is not initialized.

#     Returns:
#             List[DataNode]: A list of DataNode objects that potentially stores data retrieved by the given storage node 'node'.
#     """
#     if not SECURITY_DETECTOR_MANAGER:
#         raise Exception("SECURITY_DETECTOR_MANAGER is not initialized.")

#     # Make sure that the DataNode is not actually a ID, var name pair
#     assert isinstance(node, DataNode)

#     # Get the storage node since it contains information on what is stored in the node.
#     findings = node.getAllFindings()
#     sql_info = getStatementSQLInfo(node.id)

#     # Get the modified data types from the storage call.
#     modified_types: Set[str] = set()
#     for f in findings:
#         modified_types.update(f.score.get_data_types())

#     # Exit if incomplete.
#     if not modified_types and (not sql_info or (not sql_info.table_name and not sql_info.fields)):
#         return []

#     # Now look for retrieval nodes of the same type.
#     possible_storage: Set[int] = set()
#     for f in SECURITY_DETECTOR_MANAGER.allFindings:
#         if f.score.is_storage() and f.score.matches_data_type(modified_types):
#             possible_storage.add(f.node["id"])
#             __STORAGE_TRAVERSAL_TRAVELLED[node.to_path_repr()] = f.node["id"]

#     if sql_info:
#         select_statements: List[int] = [
#             i
#             for i, o in SQLParentNodeOperations.items()
#             if "AST_SQL_INSERT" in o or "AST_SQL_UPDATE" in o
#         ]
#         for i in select_statements:
#             modifying_sql_info = getStatementSQLInfo(i)
#             if not modifying_sql_info:
#                 continue
#             if SQLInfo.table_equals(modifying_sql_info, sql_info) and SQLInfo.field_equals(
#                 modifying_sql_info, sql_info
#             ):
#                 possible_storage.add(i)

#     # Convert nodes to new DataNodes and return built list of nodes.
#     newNodes: List[DataNode] = []
#     for r in possible_storage:
#         newNode = DataNode(r, node.varName)
#         newNode.personal = node.personal
#         tempNode = newNode.getNode()
#         # try:
#         #     if tempNode["classname"]:
#         #         newNode.admin = ActionHook.isAdminClass(tempNode["classname"])
#         # except:
#         #     pass
#         newNodes.append(newNode)

#     return newNodes


# def reverseClassifyFringe(node):
#     """
#     Input:
#             node: a DataNode object
#     Output:
#             1: fringe type (note that they are mutually exclusive)
#                             a) CALL: AST_METHOD_CALL or AST_STATIC_CALL
#                             b) REACH: node that reaches another node
#                             c) UPDATE_OPTION: wordpress update_option() call
#                             d) SINK: a data flow sink
#             2: (optional) specific query data. None if no data is present.
#     """

#     # if it is a variable, need to track where it is retrieved
#     graph = getGraph()
#     nodeType = node.getType()
#     if useless(node):
#         return ["USELESS", None]
#     if nodeType == "AST_PARAM":
#         return ["PARAM", None]
#     query2 = """ MATCH (n)-[:REACHES]->(m) WHERE m.id = """ + str(node.id) + """ RETURN n"""
#     result2 = graph.run(cypher=query2).data()
#     if len(result2) > 0:
#         if nodeType == "AST_ASSIGN":
#             return ["REACH_ASSIGN", result2]
#         else:
#             return ["REACH_NO_ASSIGN", result2]
#     else:
#         return ["SOURCE", None]


# def useless(node: DataNode) -> bool:
#     """
#     If the node is not worth investigating further, returns False
#     """
#     nodeType = getNodeType(node.id)
#     return nodeType in USELESS_SINK_TYPE


# def ASTCallGetNext(variableName, nodeID):
#     """Used to traverse over method calls (deprecated)
#     Input:
#             variableName: the current variable name
#             nodeID: node ID for a node of type AST_METHOD_CALL
#     Output:
#             Returns the node ID of the AST_METHOD that the current node calls, as well as the new variable name in the next function
#             error code -1: stops at the current node because the method cannot track the method node.
#             error code -2: the current node should be discarded because it's a wrong tracking.
#     """
#     graph = getGraph()

#     if not variableName == "None" or not variableName or variableName == "":

#         query2 = f"""
# 		MATCH (node:AST)-[:PARENT_OF]->(arglist:AST)-[:PARENT_OF]->(arg:AST)-[:PARENT_OF*0..3]->(var:AST)-[:PARENT_OF]->(name:AST)
# 		WHERE node.id = {str(nodeID)} AND arglist.type = 'AST_ARG_LIST' AND var.type = 'AST_VAR' AND name.type = 'string' AND name.code = '{variableName}'
# 		RETURN arg.childnum
# 		"""
#         result2 = graph.run(cypher=query2).data()
#         if not result2:

#             # it is possible that the object contains the data. Currently not tracking
#             logging.debug(
#                 "Data is not passed through parameters or variable is not matched correctly in the param list! Handle this case. "
#             )
#             logging.debug(f"node ID: {str(nodeID)}  variable name: {variableName}")
#             # should return -2 because the method call may not contain the data we are tracking (wrong matching). We ignore the case where data is stored in the object here.
#             return -2
#         elif len(result2) == 1:
#             varIndex = result2[0]["arg.childnum"]
#             query = f"""
# 			MATCH (n:AST)-[:CALLS]->(m:AST) WHERE n.id = {str(nodeID)}
# 			RETURN m.id LIMIT 1
# 			"""
#             result = graph.evaluate(query)

#             if not result:
#                 logging.debug("AST Method not found. The method is out of bound of this plugin")
#                 # return -1. Keep the current fringe as the sink.
#                 return -1
#             params = ASTMethodGetParameterList(result)
#             if not params:
#                 return -1
#             paramName, paramList = params

#             nodeID = paramList[varIndex]
#             varName = paramName[varIndex]
#             funcName = getNodeName(getNode(paramList[varIndex])["funcid"])
#             nodeType = getNodeType(paramList[varIndex])
#             nextNode = None
#             previousNode = None

#             return DataNode(nodeID, varName, funcName, nodeType, nextNode, previousNode)

#         else:
#             logging.debug(
#                 "Data is in more than one parameters! Handle this case. node ID: " + str(nodeID)
#             )
#             return -1
#     else:
#         logging.debug("The variable name is not defined. Check out the details here: ")
#         logging.debug(f"Variable name: {variableName}. Node ID: {nodeID}")
#         return -2


"""(deprecated)
"""


# def ASTParamGetPrevious(node: DataNode):

#     graph = getGraph()

#     allPossiblePreviousNode = []
#     nodeChildnum = node.getChildnum()
#     funcID = node.getFuncID()

#     query = f"""
# 	MATCH (n)<-[:CALLS]-(m) WHERE n.id = {funcID} 
# 	WITH m
# 	MATCH (m)-[:PARENT_OF]->(x)-[:PARENT_OF]->(y)
# 	WHERE x.type = 'AST_ARG_LIST' AND y.childnum = {nodeChildnum}
# 	return m.id, y
# 	"""
#     result = graph.run(cypher=query).data()
#     if result:
#         for i in result:
#             rootOfLine = getRootOfLine(i["m.id"])
#             if not rootOfLine:
#                 return
#             value = None
#             container = ""
#             varName = ""
#             # case 1: the parameter comes from a variable (AST_VAR)
#             if i["y"]["type"] == "AST_VAR":
#                 query2 = f"""
# 				MATCH (m)-[:PARENT_OF*1..2]->(name:AST) WHERE m.id = {i['y']['id']} AND name.type = 'string' 
# 				RETURN name.code
# 				"""
#                 result2 = graph.run(cypher=query2).data()
#                 if result2:
#                     varName = result2[0]["name.code"]

#             # case 2: the parameter comes from accessing a field of an object
#             # case 3: the parameter comes from an array's field such as REQUEST (POST,GET,REQUEST) variable
#             # note: case 2 and 3 share the same code as the structure in Navex is the same for the 2 cases
#             elif i["y"]["type"] in ["AST_DIM", "AST_PROP"]:
#                 query2 = f"""
# 				MATCH (n:AST)<-[:PARENT_OF]-(x:AST)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(y:AST)
# 				WHERE x.id = {i['y']['id']} AND n.type = 'string'  AND m.type = 'AST_VAR' AND y.type = 'string' 
# 				RETURN y.code,n.code
# 				"""
#                 result2 = graph.run(cypher=query2).data()
#                 if result2:
#                     varName = result2[0]["n.code"]
#                     container = str(result2[0]["y.code"])
#             # case 4: the parameter comes from an AST_ASSIGN inside the function
#             elif i["y"]["type"] == "AST_ASSIGN":
#                 varName = ASTAssignGetName(i["y"]["id"])[0]
#                 query2 = f"""
# 				MATCH (m)-[:PARENT_OF]->(val:AST) WHERE m.id = {i['y']['id']} AND val.type IN ['string','integer'] 
# 				RETURN val.code
# 				"""

#                 result2 = graph.run(cypher=query2).data()
#                 if result2:
#                     value = result2[0]["val.code"]
#             # case 5: the parameter comes from a direct value (string,integer, AST_CONST)
#             # 	in this case, there's no varName, but we can know the data value
#             elif i["y"]["type"] in ["string", "integer"]:
#                 value = i["y"]["code"]

#             newNode = DataNode(rootOfLine["id"], varName)
#             newNode.personal = node.personal

#             newNode.value = value
#             newNode.admin = node.admin
#             newNode.container = container
#             allPossiblePreviousNode.append(newNode)
#     # case 6: triggered through action hooks
#     # (more implementation here)
#     # case 7: no function calls->do nothing

#     return allPossiblePreviousNode


"""!!!Deprecated
Argument:
	trackedVariable: a string name the tracked variable
	id: the 'id' attribute of the input node
	type: the 'type' attribute of the input node
Output:
	returns a dictionary of id of the nodes that the current node reaches, with the variable name being the key

Note: different situations for passing to the next function: POST or parameters
"""


# def reachesNextNode(trackedVariable: str, id: int, type: str):
#     if type == "AST_ASSIGN":
#         query = (
#             """
# 		MATCH (n)-[:REACHES]->(m) WHERE n.id = """
#             + str(id)
#             + """ RETURN m
# 		"""
#         )
#     # Need more work here to handle multiple parameters. Need to get the order of the parameter passed in.
#     elif type == "AST_METHOD":
#         query = (
#             """
# 		MATCH (n)-[:ENTRY]->(x)-[:FLOWS_TO]->(l)-[:REACHES]->(m) WHERE n.id = """
#             + str(id)
#             + """ AND l.type = 'AST_PARAM' RETURN m
# 		"""
#         )
#     else:
#         # Exit if invalid.
#         return None
#     graph = getGraph()
#     result = graph.run(cypher=query).data()
#     nodes = {}
#     if len(result > 0):  # type: ignore
#         for i in result:
#             dataTemp = i["m"]
#             if dataTemp["type"] == "AST_ASSIGN":
#                 query2 = (
#                     """
# 				MATCH (n)-[:PARENT_OF]->(m)-[:PARENT_OF]->(l) WHERE n.id = """
#                     + str(dataTemp["id"])
#                     + """ AND m.type = 'AST_VAR' AND l.type = 'string' RETURN l.code
# 				"""
#                 )
#                 tempResult = graph.run(cypher=query2).data()
#                 if len(tempResult) == 0 or len(tempResult) > 1:
#                     print("Error! Found an AST_ASSIGN with no variable it assigns to")
#                     printNodeInfo(dataTemp["id"])
#                 else:
#                     nodes[tempResult[0]["l.code"]] = dataTemp["id"]
#             elif dataTemp["type"] == "AST_METHOD_CALL":
#                 # more work here
#                 return 0
#     return nodes


"""Prints out the node and all its children nodes in tree format
Input: 
	nodeID: node ID for an AST node
Print:
	types of node with id nodeID and all its children nodes types. If a node is of type string, its code attribute is also printed.
"""


# def printNodeInfo(nodeID: int):
#     graph = getGraph()

#     query = f"""
# 	match p=(n:AST{{id:{nodeID}}})-[:PARENT_OF*]->(m)
# 	with relationships(p) as rels
# 	unwind rels as r
# 	with collect(r) as rels
# 	return [r in rels | [startNode(r), endNode(r)]]
# 	"""
#     result = graph.evaluate(query)
#     if not result:
#         return
#     hierarchy: Dict[int, Set[int]] = dict()
#     nodes = dict()
#     for r in result:
#         if not r:
#             continue
#         startNode, endNode = r
#         # Map all children to their parent node.
#         children = hierarchy.get(startNode["id"], set())
#         children.add(endNode["id"])
#         hierarchy[startNode["id"]] = children

#         # Make a map of id to node information.
#         nodes[startNode["id"]] = startNode
#         nodes[endNode["id"]] = endNode

#     print_str = []
#     stack = [nodeID]
#     indent = [0]
#     while stack:
#         # Get the current node and print it out.
#         current = stack.pop()
#         current_indent = indent.pop()
#         node = nodes[current]

#         # Make sure found security functions are represented in the output.
#         enc_str = ""
#         data_node: DataNode = DataNode.all_nodes.get(current, None)
#         if data_node:
#             finding = data_node.getFinding()
#             if finding:
#                 enc_str = f" (Security {finding.short_desc()})"

#         # Prepare print.
#         substr = f"""{"    " * current_indent}{node['type']}"""
#         if node["type"] == "string":
#             try:
#                 reduced = re.sub(r"\s+", " ", str(node["code"]))
#                 substr += f""": {reduced}"""
#             except:
#                 substr += node["code"]
#         substr += enc_str
#         print_str.append(substr)

#         # Prepare children for printing.
#         if current in hierarchy:
#             children_list = list(hierarchy[current])
#             children_list.sort(key=lambda x: -nodes[x]["childnum"])
#             stack.extend(children_list)
#             indent.extend([current_indent + 1 for _ in children_list])

#     print("\n".join(print_str))
