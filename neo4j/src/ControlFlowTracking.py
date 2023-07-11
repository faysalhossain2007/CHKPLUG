import re
from typing import Dict, List, Tuple

from ControlFlows import ControlFlowNode, ControlFlowPath, PropositionNode
from DataFlows import DataFlowPath, DataNode
from DataFlowTracking import reverseTrackDataFlowFromNode,reverseTrackDataFlowToAssignNoRecord
from Detectors.FunctionFinding import FunctionFinding
from Detectors.Runtime import SECURITY_DETECTOR_MANAGER
from Detectors.Scores import ScoreType
from Errors import DetectorManagerUninitializedException
from NeoGraph import getGraph
from NeoHelper import concatTree, getCallName, getNode, getRootOfLine, getVarName, isNodeAssignee


class ControlFlowTracking:
    @staticmethod
    def eliminateDuplicatedPaths(paths):
        if len(paths) == 1:
            return paths
        newPaths = []
        for i in range(len(paths) - 1):
            isDuplicate = False
            for j in range(i + 1, len(paths)):

                # if paths[i]==paths[j]:
                if not len(paths[i]) == len(paths[j]):
                    continue
                isDifferent = False
                for index in range(len(paths[i])):
                    nodeA = paths[i][index]
                    nodeB = paths[j][index]
                    if not (nodeA.id == nodeB.id and nodeA.value == nodeB.value):
                        isDifferent = True
                        break
                if not isDifferent:

                    isDuplicate = True
            if not isDuplicate:
                newPaths.append(paths[i])
        return newPaths

    """
    Input:
        dataNode1's data flows to dataNode2's data (the inputs are their IDs). These are assumed to be adjacent nodes in a dataflow path.
    Output:
        outputs a list of conditions and truth value for each control flow path
    """

    @staticmethod
    def flowsCondition(dataNodeID1, dataNodeID2):
        graph = getGraph()
        # get root of line
        root1 = getRootOfLine(dataNodeID1)
        if not root1:
            return
        root1 = root1["id"]

        root2 = getRootOfLine(dataNodeID2)
        if not root2:
            return
        root2 = root2["id"]

        # get path from 1 to 2
        query = f"""
        MATCH p = (n)-[:FLOWS_TO*0..10]->(m)
        WHERE n.id = {root1} AND m.id = {root2}
        RETURN p
        """
        result = graph.run(cypher=query).data()

        # iterate through the path to find logical expressions.
        conditionLists = []
        propNodeAndValue = {}
        if result:

            # traverse all the possible control flow paths and cancel/combine conditions
            for path in result:
                # print(path)
                conditionList = []
                for i in range(len(path["p"].relationships)):
                    if not path["p"].relationships[i]["flowLabel"] == None:
                        # print(path['p'].nodes[i]['id'])
                        # print(type(path['p'].relationships[i]['flowLabel']))
                        # print("Here")

                        # print(result[0]['p'].nodes[i]['id'])
                        # print(result[0]['p'].relationships[i]['flowLabel'])
                        if path["p"].nodes[i]["id"] in propNodeAndValue:
                            allValues = propNodeAndValue[path["p"].nodes[i]["id"]]
                            currentValue = path["p"].relationships[i]["flowLabel"]
                            if currentValue == "True" and "False" in allValues:
                                propNodeAndValue[path["p"].nodes[i]["id"]].remove("False")
                                # remove the unnecessary constraint
                                for x in range(len(conditionLists)):
                                    for y in conditionLists[x]:
                                        if y.id == path["p"].nodes[i]["id"] and y.value == "False":
                                            conditionLists[x].remove(y)
                            elif currentValue == "False" and "True" in allValues:
                                propNodeAndValue[path["p"].nodes[i]["id"]].remove("True")
                                # remove the unnecessary constraint
                                for x in range(len(conditionLists)):
                                    for y in conditionLists[x]:
                                        if y.id == path["p"].nodes[i]["id"] and y.value == "True":
                                            conditionLists[x].remove(y)
                            else:
                                propNodeAndValue[path["p"].nodes[i]["id"]].append(currentValue)
                                conditionList.append(
                                    ControlFlowTracking.getControlFlowNode(
                                        path["p"].nodes[i]["id"],
                                        path["p"].relationships[i]["flowLabel"],
                                    )
                                )

                        else:
                            propNodeAndValue[path["p"].nodes[i]["id"]] = [
                                path["p"].relationships[i]["flowLabel"]
                            ]
                            conditionList.append(
                                ControlFlowTracking.getControlFlowNode(
                                    path["p"].nodes[i]["id"],
                                    path["p"].relationships[i]["flowLabel"],
                                )
                            )
                conditionLists.append(conditionList)

        conditionLists = ControlFlowTracking.eliminateDuplicatedPaths(conditionLists)
        return conditionLists

    @staticmethod
    def trackControlFlow(dataflowPath: DataFlowPath):
        # if there are less than 2 nodes in the path, then there is no actual data flow and control flow.
        if len(dataflowPath.path) < 2:
            return
        controlFlowPaths = [ControlFlowPath()]

        for i in range(len(dataflowPath.path) - 1):
            node1 = dataflowPath.path[i]
            node2 = dataflowPath.path[i + 1]
            currentConditionLists = ControlFlowTracking.flowsCondition(node1, node2)
            for path in controlFlowPaths:
                if currentConditionLists:
                    controlFlowPaths.remove(path)
                    for conditions in currentConditionLists:
                        path_copy = path.copy()
                        path_copy.insertPath(conditions)
                        controlFlowPaths.append(path_copy)

        return controlFlowPaths

    """
    Recursively get left hand and right hand side for the current expression to get the entire AST tree
    
    Returns a Proposition Node and list of flags
    """

    @staticmethod
    def getPropositionNode(nodeID: int) -> Tuple[PropositionNode, List[str]]:
        node = getNode(nodeID)
        nodeType = node["type"]
        flags: List[str] = []

        # if the node is unary op or binary op, then it is a concatenation of multiple propositions
        if nodeType == "AST_UNARY_OP":
            if "flags" in node and "UNARY_BOOL_NOT" in node["flags"]:
                # might need to optimize the implementation here by first getting all the nodes in the sub tree

                # get the entire expression
                expression = concatTree(nodeID)
                # get child
                graph = getGraph()
                query = f"""
                MATCH (n)-[:PARENT_OF]->(m)
                WHERE n.id = {nodeID}
                RETURN m.id
                """
                result = graph.run(cypher=query).data()
                # there should be only one child
                if result and len(result) == 1:
                    currentFlag = "logic operator"
                    flags = []
                    subNodeID = result[0]["m.id"]
                    propositionNode = PropositionNode(nodeID, expression, [])
                    propositionNode.operator = "NOT"
                    subProposition = ControlFlowTracking.getPropositionNode(subNodeID)
                    # print(subNodeID)
                    if subProposition:
                        propositionNode.lefthand = subProposition[0]
                        flags.extend(subProposition[1])
                        return (propositionNode, flags)

        elif nodeType == "AST_BINARY_OP":
            if "flags" in node and "BINARY_BOOL_AND" in node["flags"]:
                # might need to optimize the implementation here by first getting all the nodes in the sub tree

                # get the entire expression
                expression = concatTree(nodeID)
                # get child
                graph = getGraph()
                query = f"""
                MATCH (n)-[:PARENT_OF]->(m)
                WHERE n.id = {nodeID}
                RETURN m.id
                """
                result = graph.run(cypher=query).data()
                # there should be only two children
                if result and len(result) == 2:

                    currentFlag = "logic operator"
                    flags = []
                    lefthandID = result[0]["m.id"]
                    righthandID = result[1]["m.id"]
                    propositionNode = PropositionNode(nodeID, expression, [])
                    propositionNode.operator = "AND"
                    lefthand = ControlFlowTracking.getPropositionNode(lefthandID)
                    righthand = ControlFlowTracking.getPropositionNode(righthandID)
                    if lefthand and righthand:
                        propositionNode.lefthand = lefthand[0]
                        propositionNode.righthand = righthand[0]
                        flags.extend(lefthand[1])
                        flags.extend(righthand[1])
                        return (propositionNode, flags)

            elif "flags" in node and "BINARY_BOOL_OR" in node["flags"]:
                # might need to optimize the implementation here by first getting all the nodes in the sub tree

                # get the entire expression
                expression = concatTree(nodeID)
                # get child
                graph = getGraph()
                query = f"""
                MATCH (n)-[:PARENT_OF]->(m)
                WHERE n.id = {nodeID}
                RETURN m.id
                """
                result = graph.run(cypher=query).data()
                # there should be only two children
                if result and len(result) == 2:
                    currentFlag = "logic operator"
                    flags = []
                    lefthandID = result[0]["m.id"]
                    righthandID = result[1]["m.id"]
                    propositionNode = PropositionNode(nodeID, expression, [])
                    propositionNode.operator = "OR"
                    lefthand = ControlFlowTracking.getPropositionNode(lefthandID)
                    righthand = ControlFlowTracking.getPropositionNode(righthandID)
                    if lefthand and righthand:
                        propositionNode.lefthand = lefthand[0]
                        propositionNode.righthand = righthand[0]
                        flags.extend(lefthand[1])
                        flags.extend(righthand[1])
                        return (propositionNode, flags)

        # if it's not the case above, then we have reached the leaf of the tree
        elif nodeType == "AST_EMPTY":
            # might need to optimize the implementation here by first getting all the nodes in the sub tree

            # get the entire expression
            expression = concatTree(nodeID)
            # get child
            graph = getGraph()
            query = f"""
            MATCH (n)-[:PARENT_OF]->(m)
            WHERE n.id = {nodeID}
            RETURN m.id
            """
            result = graph.run(cypher=query).data()

            # there should be only one child
            if result and len(result) == 1:

                subNodeID = result[0]["m.id"]
                currentFlag = "is empty" + concatTree(subNodeID)
                flags = [currentFlag]
                propositionNode = PropositionNode(nodeID, expression, [currentFlag])
                subProposition = ControlFlowTracking.getPropositionNode(subNodeID)
                if subProposition:
                    propositionNode.wrappedNode = subProposition[0]
                    flags.extend(subProposition[1])
                    return (propositionNode, flags)

        elif nodeType == "AST_ISSET":
            # might need to optimize the implementation here by first getting all the nodes in the sub tree

            # get the entire expression
            expression = concatTree(nodeID)
            # get child
            graph = getGraph()
            query = f"""
            MATCH (n)-[:PARENT_OF]->(m)
            WHERE n.id = {nodeID}
            RETURN m.id
            """
            result = graph.run(cypher=query).data()
            # there should be only one child
            if result and len(result) == 1:

                subNodeID = result[0]["m.id"]
                currentFlag = "is set " + concatTree(subNodeID)
                flags = [currentFlag]
                propositionNode = PropositionNode(nodeID, expression, [currentFlag])
                subProposition = ControlFlowTracking.getPropositionNode(subNodeID)
                if subProposition:
                    propositionNode.wrappedNode = subProposition[0]
                    flags.extend(subProposition[1])
                    return (propositionNode, flags)

        elif nodeType == "AST_INSTANCEOF":
            # might need to optimize the implementation here by first getting all the nodes in the sub tree

            # get the entire expression
            expression = concatTree(nodeID)
            # get child
            graph = getGraph()
            query = f"""
            MATCH (n)-[:PARENT_OF]->(m)
            WHERE n.id = {nodeID}
            RETURN m.id ORDER BY m.childnum
            """
            result = graph.run(cypher=query).data()
            # there should be two children
            if result and len(result) == 2:

                subNodeID = result[0]["m.id"]
                subNode2ID = result[1]["m.id"]
                currentFlag = "instance of " + concatTree(subNode2ID)

                # special case: if it is an instance of WP_User, we assign isUser flag
                if concatTree(subNode2ID) == "WP_User":
                    currentFlag = "isUser"
                flags = [currentFlag]
                propositionNode = PropositionNode(nodeID, expression, [currentFlag])
                subProposition = ControlFlowTracking.getPropositionNode(subNodeID)
                subProposition2 = ControlFlowTracking.getPropositionNode(subNode2ID)
                if subProposition and subProposition2:
                    propositionNode.lefthand = subProposition[0]
                    propositionNode.righthand = subProposition2[0]
                    flags.extend(subProposition[1])
                    flags.extend(subProposition2[1])
                    return (propositionNode, flags)

        elif nodeType in ("AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"):
            # if the proposition is an ast call, analyze the call name and argument
            expressionName = concatTree(nodeID)
            callName = getCallName(nodeID)
            if callName:
                flag = ControlFlowTracking.getCallFlag(callName)
                if ControlFlowWPFunctions.isConsentRetrievalCall(nodeID):
                    flag = "consent"
                propositionNode = PropositionNode(nodeID, expressionName, [flag])
                # ps: might need to investigate and track the call arguments
                return (propositionNode, flags)

        elif nodeType == "AST_VAR":
            expressionName = concatTree(nodeID)
            # if the variable is an assignee, we have found where the variable is assigned
            if isNodeAssignee(nodeID):

                # get assigner
                graph = getGraph()
                query = f"""
                MATCH (n)<-[:PARENT_OF]-(head)->[:PARENT_OF]->(assigner) 
                WHERE n.id = {nodeID} and head.type = 'AST_ASSIGN' AND assigner.childnum = 1
                RETURN assigner.id
                """
                result = graph.run(cypher=query).data()[0]["assigner.id"]

                flags = ControlFlowTracking.getFlagForTree(result)
                flags = [] if not flags else flags
                propositionNode = PropositionNode(nodeID, expressionName, flags)
                if (
                    ControlFlowWPFunctions.isConsentString(expressionName)
                    and "consent" not in flags
                ):
                    flags.append("consent")
                # ps: might need to investigate and track the call arguments
                return (propositionNode, flags)

            # if the variable is not an assignee, it must be assigned somewhere else. We get the source of this variable here
            
            # varName = getVarName(nodeID)
            # if varName:
            #     reverseTrackDataFlowFromNode(DataNode(nodeID, varName))

            # print(sources)

            # get paths from the sink to where it is assigned
            source = reverseTrackDataFlowToAssignNoRecord(nodeID)
            if source:
                flags.extend(ControlFlowTracking.getFlagForTree(source['id']))
            # for path in allPaths:
            #     source = path.getHead()
            #     # get assigner for the source
            #     graph = getGraph()
            #     query = f"""
            #     MATCH (n)<-[:PARENT_OF]-(head)->[:PARENT_OF]->(assigner) 
            #     WHERE n.id = {source} and head.type = 'AST_ASSIGN' AND assigner.childnum = 1
            #     RETURN assigner.id
            #     """
            #     result = graph.run(cypher=query).data()[0]["assigner.id"]
            #     # get flag for source
            #     flags.extend(ControlFlowTracking.getFlagForTree(result))
                # get condition for source and track control flow (left out for now)
                # controlFlowPath = ControlFlowTracking.trackControlFlow(path)

            if ControlFlowWPFunctions.isConsentString(expressionName) and "consent" not in flags:
                flags.append("consent")
            propositionNode = PropositionNode(nodeID, expressionName, flags)
            # ps: might need to investigate and track the call arguments
            return (propositionNode, flags)

        expressionName = concatTree(nodeID)
        propositionNode = PropositionNode(nodeID, expressionName, [])
        return (propositionNode, [])

    @staticmethod
    def getFlagForTree(nodeID: int) -> List[str]:
        propNode = ControlFlowTracking.getPropositionNode(nodeID)
        if propNode:
            return propNode[1]
        return []

    @staticmethod
    def getControlFlowNode(nodeID: int, value: str):
        """Given a nodeID in neo4j's graph that represents a condition/proposition, we output a
        ControlFlowNode that gives further context information of the node (e.g. it's a consent
        condition, admin condition, or logged in condition, etc) The ControlFlowNode is considered a
        summary of the proposition as it lists the complete expression and all of the flags related
        to the proposition, and will be linked to a tree of proposition nodes (in case that the
        condition is consisted of many propositions and linked through AND/OR/NOT)

        Args:
            nodeID (int)
            value (str)

        Returns:
            Optional[ControlFlowNode]
        """

        # ControlFlowTracking.getExpression(nodeID)
        # nodeType = getNodeType(nodeID)

        # id: int = int(nodeID)
        expression = concatTree(nodeID)

        propositionNode = ControlFlowTracking.getPropositionNode(nodeID)
        if propositionNode:
            rootNode = propositionNode[0]
            flags = propositionNode[1]
            controlFlowNode = ControlFlowNode(nodeID, expression, value, flags, rootNode)
            return controlFlowNode
        else:
            return None

    @staticmethod
    def getCallFlag(callName: str, params=None):
        """Return the correct control flow label for an AST_CALL"""
        flag = ""
        for i in ControlFlowWPFunctions.WPFunctionFlags:
            if callName in ControlFlowWPFunctions.WPFunctionFlags[i]:
                return i
        for i in ControlFlowWPFunctions.PHPFunctionFlags:
            if callName in ControlFlowWPFunctions.PHPFunctionFlags[i]:
                return i
        # more work to analyze the params? e.g. for get_option
        return "unknown call"

    @staticmethod
    def printControlFlowNode(controlFlowNode):
        pass


class ControlFlowWPFunctions:
    ConsentRetrieval: List[int] = []
    WPFunctionFlags = {
        "isAdmin": [
            "is_admin",
            "is_blog_admin",
            "is_network_admin",
            "is_site_admin",
            "is_user_admin",
        ],
        "isEncrypted": ["is_ssl"],
        "isUser": ["is_blog_user", "is_user_logged_in", "get_user_by", "get_user"],
    }
    PHPFunctionFlags: Dict[str, List[str]] = {"utility": []}
    WPDynamicFunctionFlags: Dict[str, List[str]] = {}

    @staticmethod
    def isConsentRetrievalCall(nodeID: int) -> bool:
        """Return whether a function call is considered a retrieval call for getting consent"""
        if not ControlFlowWPFunctions.ConsentRetrieval:
            ControlFlowWPFunctions.getConsentRetrievalCall()
        return nodeID in ControlFlowWPFunctions.ConsentRetrieval

    @staticmethod
    def isConsentString(string: str):
        isConsent = False
        possibleConsentRegEx = [
            ".*(consent).*",
            ".*(agree).*",
            ".*(approve).*",
            ".*(accept).*",
            ".*(permission).*",
        ]
        for i in possibleConsentRegEx:
            if re.compile(i, re.IGNORECASE).match(string):
                isConsent = True
        return isConsent

    @staticmethod
    def getConsentRetrievalCall():
        if not SECURITY_DETECTOR_MANAGER:
            raise DetectorManagerUninitializedException

        # Get all function calls that use the function finding interface and are also a retrieval call
        ffs = [
            f
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if isinstance(f, FunctionFinding) and ScoreType.RETRIEVAL == f.score.score_type
        ]
        if not ffs:
            print("finding is empty")
        for f in ffs:
            # print(f.code) # This is just concatTree called on the root call node.
            # print("Args:")
            for arg_num, arg_var_name in f.arg_map.items():
                # arg_num: the argument's order, also corresponds to an argument's childnum in Neo4j
                # arg_var_name: the argument's var name in Wordpress -- probably useful in determining if it is a key (arg_var_name == "$key")
                # print(f"""\t{arg_num}: {arg_var_name} {f.arg_info[arg_num]}""")
                # There is also a lot of auxillary information stored about each arg that was scraped from
                # WP's website; This info generally mirrors
                # https://github.com/faysalhossain2007/GDPR-CCPA-violation-checker/blob/d91ed605b2e59bdb64f4e6cda7d251f4a50a12de/neo4j/src/Detectors/wordpress_functions.json#L22123-L22123
                # but it is in a different form (split into f.arg_map and f.arg_info).
                # print(f"""\t\ttype: {f.arg_info[arg_num].get("type")}""")
                # print(f"""\t\tdescription: {f.arg_info[arg_num].get("description")}""")
                if arg_var_name == "$key":
                    graph = getGraph()
                    query = f"""
                    MATCH (n:AST{{id:{f.node["id"]}}})-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(arg:AST{{childnum:{arg_num}}})
                    RETURN arg
                    """
                    result = graph.run(cypher=query).data()
                    if result and result[0]["arg"]["type"] == "string":
                        # print(result[0]['arg']['code'])
                        isConsent = ControlFlowWPFunctions.isConsentString(result[0]["arg"]["code"])
                        if isConsent:
                            ControlFlowWPFunctions.ConsentRetrieval.append(f.node["id"])
                    # for testing purpose, check if there are other types than string
                    elif result and not (result[0]["arg"]["type"] == "string"):
                        pass
                        # print(result[0]["arg"]["type"])
                        # print(result[0]["arg"]["id"])

            # print()
        pass
