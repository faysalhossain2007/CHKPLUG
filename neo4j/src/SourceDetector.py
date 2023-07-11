import json
import os
import re
from traceback import print_exc
from typing import Any, Dict, List, Optional, Set

from ActionHook import ActionHook
from DataFlows import DataNode
from Detectors.Runtime import SECURITY_DETECTOR_MANAGER
from Errors import DetectorManagerUninitializedException, SourceDetectorException
from NeoGraph import getGraph
from NeoHelper import (
    ASTAssignGetAssignedVar,
    ASTAssignGetName,
    ASTMethodGetParameterList,
    getCallName,
    getNodeName,
    getNodeType,
    getRootOfLine,
    getVarAssignLocation,
)
from PersonalData import PersonalDataMatcher
from ClassStructure import determineObjectType,getClassHierarchy

TRACKED_TYPES = ["AST_ASSIGN", "AST_CALL", "AST_STATIC_CALL", "AST_METHOD_CALL"]

DATABASE_ACCESS_API = ["wp_get_current_user"]

DATABASE_STORE_API: List[str] = []
DATABASE_DELETE_API: List[str] = []

with open(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "WooCommerceSources.json"),
    "r",
) as f:
    WOOCOMMERCE_SOURCES = json.load(f)["customer_getters"]

with open(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "WordPressGetters.json"),
    "r",
) as f:
    WORDPRESS_SOURCES = json.load(f)["all_getters"]


class SinkDetector:
    sinkLocators: Dict[str, Any] = dict()

    @staticmethod
    def locateSink(sourceType: Optional[str] = None) -> List[DataNode]:
        return []

    @staticmethod
    def locateThirdPartySink():
        if not SECURITY_DETECTOR_MANAGER:
            raise DetectorManagerUninitializedException()
        PHPCurlParty_detector = SECURITY_DETECTOR_MANAGER.get_detector("PhpCurlDetector")
        if PHPCurlParty_detector:

            for finding in PHPCurlParty_detector.findings:
                print(finding)

        WPRemote_detector = SECURITY_DETECTOR_MANAGER.get_detector("WordPressRemoteDetector")
        if WPRemote_detector:
            for finding in WPRemote_detector.findings:
                print(finding)


class SourceDetector:

    actionHooks: list = []
    filterHooks: list = []
    sourceLocators: Dict[str, Any] = dict()

    @staticmethod
    def locateSource(sourceType: Optional[str] = None) -> List[DataNode]:
        # Faysal: implement
        # Define a name for your source finding method (e.g. "request") and then create another function to find all the sources, just like the examples above.
        # Then return a list of dataNode object
        if not sourceType:
            return SourceDetector.locateActionSource()
        else:
            return SourceDetector.sourceLocators.get(
                sourceType, SourceDetector.locateActionSource
            )()

    @staticmethod
    def locateWPAttrSource(keyword: Optional[str] = None) -> List[DataNode]:
        """Helper function. Locates all the data node source that are from wordpress user object's attributes (e.g. $object->user_email)"""
        return []

    @staticmethod
    def locateRequestSource(funcid: Optional[int] = None) -> List[DataNode]:
        """Helper function. locates all the _REQUEST, _POST, _GET variable with certain keywords

        Args:
                funcid (int): Function ID to search in.

        Returns:
                List[DataNode]: A list of the root node (DataNode objects) of the line where the request variable appears
        """

        # Finds request source among the list of node IDs
        graph = getGraph()
        sourceList = []
        PIIList = PersonalDataMatcher.get_pii_list()

        for i in PIIList:
            query = ""
            if funcid:
                query = f"""
				MATCH (n:AST)<-[:PARENT_OF]-(x:AST)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(y:AST)
				WHERE x.funcid = {funcid} AND x.type = 'AST_DIM' AND n.type = 'string' AND n.code =~ '(?).*{i}.*' AND m.type = 'AST_VAR' AND y.type = 'string' AND (y.code = '_POST' OR y.code = '_GET' OR y.code = '_REQUEST')
				RETURN COLLECT(DISTINCT x.id)
				"""
            else:
                query = f"""
				MATCH (n:AST)<-[:PARENT_OF]-(x:AST)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(y:AST)
				WHERE  x.type = 'AST_DIM' AND n.type = 'string' AND n.code =~ '(?).*{i}.*' AND m.type = 'AST_VAR' AND y.type = 'string' AND (y.code = '_POST' OR y.code = '_GET' OR y.code = '_REQUEST')
				RETURN COLLECT(DISTINCT x.id)
				"""
            trackedList: List[int] = graph.evaluate(query)
            if not trackedList:
                continue
            parentList: List[DataNode] = []
            # use this to prevent duplicate sources
            included: Set[int] = set()

            # find parent
            for j in trackedList:
                parent = getRootOfLine(j)
                if parent and parent["type"] in TRACKED_TYPES and (parent["id"] not in included):
                    try:
                        assign_name = "(Empty_name)"
                        if parent["type"] == "AST_ASSIGN":
                            names = ASTAssignGetName(parent["id"])
                            if not assign_name:
                                names = ["(Empty_name)"]
                            elif len(names) != 1:
                                print(
                                    f"{'!'*10}Assumption violated. request variable is assigned to multiple variable at the same time. Check {parent['id']}"
                                )
                            assign_name = names[0]
                        node_name = getNodeName(parent["funcid"])
                        node_type = getNodeType(parent["id"])
                        className = ""
                        try:
                            className = parent["classname"]
                        except:
                            pass
                        # Check for nones
                        if not assign_name or not node_name or not node_type:
                            continue

                        assigned_var = ASTAssignGetAssignedVar(parent["id"])
                        if assigned_var:
                            tempNode = DataNode(
                                assigned_var,
                                assign_name,
                                node_name,
                                node_type,
                                None,
                                None,
                            )
                            # tempNode.callName = getCallName(tempNode.id) # Unnecessary
                            tempNode.personal = PersonalDataMatcher.determine_category(assign_name)
                            tempNode.admin = ActionHook.isAdminClass(className)
                            parentList.append(tempNode)
                            included.add(parent["id"])
                    except Exception as e:
                        print_exc()
            sourceList.extend(list(parentList))

        return sourceList

    @staticmethod
    def locateWPDBSource(keyword: Optional[str] = None) -> List[DataNode]:
        return []

    @staticmethod
    def locateBPSource(keyword: Optional[str] = None) -> List[DataNode]:
        return []

    @staticmethod
    def locateActionSource(disablePersonalFilter: bool = False) -> List[DataNode]:
        
        graph = getGraph()
        classHierarchy = getClassHierarchy()
        query = f"""
		MATCH (argList:AST)<-[:PARENT_OF]-(addAction:AST)-[:PARENT_OF]->(astName:AST)-[:PARENT_OF]->(callname:AST)
		WHERE addAction.type = 'AST_CALL' AND astName.type = 'AST_NAME' AND (callname.code = 'add_action' OR callname.code = 'add_filter') AND argList.type = 'AST_ARG_LIST'
		WITH argList,callname,addAction
		MATCH (arg:AST)<-[:PARENT_OF]-(argList:AST)-[:PARENT_OF]->(arg2:AST)
		WHERE arg.childnum = 1 AND arg2.childnum = 0
		RETURN addAction.id AS callID, arg, arg2, callname.code
		"""
        result = graph.run(cypher=query).data()
        sourceNodes = []
        if result:
            for i in result:
                # Use this later to store the callback function information
                funcNodeID = []
                funcName = ""
                className = ""
                arg = i["arg"]
                hook = i["arg2"]
                callname = i["callname.code"]
                if callname == "add_action":
                    SourceDetector.actionHooks.append(hook)
                elif callname == "add_filter":
                    SourceDetector.filterHooks.append(hook)
                if arg["type"] == "AST_ARRAY":
                    # case when the function info is stored in an array. example: add_action( 'plugins_loaded', array( $this, 'loaded' ) );

                    # get the function name parameter and the object information
                    # assume the object information is stored in a variable initialized earlier
                    query1 = f"""
					MATCH (funcName:AST{{type:'string'}})<-[:PARENT_OF]-(ele2:AST{{childnum:1}})<-[:PARENT_OF]-(arg:AST{{id:{arg['id']}}})-[:PARENT_OF]->(ele:AST{{childnum:0}})-[:PARENT_OF]->(var:AST{{childnum:0}})
					RETURN funcName.code,var
					"""
                    result1 = graph.run(cypher=query1).data()
                    if result1:
                        objectType = None
                        #this is to handle case where the class is directly stored as the string of the class name
                        if result1[0]['var']['type']=='string':
                            objectType = result1[0]['var']['code']
                        else:
                            objectType = determineObjectType(result1[0]['var'])
                        className = objectType
                        funcName = result1[0]["funcName.code"]
                        methodIDs = classHierarchy.lookUpFunction(objectType,funcName)
                        if len(methodIDs)>0:
                            funcNodeID = methodIDs
                        
                    

                    

                elif arg["type"] == "string":
                    #case when the second parameter is a string of the function name. example: add_action( 'publish_post', 'wpdocs_email_friends' );
                    funcName = arg['code']
                    query1 = f"""
					MATCH (func:AST)
					WHERE (func.type = 'AST_METHOD' OR func.type= 'AST_FUNC_DECL') AND func.name = '{arg['code']}'
					RETURN func.id
					"""
                    result1 = graph.run(cypher=query1).data()
                    if result1:
                        for resultTemp in result1:
                            funcNodeID.append(resultTemp["func.id"])

                
                # At this point, we have tracked down the function node with funcNodeID.
                # Find all potential data source
                # Method 1: check the passed in parameters
                for funcID in funcNodeID:
                    param = ASTMethodGetParameterList(funcID)
                    if param:
                        paramName, paramList = param
                        for nodeIndex in range(len(paramName)):
                            # nodeID,varName,funcName,nodeType,nextNode,previousNode
                            nodeID = paramList[nodeIndex]
                            nodeVarName = paramName[nodeIndex]
                            """
                            if keyword not in nodeVarName:
                                continue
                            """

                            nodeType = getNodeType(nodeID)
                            nextNode = None
                            previousNode = None
                            tempNode = DataNode(
                                nodeID,
                                nodeVarName,
                                funcName,
                                nodeType,
                                nextNode,
                                previousNode,
                            )

                            tempNode.personal = PersonalDataMatcher.determine_category(nodeVarName)
                            tempNode.admin = ActionHook.isAdmin(hook, className)
                            # add to source node list if this node is a personal data node
                            if tempNode.personal or disablePersonalFilter:
                                sourceNodes.append(tempNode)
                # if function has no argument, then it probably retrieves data through means covered by other source detectors.

                #sourceNodes.extend(SourceDetector.locateRequestSource(funcNodeID))
                #sourceNodes.extend(SourceDetector.locateWooCommerceSource(funcNodeID))
                #sourceNodes.extend(SourceDetector.locateWordPressSource(funcNodeID))

        return sourceNodes

    @staticmethod
    def locateDatabaseSource(keyword: Optional[str] = None) -> List[DataNode]:
        graph = getGraph()
        sourceNode = []
        included = set()
        for api in DATABASE_ACCESS_API:
            query = f"""
			MATCH (call:AST)-[:PARENT_OF]->(name:AST)-[:PARENT_OF]->(str:AST)
			WHERE call.type = 'AST_CALL' AND name.type = 'AST_NAME' AND str.code = '{api}'
			RETURN call.id
			"""
            result = graph.run(cypher=query).data()
            for retrieve in result:
                source = getRootOfLine(retrieve["call.id"])
                if source and source["type"] == "AST_ASSIGN" and source["id"] not in included:
                    included.add(source["id"])
                    # nodeID,varName,funcName,nodeType,nextNode,previousNode
                    nodeID = source["id"]
                    varname = ""
                    if source["type"] == "AST_ASSIGN":

                        varname = ASTAssignGetName(source["id"])[0]
                        if len(varname) > 1:
                            print(
                                f"{'!'*10}Assumption violated. request variable is assigned to multiple variable at the same time. Check {source['id']}"
                            )
                    else:
                        varname = "(Empty_name)"

                    funcName = getNodeName(source["funcid"])
                    nodeType = getNodeType(source["id"])
                    className = ""
                    try:
                        className = source["classname"]
                    except:
                        pass
                    nextNode = None
                    previousNode = None
                    tempNode = DataNode(nodeID, varname, funcName, nodeType, nextNode, previousNode)
                    callName = getCallName(tempNode.id)  # Setting callname may be redundant.
                    if callName:
                        tempNode.callName = callName
                    tempNode.personal = PersonalDataMatcher.determine_category(varname)
                    tempNode.admin = ActionHook.isAdminClass(className)
                    sourceNode.append(tempNode)

        return sourceNode

    @staticmethod
    def locateWooCommerceSource(funcid: Optional[int] = None) -> List[DataNode]:
        """Locate data sources from WooCommerce's Customer class.

        Args:
                keyword (str): The keyword to search for, which should appear in the function's name.

        Returns:
                list[DataNode]: List of DataNodes that should serve as the start points for some paths.
        """
        for keyword in PersonalDataMatcher.get_pii_list():
            # Get set of relevant getters based on the keyword.
            pattern = re.compile(f"{keyword}", re.IGNORECASE)
            relevant_methods = {getter for getter in WOOCOMMERCE_SOURCES if pattern.search(getter)}
            if not relevant_methods:
                # Immediately exit if there are no possible functions left.
                return []
            regex_str = f'({"|".join(relevant_methods)})'

            graph = getGraph()
            sourceNodes = []
            included = set()
            query = ""
            if not funcid:
                query = f"""
				MATCH (call:AST)-[:PARENT_OF]->(str:AST)
				WHERE call.type = 'AST_METHOD_CALL' AND str.code =~ '{regex_str}'
				RETURN collect(call.id)
				"""
            else:
                query = f"""
				MATCH (call:AST)-[:PARENT_OF]->(str:AST)
				WHERE call.type = 'AST_METHOD_CALL' AND str.code =~ '{regex_str}' AND call.funcid = {funcid}
				RETURN collect(call.id)
				"""
            results = graph.run(cypher=query).evaluate()
            for call_id in results:
                source = getRootOfLine(call_id)
                if source and source["type"] in TRACKED_TYPES and source["id"] not in included:
                    included.add(source["id"])
                    # nodeID,varName,funcName,nodeType,nextNode,previousNode
                    nodeID = source["id"]
                    varname = ""
                    if source["type"] == "AST_ASSIGN":

                        varname = ASTAssignGetName(source["id"])[0]
                        if len(varname) > 1:
                            print(
                                f"{'!'*10}Assumption violated. request variable is assigned to multiple variable at the same time. Check {source['id']}"
                            )
                    else:
                        varname = "(Empty_name)"
                    className = ""
                    try:
                        className = source["classname"]
                    except:
                        pass
                    tempNode = DataNode(nodeID, varname)
                    tempNode.personal = PersonalDataMatcher.determine_category(varname)
                    tempNode.admin = ActionHook.isAdminClass(className)
                    sourceNodes.append(tempNode)
            return sourceNodes
        return []

    @staticmethod
    def locateWordPressSource(funcid: Optional[int] = None) -> List[DataNode]:
        """Locate data sources from WordPress's getters.

        Args:
                keyword (str): The keyword to search for, which should appear in the function's name.

        Returns:
                list[DataNode]: List of DataNodes that should serve as the start points for some paths.
        """
        for keyword in PersonalDataMatcher.get_pii_list():
            # Get set of relevant getters based on the keyword.
            pattern = re.compile(f"{keyword}", re.IGNORECASE)
            relevant_methods = {getter for getter in WORDPRESS_SOURCES if pattern.search(getter)}
            if not relevant_methods:
                # Immediately exit if there are no possible functions left.
                return []
            regex_str = f'({"|".join(relevant_methods)})'

            graph = getGraph()
            sourceNodes = []
            included = set()
            query = ""
            if not funcid:
                query = f"""
				MATCH (call:AST)-[:PARENT_OF]->(str:AST)
				WHERE call.type = 'AST_CALL' AND str.code =~ '{regex_str}'
				RETURN collect(call.id)
				"""
            else:
                query = f"""
				MATCH (call:AST)-[:PARENT_OF]->(str:AST)
				WHERE call.type = 'AST_CALL' AND str.code =~ '{regex_str}' AND call.funcid = {funcid}
				RETURN collect(call.id)
				"""
            results = graph.run(cypher=query).evaluate()
            for call_id in results:
                source = getRootOfLine(call_id)
                if source and source["type"] in TRACKED_TYPES and source["id"] not in included:
                    included.add(source["id"])
                    # nodeID,varName,funcName,nodeType,nextNode,previousNode
                    nodeID = source["id"]
                    varname = ""
                    if source["type"] == "AST_ASSIGN":
                        names = ASTAssignGetName(source["id"])
                        if not names:
                            names = ["(Empty_name)"]
                        elif len(names) > 1:
                            print(
                                f"{'!'*10}Assumption violated. request variable is assigned to multiple variable at the same time. Check {source['id']}"
                            )
                        varname = names[0]
                    else:
                        varname = "(Empty_name)"
                    className = ""
                    try:
                        className = source["classname"]
                    except:
                        pass
                    tempNode = DataNode(nodeID, varname)
                    tempNode.personal = PersonalDataMatcher.determine_category(varname)
                    tempNode.admin = ActionHook.isAdminClass(className)
                    sourceNodes.append(tempNode)
            return sourceNodes
        return []


SourceDetector.sourceLocators = {
    "request": SourceDetector.locateRequestSource,
    "add_action": SourceDetector.locateActionSource,
    "database": SourceDetector.locateDatabaseSource,
    "wpAttr": SourceDetector.locateWPAttrSource,
    "wordpress": SourceDetector.locateWordPressSource,
    "woocommerce": SourceDetector.locateWooCommerceSource,
}

SinkDetector.sinkLocators = {
    "thirdParty": SinkDetector.locateThirdPartySink,
}
