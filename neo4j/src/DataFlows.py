from sqlite3.dbapi2 import Connection
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from Detectors.Detectors import AbstractDetector, get_node_filename
from Detectors.FlowScores import FlowScore, FlowSecurity
from Detectors.Runtime import SECURITY_DETECTOR_MANAGER
from Detectors.Scores import ScoreType
from NeoGraph import getGraph
from NeoHelper import getCallName, getNode, getNodeName, getNodeType, isNodeAssignee
#from PersonalData import PersonalDataMatcher, isPersonalString
from Results import write_data_flow_path_row_many
from Utls import progress_bar

# DATA_FLOW_COUNTER is a global counter, where each value corresponds to some unique path.
DATA_FLOW_COUNTER = 0

# ALL_PATHS is a dictionary from path ID to DataFlowPath object.
ALL_PATHS: dict = {}

#RELATIONSHIP_TYPES is moved to DataFlowTracking


def getFinding(nodeID) -> Optional[AbstractDetector.Finding]:
        """Adapted from DataFlow's getFinding() function
        Lookup a node's security finding. Can return None if the DataNode is not interesting.

        Returns:
            Optional[SecurityDetector.Finding]: None if no finding, otherwise a SecurityDetector finding.
        """
        findings = getAllFindings(nodeID)
        if not findings:
            return None
        return findings[-1]

def getAllFindings(nodeID) -> List[AbstractDetector.Finding]:
    """Adapted from DataFlow's getAllFindings() function
    Get all findings for a node since a node may have multiple nested functions, each with their own finding.

    Raises:
        Exception: Raised when there is no Security Detector Manager.

    Returns:
        List[AbstractDetector.Finding]: List of findings.
    """
    global SECURITY_DETECTOR_MANAGER
    if SECURITY_DETECTOR_MANAGER:
        return SECURITY_DETECTOR_MANAGER.lookup_node_id(nodeID)
    else:
        raise Exception("No Security Detector manager initialized.")

class DataNode:

    all_nodes: Dict[int, Any] = {}

    def __init__(self, nodeID: int, varName: str, *args, **kwargs):
        self.id: int = int(nodeID)
        self.varName: str = str(varName)

        self.type = None

        self.container: str = ""
        # sometimes the value of the node can be found (e.g. assigned a string or an integer)
        self.value = None

        # Is this node personal data or not? If it is, this contains which personal data type it is.
        # self.personal = DISABLE_PERSONAL_FILTERING
        self.personal: List[str] = []
        #self.setPersonal(isPersonalString(varName))

        # Is this accessed in the admin branch or public branch
        self.admin = False

        finding: Optional[AbstractDetector.Finding] = self.getFinding()
        self.finding_type: str = ""
        if (
            finding
            and finding.score
            and finding.score.score_type
            and finding.score.score_type is not ScoreType.ERROR
        ):
            self.finding_type = finding.score.score_type.value

        self.all_nodes[self.id] = self

        self.callName: str = ""

    def __repr__(self):
        """Return an internal representation of a DataNode.

        Returns:
            str: Internal description of datanode. Changes if the type of the AST node is "type".
        """
        return f"DataNode[varName={self.varName}, id={self.id}]"

    def getNode(self) -> Dict[str, Any]:
        """Return a dict of the node's properties from Neo4j.

        Returns:
            Dict[str, Any]: Dict containing the node's information.
        """
        graph = getGraph()
        n = graph.evaluate(f"MATCH (n:AST{{id:{self.id}}}) RETURN n LIMIT 1")
        if not n:
            return dict()
        return dict(n)

    def getFuncName(self) -> str:
        """Get the containing function's name for this node.

        Returns:
            str: Name of the function.
        """
        return getNodeName(self.getNode()["funcid"])

    def getChildnum(self) -> int:
        """Get the node's child number.

        Returns:
            int: Child number of the node.
        """
        return self.getNode()["childnum"]

    def getFuncID(self) -> int:
        """Get the node's function ID.

        Returns:
            int: Function ID of the node.
        """
        return self.getNode()["funcid"]

    def getType(self) -> str:
        """Get the type of the current node.

        Returns:
            str: Type of node
        """
        return getNodeType(self.id)

    def getNext(self):
        """Get the next node in the path.

        Raises:
            DeprecationWarning: This interface is no longer supported.
        """
        raise DeprecationWarning(
            "Next/previous node information is no longer stored in the node itself. Use DataFlowPath or DataFlowGraph instead."
        )

    def getPrevious(self):
        """Get the previous node in the path.

        Raises:
            DeprecationWarning: This interface is no longer supported.
        """
        raise DeprecationWarning(
            "Next/previous node information is no longer stored in the node itself. Use DataFlowPath or DataFlowGraph instead."
        )

    def getCallName(self) -> str:
        """Get the name of function that this node calls.

        Returns:
            str: Name of callee.
        """
        if not self.callName:
            call_name = getCallName(self.id)
            return call_name if call_name else ""
        else:
            return self.callName

    def getFileName(self) -> str:
        """Get the filename of the current node.

        Returns:
            str: Name of the node's file.
        """
        filename = get_node_filename(getGraph(), self.id)
        return filename if filename else ""

    def getLineNumber(self) -> int:
        """Get the node's line number.

        Returns:
            int: Line number of the node.
        """
        return self.getNode()["lineno"]

    def toTuple(self):
        """Return the DataNode as a tuple, where all attributes of the class are now stored in said tuple.

        Returns:
            tuple: `(id, type, varName, funcName, callName, filename, lineno, finding_type)`
        """
        return (
            self.id,
            self.getType(),
            self.varName,
            self.getFuncName(),
            self.getCallName(),
            self.getFileName(),
            self.getLineNumber(),
            self.finding_type,
        )

    def to_path_repr(self) -> Tuple[int, str]:
        """Return the Node represented in the same format that is used in the DataFlows.

        Returns:
            Tuple[int, str]: Pair of node ID and variable name.
        """
        return (self.id, self.varName)

    def getFinding(self) -> Optional[AbstractDetector.Finding]:
        """Lookup a DataNode's security finding. Can return None if the DataNode is not interesting.

        Returns:
            Optional[SecurityDetector.Finding]: None if no finding, otherwise a SecurityDetector finding.
        """
        findings = self.getAllFindings()
        if not findings:
            return None
        return findings[-1]

    def getAllFindings(self) -> List[AbstractDetector.Finding]:
        """Get all findings for a node since a node may have multiple nested functions, each with their own finding.

        Raises:
            Exception: Raised when there is no Security Detector Manager.

        Returns:
            List[AbstractDetector.Finding]: List of findings.
        """
        global SECURITY_DETECTOR_MANAGER
        if SECURITY_DETECTOR_MANAGER:
            return SECURITY_DETECTOR_MANAGER.lookup_node_id(self.id)
        else:
            raise Exception("No Security Detector manager initialized.")

    def toApi(self) -> Optional[str]:
        """Convert a data node into it's contained APIs.

        This is done via looking up the data node through the Detector interfaces.

        Returns:
            Optional[str]: An API if this is an API call, otherwise None.
        """
        f = self.getFinding()
        if f and f.score.score_type is ScoreType.API:
            return f.score.categories.get("url", None)
        return None

    @staticmethod
    def lookup(node_id: int):
        """Lookup a data node from all known, registered data nodes.

        Args:
            node_id (int): The node ID to lookup.

        Returns:
            Optional[DataNode]: Returns the requested data node if it exists, otherwise None.
        """
        return DataNode.all_nodes.get(node_id, None)

    #deprecated. Now personal info is stored as property in Neo4j
    # def setPersonal(self, is_personal: Union[str, Iterable[str]]) -> bool:
    #     if isinstance(is_personal, str):
    #         self.personal = list(set([*self.personal, is_personal]))
    #     else:
    #         self.personal = list(set([*self.personal, *is_personal]))
    #     return self.personal is not PersonalDataMatcher.NO_MATCH


class DataFlowPath:
    """Used to store information of the individual paths created by data flow traversals"""

    def __init__(self, nodeID: int = -1, varName: str = "", pathList:List[int] = []):
        self.id: int = -1
        self.path: List[int] = [nodeID]
        if pathList:
            self.path = pathList
        self.score: Optional[FlowScore] = None

    def __repr__(self) -> str:
        path_str = [str(i) for i in self.path]
        return f"""DataFlowPath[{", ".join(path_str)}]"""

    def copy(self):
        p = DataFlowPath(self.id)
        p.id = self.id
        p.path = list(self.path)
        p.score = self.score
        return p

    def __eq__(self, other) -> bool:
        if isinstance(other, DataFlowPath):
            return self.path == other.path
        else:
            return False

    def __ne__(self, other) -> bool:
        return self == other

    def __hash__(self) -> int:
        return hash(tuple(self.path))

    def insert(self, nodeID: int):
        """Insert node ID to the path.

        Args:
            valuePair (Tuple[int, str]): Pair to append to data flow path.
        """
        assert isinstance(nodeID, int)
        self.path.append(nodeID)

    def insertNode(self, node: DataNode):
        """Insert a node into the path. The node is converted to a tuple and then self.insert is called.

        Args:
            node (DataNode): Node to append to the path.
        """
        assert isinstance(node, DataNode)
        self.insert(node.id)

    def getHead(self) -> int:
        """Get the first node in the path.

        Returns:
            int: ID of first node in path.
        """
        return self.path[0]

    def getTail(self) -> int:
        """Get the last node of the path.

        Returns:
            int: The last node ID.
        """
        return self.path[-1]

    def insertPath(self, path):
        """Place another DataFlow path at the end of the current.

        Args:
            path (DataFlowPath): The path to append to the end of this path.
        """
        assert isinstance(path, DataFlowPath)
        self.path.extend(path.path)

    def insertHead(self, nodeID: int):
        """Insert a node at the beginning of the linked list, placing the current head after the provided one.

        Args:
            head (DataNode): DataNode to replace the current head.
        """
        assert isinstance(nodeID, int)
        self.path.insert(0, nodeID)

    def insertHeadNode(self, node: DataNode):
        """Insert a node at the beginning of the linked list, placing the current head after the provided one.

        Args:
            head (DataNode): DataNode to replace the current head.
        """
        assert isinstance(node, DataNode)
        self.path.insert(0, node.id)

    def isValid(self) -> bool:
        """Return whether or not the linked list is valid; e.g. has a head and tail.

        Returns:
            bool: True if valid, false otherwise
        """
        return bool(self.path)

    def scoreFlow(self):
        """Score the DataFlow. Intended to be ran at the end of the analysis.

        Raises:
            Warning: Raised if add_to_paths_database has not been called for this flow yet.
            Warning: Raised if this flow already has a score.
        """
        # First, path must saved. Thus, it must have some ID assigned to it.
        if self.id < 0:
            raise Warning("This path has not been assigned an ID yet.")
        elif self.score:
            raise Warning("This flow has already been assigned a score.")

        path_list = self.toDataNodeList()
        labels = [n.getFinding() for n in path_list]
        labels_scores = [None if not f else f.score for f in labels]
        labels = [None if not s else s.score_type for s in labels_scores]
        label_set = set(labels).difference({None})

        flow_security = FlowSecurity.NO_SECURITY_SAVED
        encryption: List[str] = []
        # if not ("database" in labels or "storage" in labels):
        if not label_set.intersection({ScoreType.DATABASE, ScoreType.STORAGE, ScoreType.API}):
            flow_security = FlowSecurity.NOT_SAVED
        elif ScoreType.API in label_set and ScoreType.CRYPTOGRAPHY not in label_set:
            # Handle the case that there is an API call.
            no_http = False
            for i, score_type in enumerate(labels):
                score = labels_scores[i]
                if (
                    score_type == ScoreType.API
                    and score
                    and score.categories.get("uses_https", False)
                ):
                    no_http = True
                    break
            if no_http:
                flow_security = FlowSecurity.NO_SECURITY_SAVED
            else:
                flow_security = FlowSecurity.LOW_SECURITY_SAVED
        else:
            state_of_the_art, maintained, generic = False, False, True
            for index, label in enumerate(labels):
                if label in {ScoreType.DATABASE, ScoreType.STORAGE, ScoreType.API}:
                    # Cannot have a storage before encryption and be secure.
                    break
                elif label == ScoreType.CRYPTOGRAPHY:
                    finding = path_list[index].getFinding()
                    # TODO: Make sure that generic detectors are overwritten by explicit onces (choose the best(?) detector)
                    if finding and finding.score:
                        state_of_the_art = finding.score.categories.get(
                            "is_state_of_the_art", False
                        )
                        maintained = finding.score.categories.get("is_maintained", False)
                        generic = finding.score.categories.get("generic", False)
                        if finding.score.encryption_method:
                            encryption.append(finding.score.encryption_method)
                        flow_security_temp = FlowSecurity.create_from_finding(
                            state_of_the_art, maintained, generic
                        )

                        # Keep only the highest score.
                        if flow_security.value < flow_security_temp.value:
                            flow_security = flow_security_temp

        self.score = FlowScore(self.id, flow_security, encryption)

    def equal(self, path) -> bool:
        """Compare two paths and return if they are equal (contain the same pairs in the same order).

        Args:
            path (DataFlowPath): Path to compare equality to.

        Returns:
            bool: True if the paths are logically identical, false otherwise.
        """
        if len(self.path) != len(path.path):
            return False
        zipped = zip(self.path, path.path)
        for node1, node2 in zipped:
            nodeID1 = node1
            nodeID2 = node2
            if nodeID1 != nodeID2:
                return False
        return True

    @staticmethod
    def filterNonPersonal(pathList):
        """Return a list of segments of paths (without duplicates) consisted of dealing with personal data only.
        Assume that the first node is a personal data node

        Args:
            pathList (List[DataFlowPath]): List of paths.

        Returns:
            List[DataFlowPath]: Modified list of data flows, now only with personal info.
        """

        ##
        # emailData = PersonalData(PersonalData.personalDataCategory[0])
        # firstNameData = PersonalData(PersonalData.personalDataCategory[1])
        # lastNameData = PersonalData(PersonalData.personalDataCategory[2])
        # passwordData = PersonalData(PersonalData.personalDataCategory[3])
        # addressData = PersonalData(PersonalData.personalDataCategory[4])
        # countryData = PersonalData(PersonalData.personalDataCategory[5])
        # stateData = PersonalData(PersonalData.personalDataCategory[6])
        # zipcodeData = PersonalData(PersonalData.personalDataCategory[7])
        # postcodeData = PersonalData(PersonalData.personalDataCategory[8])
        # cityData = PersonalData(PersonalData.personalDataCategory[9])
        # birthData = PersonalData(PersonalData.personalDataCategory[10])
        # usernameData = PersonalData(PersonalData.personalDataCategory[11])
        # IPData = PersonalData(PersonalData.personalDataCategory[12])

        # if DISABLE_PERSONAL_FILTERING:
        #     return pathList

        newList = []
        # Add segmented paths
        path: DataFlowPath
        for path in pathList:
            tempPath = DataFlowPath(path.getHead())
            for node in path.toDataNodeList():
                if node.personal:
                    if tempPath:
                        tempPath.insertNode(node)
                    else:
                        tempPath = DataFlowPath(*node.to_path_repr())
                else:
                    if tempPath:
                        newList.append(tempPath)
                        tempPath = None

        # remove duplicates
        sortedPaths = sortBySourceAndSink(newList)
        newList = []
        for i in range(len(sortedPaths) - 1):
            isDuplicate = False
            for j in range(i + 1, len(sortedPaths)):
                # The paths are sorted by source and sink. If we reach to the point where sources and sinks are not equal, we don't need to search further.
                if (sortedPaths[i].getHead() != sortedPaths[j].getHead()) or (
                    sortedPaths[i].getTail() != sortedPaths[j].getTail()
                ):
                    break
                if sortedPaths[i].equal(sortedPaths[j]):
                    isDuplicate = True
            if not isDuplicate:
                newList.append(sortedPaths[i])

        return newList

    def printPathInfo(self, verbose=True):
        """Print detailed path info.

        Args:
            verbose (bool, optional): If true, prints detailed path info. If false, prints concise path info. Defaults to True.
        """
        node_list: List[DataNode] = self.toDataNodeList()
        print(node_list)

    def addToPathsDatabase(self, commit: bool = True, conn: Optional[Connection] = None):
        """Add this data flow path to the Neo4j database for data flows.

        Args:
            graph (py2neo.Graph): The Neo4j connector. This will use the database `paths`. If the database does not exist, py2neo will probably throw an error.
        """

        # Set this path's ID
        if self.id == -1:
            global DATA_FLOW_COUNTER, ALL_PATHS, __PLUGIN_ID
            path_id = DATA_FLOW_COUNTER
            ALL_PATHS[path_id] = self
            DATA_FLOW_COUNTER += 1
            self.id = path_id

            data: List[Tuple[int, int, int, str, str, str, str, str, int, str]] = list()
            for i, n in enumerate(self.toDataNodeList()):
                data.append(
                    (
                        self.id,
                        int(i),
                        n.id,
                        n.getType(),
                        n.varName,
                        n.getFuncName(),
                        n.getCallName(),
                        n.getFileName(),
                        n.getLineNumber(),
                        n.finding_type,
                    )
                )
            write_data_flow_path_row_many(data)

    def toList(self) -> List[int]:
        """Get the list representation of the path.

        Returns:
            List[Tuple[int, str]]: List of pairs of node ID and variable name.
        """
        return self.path

    def toNodeList(self) -> List[Dict[str, Any]]:
        return [getNode(i) for i in self.path]

    def toDataNodeList(self) -> List[DataNode]:
        l: List[DataNode] = [DataNode.all_nodes.get(i, None) for i in self.path]
        return l


class DataFlowGraph:
    """Used to store information of the graph created by data flow traversals"""

    def __init__(self):
        """a dict
        #Updated key: (nodeID)
                nodeID: node ID where an edge starts
                Update: only nodeID is used as key because we currently track individual variables instead and only one variable exists for one ID.
               this pair is used as key to uniquely identify DataNode objects because multiple variables can traverse through the same node (e.g. in a function call with multiple arguments)
        value: a set of node ID where an edge would end (use set to avoid duplicated edges)
               example: {(1,'email'):{(2,'email'),(3,'email')}} would mean there are edges (1,2) and (1,3) with varName 'email'. Reason for using a dictionary is to help traverse and query the graph be faster
        """
        self.edges: Dict[int, Set[int]] = {}

        """a dict
        keeps track of all relevant nodes in the graph so there'd be no need to create copies of DataNode objects that contain the same info in data flow tracking.
        key: (nodeID)
        value: node:DataNode
                
               example: {(1):<DataNode object>}
        """
        self.nodes: Dict[int, DataNode] = {}

    def insertEdge(self, startNode: DataNode, endNode: DataNode) -> bool:

        """Insert an edge into the graph
        Input:
            startNodeID and starVarName: nodeID and varName of the start node
            endNodeID and endVarName: nodeID and varName of the end node
        Output:
            this method requires that both start node and end node are already in the graph with corresponding DataNode object,
            or else there can be an edge between non existent nodes

        Returns True if the edges is successfully inserted and False if either of the node does not exist in the graph
        """
        # startTuple = (startNode.id, startNode.varName)
        # endTuple = (endNode.id, endNode.varName)

        # cannot have an edge from a node to itself
        if startNode.id == endNode.id:
            return False
        # case where there has been previous edges starting from the given start node

        if startNode.id in self.edges and endNode.id in self.nodes:
            self.edges[startNode.id].add(endNode.id)
            return True
        # case where there has not been previous edges starting from the given start node, but the start node and end node are both in the graph
        elif (startNode.id in self.nodes) and (endNode.id in self.nodes):
            self.edges[startNode.id] = {
                endNode.id,
            }
            return True
        # the start node and/or end node are not in the graph
        else:
            print("Temporary debug message: edge is inserted without adding the nodes to the graph")
            return False

    def deleteEdge(self, startNodeID: int, endNodeID: int) -> bool:
        """Delete an edge from the graph.

        Args:
            startNodeID (int): The starting node's ID.
            endNodeID (int): The ending node's ID.

        Returns:
            bool: True if there is an edge matching the input parameters and that it was deleted. False otherwise.
        """
        if startNodeID in self.edges.keys():
            if endNodeID in self.edges[startNodeID]:
                self.edges[startNodeID].remove(endNodeID)
                return True
        return False

    def insertNode(self, dataNode: DataNode, personalDataType: Optional[str] = None):
        """insert a node into the graph
        Input:
            dataNode: DataNode object to insert into the graph
            personDataType: category of personal data of the dataNode ("other" if the category is not found in PersonalData.personalDataCategory)
        Output:
            return True if node successfully inserted into the graph.
            return False if node already exists in graph
        """

        if dataNode.id not in self.nodes.keys():
            self.nodes[dataNode.id] = dataNode
            return True
        else:
            return False

    def deleteNode(self, dataNode: DataNode):
        if dataNode.id in self.nodes:
            del self.nodes[dataNode.id]
            del self.edges[dataNode.id]
            for i in self.edges:
                if dataNode.id in self.edges[i]:
                    self.edges[i].remove(dataNode.id)

    def getNode(self, nodeID: int) -> Optional[DataNode]:
        """Retrieve a DataNode object by nodeID and varName (if it is in the graph)
        Input:
            nodeID: id of the data node
            varName: varName attribute of the data node
        Output:
            the matching DataNode object
            or False if the node does not exist in the current DataFlowGraph object
        """
        return self.nodes.get(nodeID, None)

    def importGraphToNeo4j(self, sourceList: List[DataNode]):
        """Imports the data flow graph to Neo4j. This function uses a list of sources as start, and
            uses BFS to traverse the graph until the graph cannot be traversed further. New edges are added during the traversal.

        Input:
            sourceList: a list of DataNode objects that are sources of paths. This is supplied to make complete graph traversal less expensive
        Outcome:
            edges are added in the following format:
                relationship type: {Personal data type in upper case}+ '_FLOWS' (e.g. 'EMAIL_FLOWS')
                relationship attribute: varName (indicates the varName of the start node. e.g. (1,'a')->(2,'b') would have an edge with varName = 'a')
                    this attribute is used to keep track of which variable flows to the next node
        """
        for source in sourceList:
            # first verify that the object is in the graph
            if source.id not in self.nodes:
                print("source " + str((source.id, source.varName)) + "not found in the graph")
                pass
            currentNodes = [source.id]
            while currentNodes:
                tempNode = currentNodes.pop(0)
                newfringe = self.getNewFringeImport(tempNode)
                currentNodes.extend(newfringe)

    def getAllPaths(self) -> Dict[str, List[DataFlowPath]]:
        """Get all sources in the graph, then all paths from sources to sinks"""
        allSources = self.getAllSources()
        return self.getAllPathsFromSource(allSources)

    def getAllSources(self) -> List[DataNode]:
        allSources: List[DataNode] = []
        for nodeA in self.nodes:
            isSource = True
            for nodeB in self.edges:
                if nodeA in self.edges[nodeB]:
                    isSource = False
                    break
            if isSource:
                allSources.append(self.nodes[nodeA])
        return allSources

    def getAllPathsFromSource(self, sourceList: List[DataNode]) -> Dict[str, List[DataFlowPath]]:
        """Returns all paths to sinks from a given list of sources as recorded in the graph object. Uses BFS to achieve the traversal.
        Output:
            returns a dict of all paths grouped by personal data type
            key: personal data type
            value: list of DataFlowPath objects
        """
        resultDict: Dict[str, List[DataFlowPath]] = {}
        for source in progress_bar(sourceList):
            # first verify that the object is in the graph
            if source.id not in self.nodes:
                print("source " + str((source.id, source.varName)) + "not found in the graph")
                pass

            tempPath = DataFlowPath(source.id, source.varName)
            currentPaths = [tempPath]
            finishedPaths = []
            while currentPaths:
                currentPath = currentPaths.pop(0)
                newPaths = self.getNewFringeExport(currentPath)
                if not newPaths:
                    finishedPaths.append(currentPath)
                else:
                    currentPaths.extend(newPaths)
            for personalType in self.nodes[source.id].personal:
                if personalType in resultDict:
                    resultDict[personalType].extend(finishedPaths)
                else:
                    resultDict[personalType] = finishedPaths
        return resultDict

    def getAssignLocationFromSink(self, sinkNodeID: int) -> List[DataFlowPath]:
        """Get a list of all paths starting at an AST_ASSIGN node leading to a specific sink (used to trace where a variable is assigned).

        Returns:
            List[DataFlowPath]: list of paths from sink to source via personal data type.
        """
        # # First get a set of sinks.

        # for node_id, node in self.nodes.items():
        #     for finding in node.getAllFindings():
        #         if finding and finding.score.is_sink():
        #             sinks.add(node_id)

        # Traverse from sinks back.
        sink_paths: List[DataFlowPath] = [DataFlowPath(sinkNodeID, self.nodes[sinkNodeID].varName)]

        queue: List[int] = [sinkNodeID]
        while queue:
            current = queue.pop(0)
            edges = [k for k, v in self.edges.items() if current in v]

            queue.extend(edges)
            paths = [p for p in sink_paths if p.getHead() == current]
            for p in paths:
                if edges:
                    sink_paths.remove(p)
                    for e in edges:
                        # if e is an assignee, stop here
                        if not isNodeAssignee(current):
                            p_copy = p.copy()
                            p_copy.insertHead(e)
                            sink_paths.append(p_copy)
                            # print(sink_paths)

        return sink_paths

    def getAllPathsToSink(self, sinkNodeID) -> Dict[str, List[DataFlowPath]]:
        """Get a list of all paths leading to a specific sink.

        Returns:
            Dict[str, List[DataFlowPath]]: Dictionary of paths from sink to source via personal data type.
        """

        # # First get a set of sinks.
        sinks: Set[int] = set()
        sinks.add(sinkNodeID)
        # for node_id, node in self.nodes.items():
        #     for finding in node.getAllFindings():
        #         if finding and finding.score.is_sink():
        #             sinks.add(node_id)

        # Traverse from sinks back.
        sink_paths: Dict[int, List[DataFlowPath]] = {
            i: [DataFlowPath(i, self.nodes[i].varName)] for i in sinks
        }
        for sink_id in sink_paths.keys():
            queue: List[int] = [sink_id]
            while queue:
                current = queue.pop(0)
                edges = [k for k, v in self.edges.items() if current in v]
                queue.extend(edges)
                paths = [p for p in sink_paths[sink_id] if p.getHead() == current]
                for p in paths:
                    if edges:
                        sink_paths[sink_id].remove(p)
                        for e in edges:
                            p_copy = p.copy()
                            p_copy.insertHead(e)
                            sink_paths[sink_id].append(p_copy)

        # Now group paths by data type rather than sink ID.
        grouped: Dict[str, Set[DataFlowPath]] = dict()
        for k, v in sink_paths.items():
            for p in v:
                for finding in self.nodes[p.getTail()].getAllFindings():
                    pii_type = finding.score.get_data_type()
                    if not pii_type:
                        continue
                    if pii_type not in grouped.keys():
                        grouped[pii_type] = set()
                    grouped[pii_type].add(p)

        # Convert sets to list and output result.
        output = {k: sorted(list(v), key=lambda x: str(x)) for k, v in grouped.items()}
        return output

    def classifyAllNodesByPersonalData(self) -> Dict[str, List[DataNode]]:
        resultDict: Dict[str, List[DataNode]] = dict()
        for i in self.nodes:
            for personalType in self.nodes[i].personal:
                if personalType in resultDict:
                    resultDict[personalType].append(self.nodes[i])
                else:
                    resultDict[personalType] = [self.nodes[i]]
        return resultDict

    # def getNewFringeImport(self, currentNode: int) -> List[int]:
    #     """deprecated"""
    #     graph = getGraph()

    #     newfringe = []

    #     node = self.nodes.get(currentNode, None)
    #     nextNodes: List[int] = list(self.edges.get(currentNode, []))

    #     if not (node and nextNodes):
    #         return []

    #     # edgesType = self.nodes[currentNode].personal.upper() + "_FLOWS"
    #     for nextNode in nextNodes:
    #         query = f"""
    #         MATCH (n)-[r]->(m) 
    #         WHERE n.id = {currentNode} AND m.id = {nextNode} AND type(r) in {RELATIONSHIP_TYPES}
    #         r.personal = '{node.personal}'
    #         """
    #         graph.run(query)

    #         newfringe.append(nextNode)

    #     return newfringe

    def getNewFringeExport(self, currentPath: DataFlowPath) -> List[DataFlowPath]:
        newfringe: List[DataFlowPath] = []
        lastNode = currentPath.getTail()

        node = self.nodes.get(lastNode, None)
        nextNodes: Set[int] = self.edges.get(lastNode, set())

        if not (node and nextNodes):
            return []

        for nextNode in nextNodes:
            if nextNode not in currentPath.path:
                tempPath = currentPath.copy()
                tempPath.insert(nextNode)
                newfringe.append(tempPath)

        # no update in fringes, so all nodes have reached their sinks
        return newfringe


def sortBySourceAndSink(paths: List[DataFlowPath]) -> List[DataFlowPath]:
    """Return a list of paths sorted via head ID and tail ID.

    Args:
        paths (List[DataFlowPath]): List of data flow paths to sort.

    Returns:
        List[DataFlowPath]: Sorted list of data flow paths.
    """
    temp = sorted(paths, key=lambda p: p.getTail())
    return sorted(temp, key=lambda p: p.getHead())
