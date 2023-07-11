from ActionHook import ActionHook
from ControlFlowTracking import ControlFlowWPFunctions
from NeoHelper import getNode
from NeoGraph import getGraph
from functools import lru_cache
from Settings import LRU_CACHE_SIZE
import re

@lru_cache(maxsize=LRU_CACHE_SIZE)
def isNodeAdmin(nodeID):
    nodeObj = getNode(nodeID)
    if 'classname' in nodeObj and ActionHook.isAdminClass(nodeObj['classname']):
        return True
    
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{type:'AST_CALL',funcid:{nodeObj.get('funcid',-1)}}})-[:PARENT_OF]->(x:AST{{childnum:0,type:'AST_NAME'}})-[:PARENT_OF]->(name:AST{{childnum:0,type:'string'}})
    WHERE name.code IN {ControlFlowWPFunctions.WPFunctionFlags["isAdmin"]}
    RETURN n
    """
    result = graph.run(cypher = query).data()
    if result and len(result)>0:
        return True
    if isNodeInAdminFileOrDirectory(nodeID):
        return True
    return False
@lru_cache(maxsize=LRU_CACHE_SIZE)
def isNodeInAdminFileOrDirectory(nodeID):
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{id:{nodeID}}})<-[:PARENT_OF|FILE_OF|DIRECTORY_OF*]-(file:Filesystem)
    RETURN file.name
    """
    result = graph.run(cypher=query).data()
    if result:
        for r in result:
            fileName = r['file.name']
            if re.compile(".*(admin).*", re.IGNORECASE).match(fileName):
                return True
    return False
