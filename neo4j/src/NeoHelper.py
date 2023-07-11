import concurrent.futures
import logging

import traceback
from functools import lru_cache

from typing import Any, Dict, List, Optional, Set, Tuple

import py2neo
from py2neo import cypher
from bs4 import BeautifulSoup
from selenium import webdriver
from Args import getPluginLink

from NeoGraph import getGraph
from Settings import LRU_CACHE_SIZE, MAX_NODE_CODE_LENGTH, ROOT_DIR
import tldextract
import validators


def requiresAnalysis():
    graph = getGraph()
    query = f"""
    MATCH (n:PERSONAL)
    RETURN n LIMIT 1
    """
    result = graph.evaluate(cypher=query)
    if result:
        return True
    return False

def isURLThirdParty(url):
    if not isUrlValid(url):
        return False
    #currently, there is no first party, because the plugin party itself is a third party to the site owner.
    return True
    # return not compareURLDomain(url,getPluginLink())


def compareURLDomain(url1, url2):
    """Compare if two given urls have the same domain.
    """
    domain1 = tldextract.extract(url1)[1]
    domain2 = tldextract.extract(url2)[1]
    return domain1 == domain2


def isUrlValid(string):
    """Check if a string is a valid URL
    
    """
    if validators.url(string):
        return True
    return False


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getVarChild(nodeID: int) -> List[int]:
    """Get all the AST_VAR children of the nodeID
    Returns a list of IDs
    """
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{id:{nodeID}}})-[:PARENT_OF*0..10]->(m:AST{{type:"AST_VAR"}})
    RETURN COLLECT(DISTINCT m.id)
    """
    result = graph.evaluate(query)
    if not result:
        return []
    return sorted([int(i) for i in result])


"""Gets a list of the parameters for an AST_METHOD
Input:
    ASTMethodID: the node ID for a node of type AST_METHOD
Output:
    Returns two lists, the first being the names of the parameters and second being the node id for the parameters.
    Returns None if there are not parameters or if bugs happened.
"""


def ASTMethodGetParameterList(ASTMethodID: int, ) -> Optional[Tuple[List[str], List[int]]]:
    query = f"""
    MATCH (n:AST)-[:ENTRY]->(x:Artificial)
    WHERE n.id = {ASTMethodID}
    RETURN x.id LIMIT 1
    """
    graph = getGraph()
    currentID = graph.evaluate(query)
    if not currentID:
        # logging.error("Bug here. No corresponding entry node to AST Method with ID: "+ str(ASTMethodID)+". Check if the corresponding node to the ID is of type AST_METHOD.")
        return None
    paramList = []
    while True:
        tempQuery = f"""
        MATCH (n)-[:FLOWS_TO]->(m:AST)
        WHERE n.id = {currentID} AND m.type = 'AST_PARAM'
        RETURN m.id
        """

        tempResult = graph.run(cypher=tempQuery).data()
        if len(tempResult) == 0:
            break
        currentID = tempResult[0]["m.id"]
        paramList.append(currentID)
    if len(paramList) == 0:
        return None
    else:
        # get names for all the parameters
        paramName = []
        for i in paramList:
            tempQuery = ("""
            MATCH (n:AST)-[:PARENT_OF]->(m:AST) WHERE n.id = """ + str(i) + """ AND m.type = 'string' RETURN m
            """)
            tempResult = graph.run(cypher=tempQuery).data()
            if len(tempResult) == 0:
                # the parameter can have more than one string children because of default value set to the parameter
                logging.error("Bug here. No corresponding string node to AST Param with ID: " + str(i) +
                              ". Check if the corresponding node to the ID is of type AST Param.")
                return None
            paramName.append(sorted(tempResult, key=lambda x: x["m"]["childnum"])[0]["m"]["code"])
        return paramName, paramList


def unique(l: List[Any]) -> List[Any]:
    """Keep only the unique values of a list. This operation is not stable.

    Args:
            l (List[Any]): List to trim.

    Returns:
            List[Any]: List of only unique elements from l.
    """
    return list(set(l))


global __node_cache, __lru_cache_miss, __manual_cache_hit
__node_cache: Dict[int, Dict[str, Any]] = dict()
__lru_cache_miss: int = 0
__manual_cache_hit: int = 0


def getNode(node_id: int) -> Dict[str, Any]:
    """Get a node given a node's ID.

    Nodes returned by this function are cached for speed at the expense of memory. This function also assumes accesses are spatially close, so nearby nodes are cached when a single node is accessed.

    Args:
            node_id (int): The ID of the node to lookup in Neo4j.

    Returns:
            Dict[str, Any]: Empty dictionary if the node could not be found. Otherwise returns a dictionary of the node's values, where each key is a string.
    """
    global __node_cache, __lru_cache_miss, __manual_cache_hit

    if node_id in __node_cache.keys():
        __manual_cache_hit += 1
        return __node_cache[node_id]

    graph = getGraph()

    start = max(node_id - 15, 0)
    end = node_id + 15
    to_fetch = [str(x) for x in range(start, end) if x not in __node_cache.keys()]
    query = f'MATCH (a) WHERE a.id in [{", ".join(to_fetch)}] RETURN a'

    node_result = graph.run(query)
    for result in node_result:
        node = dict(result['a'])
        nid = node['id']
        __node_cache[nid] = node

    __lru_cache_miss += 1
    return __node_cache.get(node_id, {})


global __node_children_cache
__node_children_cache: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getNodeChildren(nodeID: int, edge_type: str = "PARENT_OF") -> List[Dict[str, Any]]:
    """Get a node's children, ordered by child number.

    Args:
            nodeID (int): The parent node's ID.
            edge_type (str, optional): Specific edge type to traverse. Defaults to "PARENT_OF".

    Returns:
            List[Dict[str, Any]]: List of nodes converted to dicts. Should be order from lowest childnum to highest.
    """
    global __node_children_cache
    if (nodeID, edge_type) in __node_children_cache.keys():
        return __node_children_cache[(nodeID, edge_type)]

    graph = getGraph()
    query = f"""
    MATCH (a{{id:{nodeID}}})-[:{edge_type}]->(b)
    WITH b ORDER BY b.childnum
    RETURN COLLECT(DISTINCT b.id)
    """
    results = graph.evaluate(query)
    output = []
    for i in results if results else []:
        output.append(getNode(i))
    return output


global __explicitly_cached_nodes
__explicitly_cached_nodes: Set[Tuple[int, str]] = set()


def cacheAllNodeChildren(node_id: int, edge_type: str = "PARENT_OF", node_label: str = "AST"):
    global __node_cache, __node_children_cache, __explicitly_cached_nodes

    if node_id in __explicitly_cached_nodes:
        return
    __explicitly_cached_nodes.add((node_id, edge_type))

    query = f"""
    MATCH (n:{node_label}{{id:{node_id}}})-[:{edge_type}*0..]->(p:{node_label})-[:{edge_type}]->(c:{node_label})
    RETURN p, COLLECT(c)
    """
    results = getGraph().run(query)
    if not results:
        return
    try:
        for parent_node, children_nodes in results:
            parent_dict = dict(parent_node)
            __node_cache[parent_dict["id"]] = parent_dict
            __explicitly_cached_nodes.add(parent_dict["id"])

            children_dict = [dict(c) for c in children_nodes]
            children_dict.sort(key=lambda x: x["childnum"])
            for child in children_dict:
                __node_cache[child["id"]] = child
                __explicitly_cached_nodes.add(parent_node["id"])

            __node_children_cache[(parent_dict["id"], edge_type)] = children_dict
    except:
        return


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getNodeAllChildrenAsSubgraph(nodeID: int, edge_type: str = "PARENT_OF") -> py2neo.Subgraph:
    """Get a node's children, ordered by child number.

    Args:
            nodeID (int): The parent node's ID.
            edge_type (str, optional): Specific edge type to traverse. Defaults to "PARENT_OF".

    Returns:
            List[Dict[str, Any]]: List of nodes converted to dicts. Should be order from lowest childnum to highest.
    """
    graph = getGraph()
    query = f"""
    MATCH p=(a{{id:{nodeID}}})-[:{edge_type}*]->(b)
    RETURN p
    """
    results = graph.run(query)
    return results.to_subgraph()


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getNodeType(nodeID: int) -> str:
    """Return the 'type' attribute of an AST node
    Input:
            nodeID: the node ID of an AST node
    Output:
            returns the 'type' attribute of the AST node
    """
    return getNode(nodeID).get("type", "")


@lru_cache(maxsize=LRU_CACHE_SIZE)
def isNodeAssignee(nodeID: int) -> bool:
    graph = getGraph()
    # check if the variable is assignee
    query = f"""
    MATCH (n)<-[:PARENT_OF]-(m) WHERE n.id = {nodeID}
    RETURN n.childnum, m.type
    """
    result = graph.run(cypher=query).data()
    if result:
        childnum = result[0]["n.childnum"]
        mType = result[0]["m.type"]
        if childnum == 0 and mType == "AST_ASSIGN":
            return True
    return False


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getVarName(nodeID: int) -> Optional[str]:
    # graph = getGraph()
    node = getNode(nodeID)
    nodeType = node.get("type", "")

    if nodeType == "AST_VAR":
        children = [c for c in getNodeChildren(nodeID) if c.get("type") == "string"]
        if not children:
            return concatChildString(nodeID)
        else:
            return children[0].get("code", None)

    elif nodeType == "AST_PARAM":
        children = [c for c in getNodeChildren(nodeID) if c.get("type") == "string"]
        if not children:
            return concatChildString(nodeID)
        else:
            return children[0].get("code", None)

    elif nodeType == "AST_CONST":
        children1 = [c for c in getNodeChildren(nodeID) if c.get("type") == "AST_NAME"]
        if not children1:
            return None
        children2 = [c for c in getNodeChildren(children1[0]["id"]) if c.get("type") == "string"]
        if not children2:
            return None
        return children2[0].get("code", None)

    return None


def escapeQuotes(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


@lru_cache(maxsize=LRU_CACHE_SIZE)
def concatTree2(nodeID: int, nodeLabel: str = "AST") -> str:
    graph = getGraph()
    query = f"""
    MATCH p=(n:{nodeLabel}{{id:{nodeID}}})-[:PARENT_OF*0..]->(m{nodeLabel})
    UNWIND relationships(p) as r
    RETURN [n, COLLECT(DISTINCT([startNode(r), endNode(r)]))]
    """
    results = graph.evaluate(query)
    if not results:
        result = graph.evaluate(f""" MATCH (n:{nodeLabel}{{id:{nodeID}}}) RETURN n """)
        if not result:
            return ""
        results = (result, [])
    try:
        start, result = results
    except:
        return ""
    start_d = dict(start)

    rels: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [(dict(start), dict(end)) for start, end in result]
    node_dict: Dict[int, Dict[str, Any]] = {start_d["id"]: start_d}
    for p, c in rels:
        node_dict[p["id"]] = p
        node_dict[c["id"]] = c
    rels_dict: Dict[int, List[int]] = dict()
    for p_id in node_dict.keys():
        children: List[Dict[str, Any]] = [c for p, c in rels if p["id"] == p_id]
        children.sort(key=lambda x: x["childnum"])
        rels_dict[p_id] = [c["id"] for c in children]

    return _concatTree2(nodeID, node_dict, rels_dict)


def _concatTree2(start: int, node_dict: Dict[int, Dict[str, Any]], rels_dict: Dict[int, List[int]]) -> str:
    output = ""
    try:
        node = node_dict[start]
    except:
        return output
    node_type = node["type"]
    children = rels_dict.get(start, [])

    # Entry
    if node_type == "AST_VAR":
        output += "$"
    elif node_type == "AST_PARAM":
        output += "$"
    elif node_type in ("AST_ARG_LIST", "AST_ARG_LIST"):
        output += "("
    elif node_type == "AST_ARRAY":
        output += "["
    elif node_type == "AST_UNARY_OP" and "UNARY_BOOL_NOT" in node.get("flags", []):
        output += "!"
    elif node_type == "AST_UNARY_OP" and "UNARY_MINUS" in node.get("flags", []):
        output += "-"
    elif node_type == "AST_UNARY_OP" and "UNARY_SILENCE" in node.get("flags", []):
        output += "@"

    # Self
    if node_type in ("AST_ARG_LIST", "AST_ARG_LIST", "AST_ARRAY"):
        output += ", ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type in ("AST_METHOD_CALL", "AST_STATIC_CALL"):
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"{strs[0]}->{strs[1]}{strs[2]}"
    elif node_type == "AST_EMPTY":
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"empty({strs[0]})"
    elif node_type == "AST_ISSET":
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"isset({strs[0]})"
    elif node_type == "AST_INSTANCEOF":
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"{strs[0]} instanceof {strs[1]}"
    elif node_type == "string":
        # Have to get the parent to determine if quotes are needed.
        parent = [k for k, v in rels_dict.items() if start in v]
        if not parent or node_dict[parent[0]]["type"] not in (
                "AST_VAR",
                "AST_NAME",
                "AST_PROP",
                "AST_CALL",
                "AST_METHOD_CALL",
                "AST_STATIC_CALL",
        ):
            if "code" in node:
                output += f'"{str(node["code"])}"'
            else:
                output += '""'

        else:
            output += str(node["code"])
    elif node_type == "integer":
        output += str(node["code"])
    elif node_type == "AST_ARRAY_ELEM":
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        if len(strs) == 2 and strs[1]:
            output += f"{strs[1]} => {strs[0]}"
        else:
            output += f"{strs[0]}"
    elif node_type == "AST_DIM":
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"{strs[0]}[{strs[1]}]"
    elif node_type == "AST_PROP":
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"{strs[0]}->{strs[1]}"
    elif node_type == 'AST_CLASS_CONST':
        strs = [_concatTree2(c, node_dict, rels_dict) for c in children]
        output += f"{strs[0]}::{strs[1]}"
    elif node_type == "AST_BINARY_OP" and "BINARY_ADD" in node.get("flags", []):
        output += " + ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_BOOL_AND" in node.get("flags", []):
        output += " && ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_BOOL_AND" in node.get("flags", []):
        output += " || ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_CONCAT" in node.get("flags", []):
        output += " . ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_DIV" in node.get("flags", []):
        output += " / ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_EQUAL" in node.get("flags", []):
        output += " == ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_GREATER" in node.get("flags", []):
        output += " > ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_GREATER_OR_EQUAL" in node.get("flags", []):
        output += " >= ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_IDENTICAL" in node.get("flags", []):
        output += " === ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_NOT_EQUAL" in node.get("flags", []):
        output += " != ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_NOT_IDENTICAL" in node.get("flags", []):
        output += " !== ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_SMALLER" in node.get("flags", []):
        output += " < ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_IS_SMALLER_OR_EQUAL" in node.get("flags", []):
        output += " <= ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_MUL" in node.get("flags", []):
        output += " * ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_BINARY_OP" and "BINARY_SUB" in node.get("flags", []):
        output += " - ".join([_concatTree2(c, node_dict, rels_dict) for c in children])
    elif node_type == "AST_STMT_LIST":
        output += "".join([_concatTree2(c, node_dict, rels_dict) + ";\n" for c in children])
    else:
        output += "".join([_concatTree2(c, node_dict, rels_dict) for c in children])

    # Exit
    if node_type in ("AST_ARG_LIST", "AST_ARG_LIST"):
        output += ")"
    elif node_type == "AST_ARRAY":
        output += "]"

    return output


@lru_cache(maxsize=LRU_CACHE_SIZE)
def concatTree(nodeID: int, nodeLabel: str = "AST") -> str:
    return escapeQuotes(concatTree2(nodeID, nodeLabel=nodeLabel))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def concatTreeOld(nodeID: int, nodeLabel: str = "AST") -> str:

    cacheAllNodeChildren(nodeID)

    nodeType = getNodeType(nodeID)

    if nodeType in ["AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"]:
        return concatCallName(nodeID, nodeLabel)

    elif nodeType == "AST_ARRAY":
        return concatArray(nodeID, nodeLabel)

    elif nodeType == "string":
        return f'"{escapeQuotes(getNode(nodeID).get("code", ""))}"'

    elif nodeType == "integer":
        return getNode(nodeID).get("code", "0")

    elif nodeType == "AST_DIM":
        children = getNodeChildren(nodeID)
        return f"""{concatTreeOld(children[0]["id"], nodeLabel)}[{concatTreeOld(children[1]["id"], nodeLabel)}]"""

    elif nodeType == "AST_NAME":
        children = [c for c in getNodeChildren(nodeID) if c.get("type") == "string"]
        if not children:
            return ""
        return children[0].get("code", "")

    elif nodeType in ["AST_VAR", "AST_CONST"]:
        return f"${getVarName(nodeID)}"

    elif nodeType == "AST_PROP":

        children = getNodeChildren(nodeID)
        if len(children) < 2:
            return ""
        return f"""{concatTreeOld(children[0]["id"])}->{concatTreeOld(children[1]["id"])}"""

    else:
        children = getNodeChildren(nodeID)
        return "".join([concatTree(c["id"]) for c in children])


@lru_cache(maxsize=LRU_CACHE_SIZE)
def concatArray(nodeID: int, nodeLabel: str) -> str:
    graph = getGraph()
    arrayElem = f"""
    MATCH (n:{nodeLabel})-[:PARENT_OF]->(elem:{nodeLabel})
    WHERE n.id = {nodeID}
    WITH elem
    MATCH (child0:{nodeLabel})<-[:PARENT_OF]-(elem)-[:PARENT_OF]->(child1:{nodeLabel})
    WHERE child0.childnum = 0 AND child1.childnum = 1
    RETURN child0.id, child1.id
    """
    arrayResult = graph.run(cypher=arrayElem).data()
    arrayStr = "{"
    for elem in arrayResult:
        arrayStr += concatTree(elem["child1.id"]) + ":" + concatTree(elem["child0.id"]) + ", "
    arrayStr = arrayStr[:-2]
    arrayStr += "}"
    return arrayStr


@lru_cache(maxsize=LRU_CACHE_SIZE)
def concatCallName(nodeID: int, nodeLabel: str) -> str:

    # first get the call name:
    callName = getCallName(nodeID)
    if not callName:
        # issues with weird funciton call structure
        callName = "<unknownCallName>"

    graph = getGraph()
    paramString = ""
    paramsQuery = f"""
    MATCH (n:{nodeLabel})-[:PARENT_OF]->(m:{nodeLabel})-[:PARENT_OF]->(args:{nodeLabel})
    WHERE n.id = {nodeID} AND m.type = 'AST_ARG_LIST'
    RETURN args ORDER BY args.childnum ASC
    """
    paramsResult = graph.run(cypher=paramsQuery).data()

    for i in paramsResult:
        if i["args"]["type"] in ["string", "integer"]:
            paramString += '"' + escapeQuotes(i["args"]["code"]) + '",'
        elif i["args"]["type"] in ["AST_VAR", "AST_CONST"]:
            paramString += "$" + str(getVarName(i["args"]["id"])) + ","
        elif i["args"]["type"] in ["AST_CALL", "AST_METHOD_CALL", "AST_STATIC_CALL"]:
            paramString += concatCallName(i["args"]["id"], nodeLabel=nodeLabel) + ","
        else:
            paramString += concatTree(i["args"]["id"]) + ","
    paramString = paramString[:-1]

    if not paramString:
        # print("Error with concatenating params"+str(nodeID))
        return callName + "(" + ")"
    return callName + "(" + paramString + ")"


@lru_cache(maxsize=LRU_CACHE_SIZE)
def concatChildString(nodeID: int, nodeLabel: str = 'AST') -> str:
    """
    Concatenate all of the string of the children of the current node together to form a complete string
    """

    graph = getGraph()
    query = f"""
    MATCH (n:{nodeLabel}{{id:{nodeID}}})-[:PARENT_OF*]->(m:{nodeLabel}{{type:"string"}})
    WITH m ORDER BY m.id ASC
    RETURN COLLECT(m.code)
    """
    results = graph.evaluate(query)
    if not results:
        return ""
    return "->".join([str(s) for s in results])


#deprecated. Should use reverseTrackDataFlowToAssignNoRecord() instead.
@lru_cache(maxsize=LRU_CACHE_SIZE)
def getVarAssignLocation(callID: int, varName: int) -> int:
    """Given a variable name in a method call, we want to find where this variable was assigned
    Output:
            assign node ID
    """
    graph = getGraph()
    query = f"""
    MATCH (call:AST)<-[:REACHES]-(assign:AST)-[:PARENT_OF]->(var:AST)-[:PARENT_OF]->(str:AST)
    WHERE call.id = {callID} AND assign.type = 'AST_ASSIGN' AND var.type = 'AST_VAR' AND str.code = '{varName}'
    RETURN assign.id
    """
    result = graph.evaluate(query)
    if not result:
        return 0
    return result


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getNodeName(nodeID: int) -> str:
    """Return the 'name' attribute of an AST node
    Input:
            nodeID: the node ID of an AST node
    Output:
            returns the 'name' attribute of the AST node
    """
    return getNode(nodeID).get("name", "")


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getASTMethodName(nodeID: int) -> str:
    """Return the name of an AST_METHOD_CALL and AST_STATIC_CALL
    Input:
            nodeID: the node ID of an AST_METHOD_CALL and AST_STATIC_CALL
    Output:
            returns the name of the call
    """
    graph = getGraph()
    query = f"""
    MATCH (x)<-[:PARENT_OF]-(n)-[:PARENT_OF]->(m)
    WHERE n.id = {nodeID} AND x.childnum = 0 AND m.childnum = 1 AND m.type = 'string'
    RETURN m.code, x.id 
    """
    result = graph.run(cypher=query).data()
    if result:
        return concatTree(result[0]["x.id"]) + "." + result[0]["m.code"]
    else:
        return "unknown_JS_call"


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getASTCallName(nodeID: int) -> Optional[str]:
    """Returns the name of an AST_CALL. If the call has no name, returns -1
    Input:
            nodeID: the node ID of an AST_CALL
    Output:
            returns the name of the call
    """
    graph = getGraph()
    query = f"""
    MATCH (n)-[:PARENT_OF]->(x)-[:PARENT_OF]->(m)
    WHERE n.id =  {nodeID} AND x.type = 'AST_NAME' AND m.type = 'string'
    RETURN m.code
    """
    result = graph.run(cypher=query).data()
    if result:
        return result[0]["m.code"]
    else:
        return "unknown_JS_call"


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getCallName(nodeID: int) -> Optional[str]:
    nodeType = getNodeType(nodeID)
    if nodeType == "AST_METHOD_CALL" or nodeType == "AST_STATIC_CALL":
        return getASTMethodName(nodeID)
    elif nodeType == "AST_CALL":
        return getASTCallName(nodeID)
    return None


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getCallArguments(nodeID: int):
    nodeType = getNodeType(nodeID)
    if nodeType in ['AST_CALL', 'AST_METHOD_CALL', 'AST_STATIC_CALL']:
        argList = []
        graph = getGraph()
        query = f"""
        MATCH (n:AST{{id:{nodeID}}})-[:PARENT_OF]->(argList:AST{{type:'AST_ARG_LIST'}})-[:PARENT_OF]->(args:AST)
        RETURN args
        """
        result = graph.run(cypher=query).data()
        if result:
            for i in result:
                argList.append(i['args'])
        return argList
    return []


def eliminateDuplicates(currentVariableName, currentVariableID):
    """Helper function: eliminate all the duplicate variable IDs and their respective variable names"""
    index = 0
    while not index == len(currentVariableID):
        if currentVariableID.count(currentVariableID[index]) > 1:
            currentVariableName.pop(index)
            currentVariableID.pop(index)
        else:
            index += 1


@lru_cache(maxsize=LRU_CACHE_SIZE)
def ASTAssignGetName(nodeID: int) -> List[str]:
    """Returns the variable name of an AST_ASSIGN node
    Input:
            nodeID: node ID of an AST_ASSIGN node
    Output:
            a list of the variable name of the AST_ASSIGN node
    """

    if getNodeType(nodeID) != "AST_ASSIGN":
        print("Error! " + str(nodeID) + " Is not an AST_ASSIGN node")
        return []

    graph = getGraph()
    query = f"""
    MATCH (n)-[:PARENT_OF]->(d)-[:PARENT_OF*0..10]->(m)-[:PARENT_OF]->(x)
    WHERE n.id = {nodeID} AND d.childnum=0 AND m.type = 'AST_VAR' AND x.type = 'string'
    RETURN COLLECT(x.code)
    """
    result: List[str] = graph.evaluate(query)
    if not result:
        return []
    return result

def ASTAssignGetAssignedVar(nodeID: int) -> Optional[int]:
    """In a line of AST_ASSIGN, Get the nodeID of the var that is being assigned a value"""
    graph = getGraph()
    query = f"""
    MATCH (n)-[:PARENT_OF]->(d)-[:PARENT_OF*0..10]->(m)-[:PARENT_OF]->(x)
    WHERE n.id = {nodeID} AND d.childnum=0 AND m.type = 'AST_VAR' AND x.type = 'string'
    RETURN m.id LIMIT 1
    """

    result = graph.evaluate(query)
    if result:
        return int(result)
    else:
        return None


def ASTAssignGetPassInVar(nodeID):
    graph = getGraph()
    query = f"""
    MATCH (n)-[:PARENT_OF]->(d)-[:PARENT_OF*0..10]->(m)-[:PARENT_OF]->(x)
    WHERE n.id = {nodeID} AND d.childnum>0 AND m.type = 'AST_VAR' AND x.type = 'string'
    RETURN x.code
    """
    allVarName = []
    result = graph.run(cypher=query).data()
    for i in result:
        allVarName.append(i["x.code"])
    return allVarName


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getRootOfLine(node_id: int) -> Optional[Dict[str, Any]]:
    """Get the root node of the line of code that node with nodeID is on. Update: returns the node itself if the node is already the root node
    Input:
            nodeID: node ID of a node
    Output:
            outputs the root node of the line of the code that the input node is on.
    """
    graph = getGraph()
    queryParent = f"""
    MATCH p=(n:AST)<-[:PARENT_OF*0..10]-(x:AST)-[:FLOWS_TO]->()
    WHERE n.id = {node_id}
    RETURN x ORDER BY length(p) ASC LIMIT 1
    """
    result = graph.evaluate(queryParent)
    if not result:
        return None
    return dict(result)


def getMaxNodeID() -> int:
    """Get the current maximum node ID.

    Returns:
            int: The highest ID in the Neo4j graph.
    """
    return int(getGraph().evaluate(""" MATCH (n) RETURN MAX(n.id) """))


def binary_concat(entry_id: int, all_nodes: List[Tuple[Dict[str, Any], Dict[str, Any]]], top=True) -> str:
    """Recursively traverse a tree of binary concatenation operators and return a concatenated string that is hopefully
    valid SQL.

    Args:
            entry_id (int): The first ID of the SQL argument tree.
            all_nodes (List[Dict[str, Any]]): All nodes in the tree.

    Returns:
            str: SQL that should be able to be parsed.
    """
    entry_node = None
    children: List[str] = []

    for child, parent in all_nodes:
        if child["id"] == entry_id:
            entry_node = child
            break
    if not entry_node:
        return ""

    # Base case
    if entry_node["type"] == "string":
        return entry_node["code"]
    elif entry_node["type"] == "AST_VAR":
        children.append("$")
        # pass

    for child, parent in all_nodes:
        if parent["id"] == entry_node["id"]:
            s = binary_concat(child["id"], all_nodes, top=False)
            children.append(s)

    if top:
        return "".join(children).strip()
    return "".join(children)


def scrape(websiteURL):
    """Web scraper for privacy policy"""
    driver = webdriver.Chrome(ROOT_DIR + "neo4j/src/chromedriver")
    driver.get(websiteURL)

    content = driver.page_source
    soup = BeautifulSoup(content, features="html.parser")
    return soup


class SQLInfo:

    def __init__(self) -> None:
        self.start_id: int = -1
        self.table_name: str = ""
        self.fields: Set[str] = set()
        self.operation: str = ""
        self.code: str = ""

    def __repr__(self) -> str:
        return f"SQLInfo[id={self.start_id}, table={self.table_name}, operations={self.operations}, fields={self.fields}]"

    @staticmethod
    def table_equals(s1, s2) -> bool:
        if not s1.table_name or not s2.table_name:
            return False
        else:
            return s1.table_name == s2.table_name

    @staticmethod
    def field_equals(s1, s2) -> bool:
        if not s1.fields or not s2.fields:
            return False
        elif "*" in s1.fields or "*" in s2.fields:
            return True
        else:
            return bool(set(s1.fields).intersection(set(s2.fields)))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def getStatementSQLInfo(node_id: int) -> Optional[SQLInfo]:
    output: SQLInfo = SQLInfo()
    graph = getGraph()
    query = f"""
    MATCH (n:AST_SQL{{id:{node_id}}})
    RETURN n
    """
    result = graph.evaluate(query)
    if not result:
        return None
    # print(result)
    output.start_id = result.get("id", -1)

    output.code = result.get("code", "")

    output.table_name = result.get("table", "")

    output.fields = result.get("columns", [])

    output.operation = result.get("type", "")

    return output


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_form_inputs():
    graph = getGraph()

    query = """
    MATCH (form:AST_HTML{type:"AST_HTML_ELEMENT", code:"form"})-[:PARENT_OF*0..]->
        (element:AST_HTML{type:"AST_HTML_ELEMENT"})-[:PARENT_OF]->
        (attribs:AST_HTML{type:"AST_HTML_ATTRIBUTES"})-[:PARENT_OF]->(attrib:AST_HTML{type:"AST_HTML_ATTRIBUTE"})
    MATCH (key:AST_HTML{childnum:0})<-[:PARENT_OF]-(attrib)-[:PARENT_OF]->(value:AST_HTML{childnum:1})
    RETURN form.id, COLLECT([element.id, element.code, key.code, value.code])
    """
    results = graph.run(query)

    forms = dict()
    elements = dict()
    for form_id, e in results:
        for element_id, element_code, key, value in e:
            if element_id not in elements.keys():
                elements[element_id] = {
                    "form_id": form_id,
                    "element": element_code,
                    key: value,
                }
            else:
                elements[element_id][key] = value
    for k, v in elements.items():
        if v.get("element") in {
                "form",
                "button",
                "datalist",
                "fieldset",
                "input",
                "keygen",
                "label",
                "legend",
                "meter",
                "optgroup",
                "option",
                "output",
                "progress",
                "select",
                "textarea",
        }:
            if v.get("form_id") not in forms.keys():
                forms[v.get("form_id")] = []
            v_simplified: Dict[str, Any] = dict(v)
            v_simplified.pop("form_id")
            forms[v.get("form_id")].append(v_simplified)

    return forms


global __traverse_cfg_travelled_tls
__traverse_cfg_travelled_tls: Set[int] = set()


@lru_cache(maxsize=LRU_CACHE_SIZE)
def traverse_cfg(node_id: int) -> Tuple[int, List[Tuple[int, int, str]], bool]:
    """Traverse a node in a control flow graph until the next branch. A branch here means a function or method call in a CFG.

    Args:
            node_id (int): The node ID to start at.

    Returns:
            Tuple[List[Tuple[int, int, str]], bool]: Pair of a list of relationships in the form (start id, end id, relationship type) and a boolean indicating whether or not the traversed section contains any echo statements.
    """
    # Stop recursion.
    global __traverse_cfg_travelled_tls
    if node_id in __traverse_cfg_travelled_tls:
        return (-1, [], False)
    else:
        __traverse_cfg_travelled_tls.add(node_id)

    graph = getGraph()

    query = f"""
    MATCH (tl:AST{{id:{node_id}}})-[:ENTRY|PARENT_OF*]->(n)
    WHERE (n:AST OR n:Artificial)
    MATCH (tl)-[:ENTRY]->(entry:Artificial)
    MATCH p=(temp1)-[:FLOWS_TO|CALLS|ENTRY]->(n)-[:FLOWS_TO|CALLS|EXIT]->(temp2)
    WHERE (temp1:AST OR temp1:Artificial) AND (temp2:AST OR temp2:Artificial)
    UNWIND RELATIONSHIPS(p) as r
    RETURN entry.id, COLLECT(DISTINCT [startNode(r).id, endNode(r).id, type(r)]), COLLECT(DISTINCT startNode(r).type) , COLLECT(DISTINCT endNode(r).type) 
    """
    results_top = graph.run(query)
    if not results_top:
        return (-1, [], False)

    # Should return one row.
    output: List[Tuple[int, int, str]] = []
    has_echo: bool = False
    types: Set[str] = set()

    relations: List[Tuple[int, int, str]]
    entry_id: int = -1
    for entry_id, relations, types1, types2 in results_top:
        # Check if there are any AST_ECHO nodes in the returned types.
        types.update(types1)
        types.update(types2)
        has_echo = has_echo or "AST_ECHO" in types

        # Check every relation. If it is a calls edge, then branch and check that CFG.
        for relation in relations:
            # Unpack the relation.
            _, end_id, rel_type = relation
            # Append the current relation to the output.
            output.append(relation)
            if rel_type == "CALLS":
                _, branch_relations, branch_has_echo = traverse_cfg(end_id)
                # Update has_echo if the branch echos anything.
                has_echo = has_echo or branch_has_echo
                # Now extend the output
                output.extend(branch_relations)

    return (entry_id, output, has_echo)


def debug_cache_info():
    """Print debug info about the cached functions."""
    cached_functions = [
        getNode,
        getNodeType,
        getVarAssignLocation,
        getNodeName,
        getASTMethodName,
        getASTCallName,
        getCallName,
        ASTAssignGetName,
    ]
    for f in cached_functions:
        print(f.__name__)
        print(f.cache_info())
        print()
