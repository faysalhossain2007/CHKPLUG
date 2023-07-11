from dataclasses import replace
from typing import Any, Dict, List, Optional, Set, Tuple
from Settings import LRU_CACHE_SIZE, MAX_NODE_CODE_LENGTH, ROOT_DIR
from functools import lru_cache
from NeoHelper import cacheAllNodeChildren,getNode,concatTree,getNodeChildren,isUrlValid
from DataFlowTracking import reverseTrackDataFlowToAssignNoRecord,getMaxTraversalLength

from json import dumps, loads

from DataFlowTracking import getSources

from NeoGraph import getGraph

import signal
global _evaluateExpressionScopes
_evaluateExpressionScopes: Set[int] = set()

class TimeoutExceptionValueResolver(Exception):   # Custom exception class
    print("Timeout in resolving values")

def timeout_handler_value_resolver(signum, frame):   # Custom signal handler
    raise TimeoutExceptionValueResolver

# Change the behavior of SIGALRM
signal.signal(signal.SIGALRM, timeout_handler_value_resolver)

@lru_cache(maxsize=LRU_CACHE_SIZE)
def evaluateURLExpression(expression_id:int) -> List[str]:
    """Attempt to statically evaluate an expression for URL
    The output of this function is cached for speed at the expense of memory.
    Usage example: use this on the a variable that passes a URL
    Args:
            expression_id (int): The root of the expression tree to evaluate.
    Returns:
            List[str]: a list of possible strings for url.
    """
    n = getNode(expression_id)
    if not n:
        return []
    urls = []
    if n.get("type", "") == "string":
        potentialURLString = n.get("code", "")
        if isUrlValid(potentialURLString):
            urls.append(potentialURLString)
    elif n.get("type", "") in ["AST_VAR","AST_CONST"]:
        var = getSources(expression_id,no_constraint = True)
        for i in var:
            if i['type']=='string' and 'code' in i and isUrlValid(i['code']):
                urls.append(i['code'])
    return urls

@lru_cache(maxsize=LRU_CACHE_SIZE)
def evaluateExpressionSQL(
    expression_id: int, node_label: str = "AST"
) -> Tuple[Optional[str], Set[int]]:
    """Attempt to statically evaluate a SQL expression.
    This function is identical to evaluationExpression() apart from a special handling for tracking wpdb->prepare() statement
    """
    graph = getGraph()
    query = f"""
    MATCH (n:{node_label}{{id:{expression_id}}})<-[:PHP_REACHES{getMaxTraversalLength()}]-(m:AST{{type:'AST_METHOD_CALL'}})
    WHERE (:AST{{childnum:1,type:'string',code:'prepare'}})<-[:PARENT_OF]-(m)-[:PARENT_OF]->(:AST{{childnum:0,type:'AST_VAR'}})-[:PARENT_OF]->(:AST{{type:'string',code:'wpdb'}})
    RETURN m.id
    """
    result = graph.evaluate(cypher=query)
    # print(result)
    if result:
        return (evaluateExpression(result)[0], set())
    else:
        return evaluateExpression(expression_id)

@lru_cache(maxsize=LRU_CACHE_SIZE)
def evaluateExpression(
    expression_id: int, node_label: str = "AST"
) -> Tuple[Optional[str], Set[int]]:
    """Attempt to statically evaluate an expression.
    The output of this function is cached for speed at the expense of memory.
    Usage example: use this on the right-hand side of an AST_ASSIGN statement to try and statically
    resolve the resulting value of the variable.
    Args:
            expression_id (int): The root of the expression tree to evaluate.
    Returns:
            Union[int, str]: An integer, string, or None depending on the value of the expression.
            Set[int]: List of sources for the expression that aren't constants (ints, strings, etc.)
    """
    global _evaluateExpressionScopes
    _evaluateExpressionScopes = set()
    cacheAllNodeChildren(expression_id)

    signal.alarm(60)   
    try:
        values, sources = evaluateExpressionUnjoined(expression_id, node_label)
    except:
        return (None, set())
    else:
        signal.alarm(0)
        if values:
            return ("".join(values), sources)
        else:
            return (None, set())


@lru_cache(maxsize=LRU_CACHE_SIZE)
def evaluateExpressionUnjoined(
    expression_id: int, node_label: str = "AST"
) -> Tuple[List[str], Set[int]]:
    """Attempt to statically evaluate an expression.
    The output of this function is cached for speed at the expense of memory.
    Usage example: use this on the right-hand side of an AST_ASSIGN statement to try and statically
    resolve the resulting value of the variable.
    Args:
            expression_id (int): The root of the expression tree to evaluate.
    Returns:
            Union[int, str]: An integer, string, or None depending on the value of the expression.
            Set[int]: List of sources for the expression that aren't constants (ints, strings, etc.)
    """

    # Stop infinite recursion at the cost of accuracy.
    global _evaluateExpressionScopes
    if expression_id in _evaluateExpressionScopes:
        # print("evaluateExpression error: stopping infinite recursion.")
        return [], set()
    else:
        _evaluateExpressionScopes.add(expression_id)

    cacheAllNodeChildren(expression_id, node_label=node_label)

    n = getNode(expression_id)
    if not n:
        return [], set()

    if n.get("type", "") == "string":
        return [n.get("code", "")], set()

    elif n.get("type", "") == "integer":
        return [str(n.get("code", 0))], set()

    elif n.get("type", "") in ["AST_VAR","AST_CONST"]:
        var = reverseTrackDataFlowToAssignNoRecord(expression_id)

        # # Get the variable's name.
        # children = getNodeChildren(expression_id)

        # # Variable needs to be valid (have a AST_NAME or string child).
        # if not children:
        #     return [], set()
        # name = children[0].get("code")
        # if not name:
        #     return [], set()

        # # Have to find a REACHES edge.
        # root = getRootOfLine(expression_id)
        # if not root:
        #     return [name], {n["id"]}

        # # Get the variable's assignment location.
        # var = getVarAssignLocation(root["id"], name)
        if not var:
            return [concatTree(expression_id)], {n["id"]}
        var = var['id']
        # Evaluate the RHS of the assignment.
        value, sources = evaluateExpressionUnjoined(var)
        # If could not be resolved, return the variable's name rather than nothing.
        if not value and not sources:
            return [concatTree(expression_id)], {n["id"]}
        return value, {n["id"]}

    # elif n.get("type", "") == "AST_CONST":
    #     # Get the variable's name.
    #     children = getNodeChildren(expression_id)

    #     # Constant needs to be valid (have a AST_NAME or string child).
    #     if not children:
    #         return [], set()
    #     name_children = getNodeChildren(children[0]["id"])
    #     name = name_children[0].get("code", None) if name_children else None
    #     if not name:
    #         return [], set()

    #     # Have to find a REACHES edge.
    #     root = getRootOfLine(expression_id)
    #     if not root:
    #         return [name], {n["id"]}
    #     # Get the assignment location.
    #     var = getVarAssignLocation(root["id"], name)
    #     if not var:
    #         return [name], {n["id"]}

    #     # Evaluate the RHS of the assignment.
    #     value, sources = evaluateExpressionUnjoined(var)
    #     # If could not be resolved, return the variable's name rather than nothing.
    #     if not value and not sources:
    #         return [name], {n["id"]}
    #     return value, {n["id"]}

    elif n.get("type", "") == "AST_ASSIGN":
        # Get the variable's name.
        children = getNodeChildren(expression_id)
        if not children or len(children) < 2:
            return [], set()
        rhs = children[1]
        value, sources = evaluateExpressionUnjoined(rhs["id"])
        return value, sources

    elif n.get("type", "") == "AST_CONDITIONAL":
        # Tertiary statement; could be either output, so return both.
        children = getNodeChildren(expression_id)
        if not children or len(children) != 3:
            return [], set()
        output_values = list()
        output_sources = set()
        for c in children[1:]:
            v, s = evaluateExpressionUnjoined(c["id"])
            output_sources.update(s)
            output_values.extend(v)
        return output_values, output_sources
    elif n.get("type", "") == "AST_BINARY_OP":
        # Determine type of binary operation.
        flags = n.get("flags", [])

        if "BINARY_CONCAT" in flags:
            # Binary concatenation?
            children = getNodeChildren(expression_id)
            if not children:
                return [], set()
        else:
            # print(f"Unhandled type for evaluteExpression.BINARY_CONCAT: {n=}")
            return [], set()

        output_values = list()
        output_sources = set()
        for c in children:
            v, s = evaluateExpressionUnjoined(c["id"])
            output_sources.update(s)
            output_values.extend(v)
        #print("value")
        #print(output_values)
        return output_values, output_sources

    elif n.get("type", "") == "AST_UNARY_OP":
        # Determine type of binary operation.
        flags = n.get("flags", [])

        if "UNARY_SILENCE" in flags:
            # Silence...
            return [], set()
        else:
            # print(f"Unhandled type for evaluteExpression.BINARY_CONCAT: {n=}")
            return [], set()

        return [], set()

    elif n.get("type", "") == "AST_ENCAPS_LIST":
        children = getNodeChildren(expression_id)
        if not children:
            return [], set()

        output_values = list()
        output_sources = set()
        for c in children:
            v, s = evaluateExpressionUnjoined(c["id"])
            output_sources.update(s)
            output_values.extend(v)
        return output_values, output_sources

    elif n.get("type", "") == "AST_CALL":
        children = getNodeChildren(expression_id)
        if not children:
            return [], set()

        name_children = getNodeChildren(int(children[0]["id"]))
        if not name_children:
            return [], set()

        name_str = name_children[0].get("code", "")

        if (name_str == "__" and len(children) >= 2) or name_str in ['esc_html','esc_html_e','esc_attr','esc_url','esc_textarea','esc_attr_e','esc_html__','esc_url_raw','wp_kses_post','sprintf','wpautop']:
            # Now grab the arg ID.
            args = getNodeChildren(children[1].get("id", -1))
            if not args:
                return [], set()
            return evaluateExpressionUnjoined(args[0]["id"])
        else:
            return [concatTree(expression_id)], set()
    elif n.get("type", "") == "AST_METHOD_CALL":
        graph = getGraph()
        query = f"""
        MATCH (prep:AST{{childnum:1,type:'string',code:'prepare'}})<-[:PARENT_OF]-(n:AST{{id:{expression_id}}})-[:PARENT_OF]->(var:AST{{childnum:0,type:'AST_VAR'}})-[:PARENT_OF]->(str:AST{{type:'string',code:'wpdb'}})
        MATCH (n)-[:PARENT_OF]->(arg_list:AST{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(args:AST)
        WITH args
        ORDER BY args.childnum ASC
        RETURN COLLECT(args.id)
        """
        # MATCH (n)-[:PARENT_OF]->(arg_list:AST{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(args:AST)
        # RETURN COLLECT(args) ORDER BY args.childnum
        result = graph.evaluate(cypher=query)
        # print(result)
        if result:
            values = [evaluateExpression(i)[0] for i in result]
            # print(values)
            sql = values[0]
            del values[0]
            for i in range(len(values)):
                if values[i] is None:
                    values[i] = f'"placeholder_{i}"'
            indices = []
            for c in range(len(sql)):
                if sql[c]=='%':
                    indices.append(c)
            diff = 0
            for i in indices:
                temp = i+diff
                replace_target = sql[temp:temp+2]
                # print(replace_target)
                sql = sql.replace(replace_target,values[0],1)
                diff = len(values[0])-len(replace_target)
                print(sql)
                del values[0]
                # print(sql[sql.index("%"):sql.index("%")+2])
            # print("SQL:")
            # print(sql)
            return [sql],set()
            
        else:
            return [concatTree(expression_id)], set()
        pass
    elif n.get("type", "") == "AST_DIM":
        # Simply return the strings concatenated together.
        children = getNodeChildren(expression_id)
        if not children or len(children) < 2:
            return [], set()

        output_value = ""
        output_sources = set()
        container_values, container_sources = evaluateExpressionUnjoined(children[0]["id"])
        key_values, key_sources = evaluateExpressionUnjoined(children[1]["id"])
        output_sources.update(container_sources)
        output_sources.update(key_sources)
        output_value = f"""{"".join(container_values)}_{"".join(key_values)}"""
        return [output_value], output_sources

    elif n.get("type", "") == "AST_PROP":
        #use data flow to determine if there is a single value that flows to this AST_PROP

        sources = getSources(expression_id)

        if sources and len(sources)==1 and not sources[0]['id']==expression_id:
            value,source = evaluateExpressionUnjoined(sources[0]['id'])

            return value,source
        # Simply return the strings concatenated together.
        children = getNodeChildren(expression_id)
        if not children or len(children) < 2:
            return [], set()

        output_value = ""
        output_sources = set()
        container_values, container_sources = evaluateExpressionUnjoined(children[0]["id"])
        key_values, key_sources = evaluateExpressionUnjoined(children[1]["id"])
        output_sources.update(container_sources)
        output_sources.update(key_sources)
        output_value = f"""{"".join(container_values)}_{"".join(key_values)}"""
        return [output_value], output_sources

    elif n.get("type", "") == "AST_ARRAY":
        # Simply return the strings concatenated together.
        children = getNodeChildren(expression_id)
        if not children:
            return [], set()

        output_values_dict = dict()
        output_sources = set()
        for child in children:
            container_values, container_sources = evaluateExpressionUnjoined(child["id"])
            try:
                vals = loads(container_values[0])
                if len(vals) == 2:
                    v, k = vals
                    output_values_dict[k] = v
                else:
                    output_values_dict[len(output_values_dict) + 1] = vals
            except:
                output_values_dict[len(output_values_dict) + 1] = container_values
            output_sources.update(container_sources)

        return [dumps(output_values_dict)], output_sources

    elif n.get("type", "") == "AST_ARRAY_ELEM":
        # Simply return the strings concatenated together.
        children = getNodeChildren(expression_id)
        if not children:
            return [], set()

        output_values = []
        output_sources = set()
        for child in children:
            container_values, container_sources = evaluateExpressionUnjoined(child["id"])
            if container_values:
                output_values.append(container_values[0])
            output_sources.update(container_sources)

        return [dumps(output_values)], output_sources

    # print(f"Unhandled type for evaluteExpression: {n=}")
    return [], set()