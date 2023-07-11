# GDPR Checker - Utils.py
# Patrick Thomas pwt5ca
# Created 201210

import os
import re
from typing import Dict, List, Optional, Set, Tuple

import py2neo
from Settings import ALL_WORDPRESS_FUNCTIONS

call_name_pattern = re.compile("^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$")


def get_code_from_file(graph: py2neo.Graph, node_id: int, plugin_path: Optional[str] = None) -> str:
    query = f"""
	MATCH p=(n:AST)<-[:PARENT_OF*1..10]-(x:AST)-[:FLOWS_TO]->() 
	WHERE n.id = {node_id}
	RETURN x ORDER BY length(p) ASC LIMIT 1
	"""
    root = graph.evaluate(query)
    if not root:
        raise Exception("Could not get root of line")

    line_no = root["lineno"]
    filename = get_node_filename(graph, root["id"])
    if not filename:
        raise Exception("Could not get filename")
    if plugin_path and filename.startswith("/var/www/html/"):
        filename = os.path.join(plugin_path, filename.replace("/var/www/html/", ""))

    query = f"""
	MATCH (n:AST{{id:{root['id']}}})-[:FLOWS_TO]->(m:AST)
	RETURN m.lineno LIMIT 1
	"""
    next_line_no = graph.evaluate(query)
    if not next_line_no:
        next_line_no = line_no

    try:
        with open(filename, "r") as f:
            lines = f.readlines()
            return "".join(lines[line_no - 1 : next_line_no])
    except Exception as e:
        raise e


def get_node_filename(graph: py2neo.Graph, node_id: int) -> Optional[str]:
    q = f"""
    MATCH (file:Filesystem)-[:FILE_OF]->(toplevel:AST)-[:PARENT_OF*0..]->(n:AST{{id:{node_id}}})
    RETURN toplevel.name
    """
    result: Optional[str] = graph.evaluate(q)
    # if result:
    #     return str(result).replace("/var/www/html/", "", 1)
    # return None
    return result


def get_php_uses_map(graph: py2neo.Graph) -> Dict[str, list]:
    uses = {}  # type: Dict[str, list]

    query = """
    match (n)-[:PARENT_OF]->(m) where n.type =~ "AST_USE_ELEM" and m.type =~ "string" 
    return m.id, m.code
    """
    result = graph.run(query)
    for i, s in result:
        filename = str(get_node_filename(graph, i))
        uses_for_file = uses.get(filename, [])
        uses_for_file.append(s)
        uses[filename] = uses_for_file
    return uses


def get_variable_value(
    graph: py2neo.Graph,
    usage_id: int,
    class_name: Optional[str] = None,
    node_type: str = "None",
) -> Optional[str]:
    query = None
    if node_type == "string":
        query = f"""match (n) where n.id = {usage_id} return n as var limit 1"""
    elif re.match("AST_.*(VAR|CONST|CONST_ELEM)", node_type):
        query = f"""
        match (n)-[:PARENT_OF*]->(var_usage) where n.id = {usage_id} and var_usage.type =~ "string"
            {'and var_usage.classname =~ "' + class_name + '"' if class_name is not None else ""}
        match p = (assign)-[:PARENT_OF]->(var)-[:PARENT_OF*]->(var_name) 
        where assign.type =~ "AST_(ASSIGN|CONST_DECL)" 
            and var.type =~ "AST_.*(VAR|CONST_ELEM)" and var.childnum = 0
            and var_name.code = var_usage.code and var_name.childnum = 0
        with assign as root
        match (assign)-[:PARENT_OF]->(var)
        where assign.id = root.id
            and ((var.type = "AST_ASSIGN" and var.childnum = 1) or (var.type =~ "AST_CONST_ELEM"))
        return var
        """
    else:
        query = f"""
        match (var_usage) where var_usage.id = {usage_id} {'and var_usage.classname =~ "' + class_name + '"' if class_name is not None else ""}
        match (elem)-[:PARENT_OF]->(var_def) where elem.type =~ ".*_ELEM" and var_def.code = var_usage.code
        match (elem)-[:PARENT_OF]->(var_value) where var_value.childnum = 1
        return var_value as var
        """
    results = graph.run(query)

    for result in results:
        if result is not None:
            result = result["var"]
        else:
            continue

        if result["type"] == "string":
            # Variable is defined as a constant here; search is done.
            return result["code"]
        elif re.match("AST_CLASS_CONST", result["type"]):
            # Result is some other expression... have to look up again.
            query = f"""
            match (var_value)-[:PARENT_OF]->(var_name) 
                where var_value.id = {result['id']} and var_name.childnum = 1
            optional match (var_value)-[:PARENT_OF]->(var_class)-[:PARENT_OF]->(var_classname) 
                where var_value.id = {result['id']} and var_class.childnum = 0 and var_class.type =~ "AST_NAME"
            return var_name.id as id, var_classname.code as classname
            """
            var_name = graph.run(query).data()
            if var_name is not None:
                data = var_name[0]
                return get_variable_value(graph, data["id"], class_name=data["classname"])
        elif re.match("AST.*_VAR", result["type"]):
            # Result is some other expression... have to look up again.
            query = f"""
            match (var_value)-[:PARENT_OF]->(var_name) 
                where var_value.id = {result['id']} and var_name.childnum = 0
            return var_name as n
            """
            var_name = graph.run(query).evaluate()
            if var_name is not None:
                return get_variable_value(graph, var_name["id"], node_type=var_name["type"])
        elif re.match("AST.*_(CONST|CONST_ELEM)", result["type"]):
            # Result is some other expression... have to look up again.
            query = f"""
            match (var_value)-[:PARENT_OF]->(var_name) 
                where var_value.id = {result['id']} and var_name.childnum = 1
            return var_name as n
            """
            var_name = graph.run(query).evaluate()
            if var_name is not None:
                return get_variable_value(graph, var_name["id"], node_type=var_name["type"])

    return None


def find_reaches_relationship(
    graph: py2neo.Graph, string_node_id: int
) -> Optional[Tuple[dict, dict]]:
    """Uses REACHES edges from the AST to find the most accurate definition of some used variable.

    Args:
        graph (py2neo.Graph): The graph containing the PHP AST.
        string_node_id (int): The ID of the usage's variable name, should be type string.

    Returns:
        Tuple[dict, dict]: Tuple of the definition and usage, like (definition, usage).
    """

    query = f"""
    match (start) where start.id = {string_node_id}
    with start.code as var_name
    match (n) where n.code =~ var_name
    with collect(n) as n, var_name
    with head(n) as n, last(n) as m, var_name
    match p = (n)<-[:PARENT_OF*]-()-[r:REACHES]-()-[:PARENT_OF*]->(m) 
        where none(x in nodes(p) where x.type =~ "AST_STMT_LIST")
        and r.var =~ var_name
    return [startNode(r), endNode(r)] limit 1
    """
    result = graph.evaluate(query)
    if result is not None:
        definition, usage = result
        return definition, usage
    return None


def variable_dereference(graph: py2neo.Graph, node_id: int) -> dict:
    node = graph.run(f"match (n) where n.id = {node_id} return n limit 1").evaluate()
    if node is None:
        return {}
    else:
        query = f"""
        match (n)-[:PARENT_OF*]->(m) where n.id = {node_id} and m.type =~ "string"
        with m
        match p=(def)-[r:REACHES]->(use)-[:PARENT_OF*]->(m) where r.var = m.code
        return [def, use, r.var] as pair
        """
        pairs = graph.run(query)
        deref = {}  # type: dict
        for pair in pairs:
            data = pair.data()["pair"]
            definition, usage, var_name = data
            if definition["type"] == "AST_CONST_DECL":
                query = f"""
                match (a)-[:PARENT_OF]->(b)-[:PARENT_OF]->(c) where a.id = {definition['id']} and c.childnum = 1
                return c
                """
                definition_value = graph.evaluate(query)
                deref[var_name] = definition_value["code"]
            elif definition["type"] == "AST_ASSIGN":
                query = f"""
                match (a)-[:PARENT_OF]->(b) where a.id = {definition['id']} and b.childnum = 1
                optional match (b)-[:PARENT_OF*]->(c) where c.type =~ "string"
                return [b, collect(c)] limit 1
                """
                definition_value = graph.evaluate(query)
                if definition_value is not None:
                    child, subchildren = definition_value
                    if child["type"] == "string":
                        deref[var_name] = child["code"]
                    else:
                        # Try to dereference
                        more_deref = {}  # type: dict
                        for _ in subchildren:
                            more_deref = {
                                **more_deref,
                                **variable_dereference(graph, definition["id"]),
                            }
                        deref[var_name] = more_deref

        return deref


def search_scopes(graph: py2neo.Graph, stmt_list_ids: List[int]) -> List[int]:
    all_calls: Set[str] = set()
    next_calls: Set[str] = set()
    stmt_lists: List[int] = []
    query = f"""
    UNWIND [{", ".join((f'{i}' for i in stmt_list_ids))}] AS x
    MATCH (start:AST) WHERE start.id = x
    OPTIONAL MATCH (start)-[:PARENT_OF]->(call)-[:PARENT_OF]->(:AST{{type:"AST_NAME", childnum:0}})-[:PARENT_OF]->(name) WHERE call.type =~ "AST_CALL"
    OPTIONAL MATCH (start)-[:PARENT_OF]->(call2)-[:PARENT_OF]->(name2:AST{{childnum:1}}) WHERE call2.type =~ "AST_(STATIC|METHOD)_CALL"
    RETURN COLLECT(DISTINCT start.id), COLLECT(DISTINCT name.code), COLLECT(DISTINCT name2.code)
    """
    results = graph.run(query)
    for found_list_ids, calls, static_and_class_calls in results:
        stmt_lists.extend(found_list_ids)
        next_calls.update([s for s in calls if re.match(call_name_pattern, s)])
        next_calls.update([s for s in static_and_class_calls if re.match(call_name_pattern, s)])
        all_calls.update([s for s in calls if re.match(call_name_pattern, s)])
        all_calls.update([s for s in static_and_class_calls if re.match(call_name_pattern, s)])
    while next_calls:
        next_calls_part = list(next_calls)[: min(25, len(next_calls))]
        next_calls.difference_update(next_calls_part)
        query = f"""
        UNWIND [{", ".join((f'"{re.escape(i)}"' for i in next_calls_part))}] AS x
        MATCH (start:AST)-[:PARENT_OF]->(stmtlist:AST{{type:"AST_STMT_LIST"}}) WHERE start.name = x
        OPTIONAL MATCH (stmtlist)-[:PARENT_OF]->(call:AST)-[:PARENT_OF]->(:AST{{type:"AST_NAME", childnum:0}})-[:PARENT_OF]->(name) WHERE call.type =~ "AST_(STATIC_|)CALL"
        OPTIONAL MATCH (stmtlist)-[:PARENT_OF]->(call2:AST)-[:PARENT_OF]->(name2:AST{{childnum:1}}) WHERE call2.type =~ "AST_METHOD_CALL"
        RETURN COLLECT(DISTINCT stmtlist.id), COLLECT(DISTINCT name.code), COLLECT(DISTINCT name2.code)
        """
        results = graph.run(query)
        for found_list_ids, calls, static_and_class_calls in results:
            stmt_lists.extend(found_list_ids)
            next_calls.update([s for s in calls if re.match(call_name_pattern, s)])
            next_calls.update([s for s in static_and_class_calls if re.match(call_name_pattern, s)])
        next_calls.difference_update(all_calls)
        all_calls.update(next_calls)

    # print(f"{all_calls =}")
    # print(f"{next_calls =}")
    # print(f"{stmt_lists =}")

    return stmt_lists


def map_args(graph: py2neo.Graph, call_node_id: int) -> Dict[int, str]:
    """Map a function call's arguments to it's known interface. The interface is provided through
    the `function_info` argument, which is in the same format as
    neo4j/src/Detectors/wordpress_functions.json.

    Example function info JSON file:
    ```json
    {
        {
            "_ajax_wp_die_handler": {
                "url": "https://developer.wordpress.org/reference/functions/_ajax_wp_die_handler/",
                "$message": {
                    "type": ["string"],
                    "required": true,
                    "description": "Error message.",
                    "default": "''"
                },
                "$title": {
                    "type": ["string"],
                    "required": false,
                    "description": "Error title (unused).",
                    "default": "''"
                },
                "$args": {
                    "type": ["string", "array"],
                    "required": false,
                    "description": "Arguments to control behavior.",
                    "default": "array()"
                }
            }
        }
    }
    ```

    Args:
        graph (py2neo.Graph): Graph to search
        call_node_id (int): Calling node ID.
        function_info (Dict[str, Any]): Function info dictionary, in a format similar to wordpress_functions.json.

    Returns:
        Dict[int, str]: Mapping of arg child number to likely argument info.
    """

    query = f"""
    MATCH (call:AST{{id: {call_node_id}}})-[:PARENT_OF]->(:AST{{type:"AST_NAME", childnum:0}})-[:PARENT_OF]->(name:AST{{type:"string", childnum:0}})
    MATCH (call:AST{{id: {call_node_id}}})-[:PARENT_OF]->(arglist:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(arg:AST)
    RETURN [name.code, COLLECT(arg)]
    """
    results = graph.evaluate(query)
    if not results:
        return dict()

    name, args = results
    output: Dict[int, str] = dict()

    # Lookup the function's info.
    info = ALL_WORDPRESS_FUNCTIONS.get(name, None)
    if not info:
        return dict()

    param_keys = [k for k in info.keys() if k[0] == "$"]
    for index, k in enumerate(param_keys):
        if info[k]["required"]:
            output[index] = k

    for arg in args:
        index = arg["childnum"]
        if index in output.keys():
            # Required and statically known; skip this.
            pass
        else:
            # Likely a positional argument.
            try:
                output[index] = param_keys[index]
            except IndexError:
                pass

    return output


def map_args_with_name(graph: py2neo.Graph, call_node_id: int, call_name: str) -> Dict[int, str]:
    query = f"""
    MATCH (call:AST{{id: {call_node_id}}})-[:PARENT_OF]->(arglist:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(arg:AST)
    RETURN COLLECT(arg)
    """
    args = graph.evaluate(query)
    if not args:
        return dict()

    output: Dict[int, str] = dict()

    # Lookup the function's info.
    info = ALL_WORDPRESS_FUNCTIONS.get(call_name, None)
    if not info:
        return dict()

    param_keys = [k for k in info.keys() if k[0] == "$"]
    for index, k in enumerate(param_keys):
        if info[k]["required"]:
            output[index] = k

    for arg in args:
        index = arg["childnum"]
        if index in output.keys():
            # Required and statically known; skip this.
            pass
        else:
            # Likely a positional argument.
            try:
                output[index] = param_keys[index]
            except IndexError:
                pass

    return output
