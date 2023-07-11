
import sqlparse
from NeoGraph import getGraph
from ValueResolver import evaluateExpressionSQL
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from NodeEdgeManager import *
import os
from Settings import SRC_DIR,ROOT_DIR

from Naked.toolshed.shell import muterun_js
import json


SQLParentNodes: Set[int] = set()
SQLParentNodeOperations: Dict[int, Set[str]] = dict()
def getSQLParentNodes():
    global SQLParentNodes
    if SQLParentNodes:
        return SQLParentNodes
    else:
        graph = getGraph()
        query = f"""
        MATCH (cl:AST_SQL)
        RETURN COLLECT(cl.id)
        """
        results = graph.evaluate(query)
        if results:
            for call_id in results:
                SQLParentNodes.add(call_id)
        return SQLParentNodes
def SQLToAST(nodeID: int) -> bool:
    """SQL parser. This method parses the query and attaches the AST nodes to the AST_CALL node for the query.

    Args:
            nodeID (int): Starting node ID of the SQL.
            dereffed (bool, optional): If this is a variable, has it already been dereferenced? Defaults to False.

    Raises:
            Exception: Either the Neo4j graph is unexpected or the SQL could not be processed.
    Returns:
            returns the number of nodes created
    """
    nodeCount=0
    graph = getGraph()

    query = f"""
	MATCH (call:AST{{id:{nodeID}}})-[:PARENT_OF]->(arg_list:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(arg:AST)
	RETURN COLLECT(arg)
	"""
    results = graph.evaluate(query)
    if not results or len(results) < 1:
        # Something is wrong, or this is a false-positive for SQL statements.
        return False

    query_funcid = results[0]["funcid"]
    query_lineno = results[0]["lineno"]

    sql, _ = evaluateExpressionSQL(results[0]["id"])
    # print("*"*10)
    # print(sql)

    if sql:
        sql = re.sub(r"\s+", " ", sql)
        # '$' will cause error. Remove them.
        #sql = sql.replace("$","")
    else:
        # raise Exception("Could not determine SQL from PHP AST.")
        return False

    sql_statements = sqlparse.split(sql)
    parsed = [sqlparse.parse(s)[0].tokens for s in sql_statements]
    # print("="*10)
    # print(parsed)
    # inject nodes back to Neo4j
    # max_id = graph.evaluate("MATCH (n) RETURN max(n.id)")
    # if not max_id:
    #     max_id = 0
    # next_id = max_id + 1

    stmt_list: List[sqlparse.sql.Token]
    for stmt_list in parsed:
        # Make SQL a subgraph of the call.
        id = addNode(
            label='AST_SQL',
            type='AST_SQL_START',
            lineno=str(query_lineno),
            code=sql,
            childnum=0,
            funcid=str(query_funcid),
            )
        nodeCount+=1
        addEdge(nodeID,'AST',id,'AST_SQL','PARENT_OF')
        # Iteratively recurse through SQL parse tree.
        prev_id = 0
        token_queue: List[Optional[sqlparse.sql.Token]] = list(stmt_list)
        scope_stack: List[int] = [id]
        scope_child_num: List[int] = [0]
        
        while token_queue:
            token: Optional[sqlparse.sql.Token] = token_queue.pop(0)
            if token is None:
                scope_stack.pop()
                scope_child_num.pop()
            elif token.is_whitespace or token.normalized in {",", ";"}:
                continue
            else:
                if not token.is_group and token.is_keyword:
                    # query = f"""
					# MATCH (parent:AST_SQL{{id:{scope_stack[-1]}}})
					# MERGE (parent)-[:PARENT_OF]->(:AST_SQL{{
					# 	type:'AST_SQL_{token.normalized}',
					# 	funcid:{query_funcid},
					# 	lineno:{query_lineno},
					# 	childnum:{scope_child_num[-1]},
					# 	id: {next_id}
					# }})
					# """
                    # graph.run(query)
                    id = addNode(
                        label='AST_SQL',
                        type=f'AST_SQL_{token.normalized}',
                        lineno=str(query_lineno),
                        code=sql,
                        childnum=scope_child_num[-1],
                        funcid=str(query_funcid),
                        )
                    nodeCount+=1
                    addEdge(scope_stack[-1],'AST_SQL',id,'AST_SQL','PARENT_OF')
                    if prev_id:
                        #query = f""" MATCH (from:AST_SQL{{id:{prev_id}}}) MATCH (to:AST_SQL{{id:{next_id}}}) MERGE (from)-[:SQL_FLOWS_TO]->(to) """
                        #graph.run(query)
                        addEdge(prev_id,'AST_SQL',id,'AST_SQL','SQL_FLOWS_TO')
                    prev_id = id

                    scope_child_num[-1] += 1
                elif not token.is_group and not token.is_keyword:
                    # query = f"""
					# MATCH (parent:AST_SQL{{id:{scope_stack[-1]}}})
					# MERGE (parent)-[:PARENT_OF]->(:AST_SQL{{
					# 	type:'AST_SQL_{token._get_repr_name()}',
					# 	code:"{token.normalized}",
					# 	funcid:{query_funcid},
					# 	lineno:{query_lineno},
					# 	childnum:{scope_child_num[-1]},
					# 	id: {next_id}
					# }})
					# """
                    # graph.run(query)
                    id = addNode(
                        label='AST_SQL',
                        type=f'AST_SQL_{token._get_repr_name()}',
                        lineno=str(query_lineno),
                        code=token.normalized,
                        childnum=scope_child_num[-1],
                        funcid=str(query_funcid),
                        )
                    nodeCount+=1
                    addEdge(scope_stack[-1],'AST_SQL',id,'AST_SQL','PARENT_OF')
                    if prev_id:
                        # query = f""" MATCH (from:AST_SQL{{id:{prev_id}}}) MATCH (to:AST_SQL{{id:{next_id}}}) MERGE (from)-[:SQL_FLOWS_TO]->(to) """
                        # graph.run(query)
                        addEdge(prev_id,'AST_SQL',id,'AST_SQL','SQL_FLOWS_TO')
                    prev_id = id

                    scope_child_num[-1] += 1
                elif token.is_group:
                    # query = f"""
					# MATCH (parent:AST_SQL{{id:{scope_stack[-1]}}})
					# MERGE (parent)-[:PARENT_OF]->(n:AST_SQL{{
					# 	type:'AST_SQL_{token._get_repr_name()}',
					# 	funcid:{query_funcid},
					# 	lineno:{query_lineno},
					# 	childnum:{scope_child_num[-1]},
					# 	id: {next_id}
					# }})
					# RETURN n
					# """
                    # node = graph.evaluate(query)
                    id = addNode(
                        label='AST_SQL',
                        type=f'AST_SQL_{token._get_repr_name()}',
                        lineno=str(query_lineno),
                        code=token.normalized,
                        childnum=scope_child_num[-1],
                        funcid=str(query_funcid),
                        )
                    nodeCount+=1
                    addEdge(scope_stack[-1],'AST_SQL',id,'AST_SQL','PARENT_OF')
                    token_queue = [*token.tokens, None, *token_queue]

                    scope_child_num[-1] += 1

                    scope_stack.append(id)
                    scope_child_num.append(0)
                    # if node:
                    #     token_queue = [*token.tokens, None, *token_queue]

                    #     scope_child_num[-1] += 1
                    #     next_id += 1

                    #     scope_stack.append(id)
                    #     scope_child_num.append(0)
    
    # Require that the SQL object is correctly found and has a operation associated with it, otherwise it is not useful.
    # sql_info = getStatementSQLInfo(nodeID)
    # if sql_info and sql_info.operations:
    #     SQLParentNodes.add(nodeID)
    #     [nodeID] = sql_info.operations

    return nodeCount

def SQLToAST1(nodeID: int) -> bool:
    graph = getGraph()
    query = f"""
	MATCH (call:AST{{id:{nodeID}}})-[:PARENT_OF]->(arg_list:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(arg:AST{{childnum:0}})
	RETURN arg
	"""
    results = graph.evaluate(query)
    if not results or len(results) < 1:
        # Something is wrong, or this is a false-positive for SQL statements.
        return False

    query_funcid = results["funcid"]
    query_lineno = results["lineno"]
    sql, _ = evaluateExpressionSQL(results["id"])
    print(sql)

    if sql:
        sql = re.sub(r"\s+", " ", sql)
        # '$' will cause error. Remove them.
        # sql = sql.replace("$","")
    else:
        # raise Exception("Could not determine SQL from PHP AST.")
        return False
    query = f"""
	MATCH (call:AST{{id:{nodeID}}})-[:PARENT_OF]->(children:AST)
	RETURN MAX(children.childnum)
	"""
    results = graph.evaluate(query)
    query_childnum = 99
    if results:
        query_childnum = int(results)+1
    return parseSQL(sql,query_childnum,query_lineno,nodeID)
    
def parseSQL(sqlStatement: str, query_childnum: int, query_lineno: int,parent_nodeID: int) -> None:
    nodeCount=0
    edgeCount = 0
    response = None
    sqlstring = sqlStatement.replace("'","\\'")
    sqlstring = f"$'{sqlstring}'"
    response = muterun_js(os.path.join(SRC_DIR,"sqlparser.js"), arguments=f"""{sqlstring}""")
    response = response.stdout.decode("utf-8")
    if response:
        nodeList = json.loads(response)
        tableInfo = nodeList['tables']
        tableInfo = [i.split("::") for i in tableInfo]
        # print(tableInfo)
        columnInfo = nodeList['columns']
        columnInfo = [i.split("::") for i in columnInfo]
        # print(columnInfo)
        current_childnum = query_childnum
        for t in tableInfo:
            operation = t[0]
            table = t[2]
            columns = []
            for c in columnInfo:
                operation_temp = c[0]
                table_temp = c[1]
                column = c[2]
                column.replace("(.*)","*")
                #if the table name for the column cannot be matched, assume it's the table name matched outside in the table info.
                if operation_temp==operation and (table_temp==table or table_temp=='null'):
                    columns.append(column)
            # print("SQL parsed result:")
            # print("==operation:"+operation)
            # print("==table:"+table)
            # print("==columns:"+str(columns))
            newID = addSQLNode("AST_SQL",operation,table,columns,query_lineno,sqlStatement,current_childnum)
            nodeCount+=1
            current_childnum+=1
            edgeCount+=addEdge(parent_nodeID,"AST",newID,"AST_SQL","PARENT_OF")
            # print("another checkpoint1")
    else:
        print(f"SQL command ({sqlStatement}) cannot be parsed correct.")
    # print(f"Added {nodeCount} AST_SQL nodes and {edgeCount} PARENT_OF edges.")
    return nodeCount

#tests
# parseSQL('SELECT t.mail FROM t;DELETE FROM t')
# parseSQL('DROP TABLE wpdbprefixforum_forums;')
# parseSQL("""CREATE TABLE thistablesforums  (
#             id int(11) NOT NULL auto_increment,
#             parent_id int(11) NOT NULL default '0',
#             author_id int(11) NOT NULL default '0',
#             views int(11) NOT NULL default '0',
#             name varchar(255) NOT NULL default '',
#             sticky int(1) NOT NULL default '0',
#             closed int(1) NOT NULL default '0',
#             approved int(1) NOT NULL default '1',
#             slug varchar(255) NOT NULL default '',
#             PRIMARY KEY  (id),
#             KEY parent_id (parent_id),
#             KEY approved (approved),
#             KEY sticky (sticky)
#             )""")