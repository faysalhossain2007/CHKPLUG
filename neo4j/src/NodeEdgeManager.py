import pandas as pd
import numpy as np
from Settings import ROOT_DIR, MAX_NODE_CODE_LENGTH
import csv
import os
from NeoGraph import getGraph
from Args import PLUGIN_NAME
from typing import Dict, List, Optional
from py2neo.bulk import create_relationships
import threading
from itertools import groupby

# Globals.
global NODE_DF, EDGE_DF, __step, NODE_FILE_NAME, EDGE_FILE_NAME, ID_COUNTER, EDGE_PAIR, ID_COUNTER_LOCK

# Constants.
RESULTS_PATH = os.path.join(ROOT_DIR, "results", "navex", PLUGIN_NAME + "_preprocess")
NODE_FILE_NAME = 'node.csv'
EDGE_FILE_NAME = 'edge.csv'
HTML_NODE_FILE_NAME = 'html_node.csv'
SQL_NODE_FILE_NAME = 'sql_node.csv'

#NODE_DF = pd.DataFrame({"id":[],"label":[],"type":[],"flags":[],"lineno":[], "code":[],"childnum":[],"funcid":[],"classname":[],"namespace":[],"endlineno":[],"name":[],"doccomment":[]})
#EDGE_DF = pd.DataFrame({"start_id":[],"start_label":[],"end_id":[],"end_label":[],"type":[],"var":[]})
#HTML_NODE_DF = pd.DataFrame({"id":[],"label":[],"type":[],"startIndex":[],"endIndex":[], "code":[],"childnum":[],"name":[]})
#SQL_NODE_DF = pd.DataFrame({"id":[],"label":[],"type":[],"table":[],"columns":[],"lineno":[], "code":[],"childnum":[]})

ID_COUNTER = 0
ID_COUNTER_LOCK = threading.Lock()

NODE_DF = []
NODE_DF_LOCK = threading.Lock()

EDGE_DF = []
EDGE_DF_LOCK = threading.Lock()

HTML_NODE_DF = []
HTML_NODE_DF_LOCK = threading.Lock()

SQL_NODE_DF = []
SQL_NODE_DF_LOCK = threading.Lock()

EDGE_PAIR = set()

__step = 0


def setUp():
    global __step
    createDirectory(__step)


def createDirectory(step):
    directory = RESULTS_PATH
    if not os.path.exists(directory):
        os.makedirs(directory)
    stepDir = getStepDirectory(step)
    if not os.path.exists(stepDir):
        os.makedirs(stepDir)


def isFieldNull(field):
    if not field:
        return True
    if pd.isnull(field):
        return True
    elif field in ['""', "''", '']:
        return True
    return False


def getMaxID():
    #This function manages the IDs assigned to newly created nodes
    #Returns a node ID for a new node.
    global ID_COUNTER, ID_COUNTER_LOCK
    ID_COUNTER_LOCK.acquire()

    if not ID_COUNTER:
        try:
            graph = getGraph()
            result = graph.evaluate("""MATCH (n) RETURN MAX(n.id)""")
            max_id: int = result if result else 0
            ID_COUNTER = max_id + 1
        finally:
            ID_COUNTER_LOCK.release()
            return ID_COUNTER
    else:
        try:
            ID_COUNTER += 1
        finally:
            ID_COUNTER_LOCK.release()
            return ID_COUNTER


def isPreprocessed():
    #check if the current step is preprocessed (files already in the results folder)
    global __step, NODE_FILE_NAME, EDGE_FILE_NAME
    directory = getStepDirectory(__step)
    nodeDir = os.path.join(directory, NODE_FILE_NAME)
    edgeDir = os.path.join(directory, EDGE_FILE_NAME)
    return os.path.exists(directory) and os.path.isfile(nodeDir) and os.path.isfile(edgeDir)


def addNode(label,
            type,
            flags=None,
            lineno=-1,
            code=None,
            childnum=-1,
            funcid=None,
            classname=None,
            namespace=None,
            endlineno=None,
            name=None,
            doccomment=None):
    """Returns the assigned new node ID of the node. This can be subsequently used for addEdge().
    """
    global NODE_DF, NODE_DF_LOCK
    id = getMaxID()
    NODE_DF_LOCK.acquire()

    try:
        NODE_DF.append(
            {
                "id": id,
                "label": label,
                "type": type,
                "flags": flags,
                "lineno": lineno,
                "code": code,
                "childnum": childnum,
                "funcid": funcid,
                "classname": classname,
                "namespace": namespace,
                "endlineno": endlineno,
                "name": name,
                "doccomment": doccomment
            }, )
    except Exception as e:
        print('Error adding node', e)
    finally:
        NODE_DF_LOCK.release()
        return id


def addSQLNode(label, type, table, columns, lineno, code, childnum):
    global SQL_NODE_DF, SQL_NODE_DF_LOCK
    id = getMaxID()
    SQL_NODE_DF_LOCK.acquire()
    try:
        SQL_NODE_DF.append({
            "id": id,
            "label": label,
            "type": type,
            "table": table,
            "columns": columns,
            "lineno": lineno,
            "code": code,
            "childnum": childnum
        })
    except Exception as e:
        print('Error adding node', e)
    finally:
        SQL_NODE_DF_LOCK.release()
        return id


def addHTMLNode(label, type, startIndex, endIndex, code, childnum, name):
    global HTML_NODE_DF, HTML_NODE_DF_LOCK
    id = getMaxID()
    HTML_NODE_DF_LOCK.acquire()
    try:
        HTML_NODE_DF.append({
            "id": id,
            "label": label,
            "type": type,
            "startIndex": startIndex,
            "endIndex": endIndex,
            "code": code,
            "childnum": childnum,
            "name": name
        })
    except Exception as e:
        print('Error adding node', e)
    finally:
        HTML_NODE_DF_LOCK.release()
        return id


# Take in a collection of edges.
def addEdgeBulk(edges):
    assert isinstance(edges, list)

    global EDGE_DF, EDGE_DF_LOCK
    EDGE_DF_LOCK.acquire()
    try:
        EDGE_DF.extend(edges)
        print(f"Number of rows: {len(EDGE_DF)}")
    except:
        print("Warning! Edges not successfully added to the NodeEdgeManager!")
        return 0

    finally:
        EDGE_DF_LOCK.release()


def addEdge(startID, startLabel, endID, endLabel, type, var=None):
    #adds the edge to the edge database if it hasn't before, and returns the number of edge added.

    global EDGE_DF, EDGE_PAIR, EDGE_DF_LOCK
    EDGE_DF_LOCK.acquire()
    edge_added = 0

    try:
        #if this edge has been added before, return 0
        if (startID, endID, type) in EDGE_PAIR:
            edge_added = 0
        #do not consider edges to the node itself
        elif startID == endID:
            edge_added = 0
        else:
            EDGE_DF.append({
                "start_id": startID,
                "start_label": startLabel,
                "end_id": endID,
                "end_label": endLabel,
                "type": type,
                "var": var
            })
            EDGE_PAIR.add((startID, endID, type))
            edge_added = 1
    except Exception as e:
        print('Error adding node', e)
    finally:
        EDGE_DF_LOCK.release()
        return edge_added


def _to_csv(outfile, data):
    if not data:
        return

    with open(outfile, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)


def writeToCSV():
    global NODE_FILE_NAME, EDGE_FILE_NAME, __step, NODE_DF, EDGE_DF, HTML_NODE_DF, SQL_NODE_DF

    directory = getStepDirectory(__step)

    nodeDir = os.path.join(directory, NODE_FILE_NAME)
    edgeDir = os.path.join(directory, EDGE_FILE_NAME)
    htmlNodeDir = os.path.join(directory, HTML_NODE_FILE_NAME)
    sqlNodeDir = os.path.join(directory, SQL_NODE_FILE_NAME)

    _to_csv(nodeDir, NODE_DF)
    _to_csv(edgeDir, EDGE_DF)
    _to_csv(htmlNodeDir, HTML_NODE_DF)
    _to_csv(sqlNodeDir, SQL_NODE_DF)


def getStepDirectory(step):
    stepname = f"step{step}"
    directory = os.path.join(RESULTS_PATH, stepname)
    return directory


def neo4j_escape(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def commit(read=False):
    if read:
        importToNeo4j(True)
    else:
        # writeToCSV()
        importToNeo4j(False)


def incrementStep():
    #This function is for steps where there's no need to import nodes or edges

    global __step
    print(f"Preprocessing step {__step} done!")
    __step += 1


def importToNeo4j(read=False):
    global __step, NODE_DF, EDGE_DF, HTML_NODE_DF, SQL_NODE_DF
    graph = getGraph()

    #determine if the node and edge info should be read from file (previously generated) or from python DF
    if read:
        # TODO
        print('READING FROM FILE IS NOT IMPLEMENTED')
        assert False

        global NODE_FILE_NAME, EDGE_FILE_NAME
        directory = getStepDirectory(__step)

        nodeDir = os.path.join(directory, NODE_FILE_NAME)
        edgeDir = os.path.join(directory, EDGE_FILE_NAME)
        html_node_dir = os.path.join(directory, HTML_NODE_FILE_NAME)
        sql_node_dir = os.path.join(directory, SQL_NODE_FILE_NAME)

        node_df = pd.read_csv(nodeDir)
        edge_df = pd.read_csv(edgeDir)
        html_node_df = pd.read_csv(html_node_dir)
        sql_node_df = pd.read_csv(sql_node_dir)
    else:
        node_df = NODE_DF
        edge_df = EDGE_DF
        html_node_df = HTML_NODE_DF
        sql_node_df = SQL_NODE_DF

    importNodeToNeo4j(graph, node_df)
    importHTMLNodeToNeo4j(graph, html_node_df)
    importSQLNodeToNeo4j(graph, sql_node_df)
    importEdgeToNeo4j(graph, edge_df)

    #clean up the current commit
    NODE_DF = []
    EDGE_DF = []
    HTML_NODE_DF = []
    SQL_NODE_DF = []
    incrementStep()


def importNodeToNeo4j(graph, node_df):
    count = 1
    tx = graph.begin()

    for row in node_df:
        node_info_list = [f"""id: {int(row['id'])}, type: "{neo4j_escape(row['type'])}" """]

        if not isFieldNull(row['flags']):
            quoted_flags = [f'"{neo4j_escape(f)}"' for f in row['flags']]
            node_info_list.append(f"""flags: [{", ".join(quoted_flags)}]""")
        if not isFieldNull(row['lineno']) and int(row['lineno']) >= 0:
            node_info_list.append(f"""lineno: {row['lineno']}""")
        if not isFieldNull(row['childnum']) and int(row['childnum']) >= 0:
            node_info_list.append(f"""childnum: {int(row['childnum'])}""")
        if not isFieldNull(row['code']):
            code_clean = neo4j_escape(row['code'])
            if len(code_clean) > MAX_NODE_CODE_LENGTH:
                code_clean = code_clean[:MAX_NODE_CODE_LENGTH - 3] + "..."
            node_info_list.append(f"""code: "{code_clean}" """)
        if not isFieldNull(row['funcid']):
            try:
                node_info_list.append(f"""funcid: {int(row['funcid'])}""")
            except:
                pass
        if not isFieldNull(row['name']):
            node_info_list.append(f"""name: "{neo4j_escape(row['name'])}" """)
        if not isFieldNull(row['classname']):
            node_info_list.append(f"""classname: "{neo4j_escape(row['classname'])}" """)
        if not isFieldNull(row['namespace']):
            node_info_list.append(f"""namespace: "{neo4j_escape(row['namespace'])}" """)
        if not isFieldNull(row['endlineno']):
            node_info_list.append(f"""endlineno: {row['endlineno']}""")
        if not isFieldNull(row['doccomment']):
            node_info_list.append(f"""doccomment: "{neo4j_escape(row['doccomment'])}" """)
        node_info_str = ", ".join([s.strip() for s in node_info_list])

        # Now insert node at newly open spot.
        query = f"""
        CREATE (:{row['label']}{{{node_info_str}}})
        """
        tx.run(query)

        if count % 1000 == 0 or count == len(node_df):
            print(str(count) + " Nodes Created")
            graph.commit(tx)
            tx = graph.begin()
        count += 1


def importHTMLNodeToNeo4j(graph, html_node_df):
    count = 1
    tx = graph.begin()
    for row in html_node_df:
        node_info_list = [
            f"""id: {int(row['id'])}, type: "{neo4j_escape(row['type'])}", childnum: {int(row['childnum'])}"""
        ]
        if not isFieldNull(row['startIndex']):
            node_info_list.append(f"""startIndex: {int(row['startIndex'])}""")
        if not isFieldNull(row['endIndex']):
            node_info_list.append(f"""endIndex: {int(row['endIndex'])}""")
        if not isFieldNull(row['code']):
            code_clean = neo4j_escape(row['code'])
            if len(code_clean) > MAX_NODE_CODE_LENGTH:
                code_clean = code_clean[:MAX_NODE_CODE_LENGTH - 3] + "..."
            node_info_list.append(f"""code: "{code_clean}" """)
        if not isFieldNull(row['name']):
            node_info_list.append(f"""name: "{neo4j_escape(row['name'])}" """)
        node_info_str = ", ".join([s.strip() for s in node_info_list])

        # Now insert node at newly open spot.
        query = f"""
        CREATE (:{row['label']}{{{node_info_str}}})
        """
        tx.run(query)

        if count % 1000 == 0 or count == len(html_node_df):
            print(str(count) + " HTML Nodes Created")
            graph.commit(tx)
            tx = graph.begin()
        count += 1


def importSQLNodeToNeo4j(graph, sql_node_df):
    count = 1
    tx = graph.begin()
    for row in sql_node_df:
        node_info_list = [
            f"""id: {int(row['id'])}, type: "{neo4j_escape(row['type'])}", childnum: {int(row['childnum'])}, table: "{neo4j_escape(row['table'])}" """
        ]
        if row['columns'] is not None:
            convertedStr = str(row['columns'])
            convertedLst = convertedStr.strip('][').split(', ')
            convertedLst = [f.strip("'") for f in convertedLst]
            convertedLst = [f.strip('"') for f in convertedLst]
            quoted_columns = [f'"{neo4j_escape(f)}"' for f in convertedLst]
            node_info_list.append(f"""columns: [{", ".join(quoted_columns)}]""")
        if not isFieldNull(row['lineno']) and int(row['lineno']) >= 0:
            node_info_list.append(f"""lineno: {row['lineno']}""")
        if not isFieldNull(row['childnum']) and int(row['childnum']) >= 0:
            node_info_list.append(f"""childnum: {int(row['childnum'])}""")
        if not isFieldNull(row['code']):
            code_clean = neo4j_escape(row['code'])
            if len(code_clean) > MAX_NODE_CODE_LENGTH:
                code_clean = code_clean[:MAX_NODE_CODE_LENGTH - 3] + "..."
            node_info_list.append(f"""code: "{code_clean}" """)

        node_info_str = ", ".join([s.strip() for s in node_info_list])

        # Now insert node at newly open spot.
        query = f"""
        CREATE (:{row['label']}{{{node_info_str}}})
        """
        tx.run(query)

        if count % 1000 == 0 or count == len(sql_node_df):
            print(str(count) + " SQL Nodes Created")
            graph.commit(tx)
            tx = graph.begin()
        count += 1


def _grouper(k):
    return k['start_label'], k['end_label'], k['type']


def importEdgeToNeo4j(graph, edge_df):
    for name, group in groupby(edge_df, _grouper):
        data = []
        count = 1

        group = list(group)
        for row in group:
            data.append(((row['start_id']), {}, (row['end_id'])))
            if count % 1000 == 0 or count == len(group):
                #print(row)
                #print(data)
                #print(name)
                print(str(count) + f" {name[2]} edges created")
                create_relationships(graph.auto(),
                                     data,
                                     name[2],
                                     start_node_key=(name[0], 'id'),
                                     end_node_key=(name[1], 'id'))
                data = []
            count += 1

    print(f"{len(edge_df)} edges imported to Neo4j")


def insertChildNode(
    parent_id: int,
    desired_childnum: int,
    label: str,
    type: str,
    desired_id: Optional[int] = None,
    flags: Optional[List[str]] = None,
    lineno: Optional[int] = None,
    code: Optional[str] = None,
    funcid: Optional[int] = None,
    name: Optional[str] = None,
    classname: Optional[str] = None,
    namespace: Optional[str] = None,
    endlineno: Optional[int] = None,
    doccomment: Optional[str] = None,
    edge_label: str = "PARENT_OF",
    start_label: str = None,
    wait: bool = False,
) -> bool:
    id = addNode(label, type, flags, lineno, code, desired_childnum, funcid, classname, namespace, endlineno, name,
                 doccomment)
    addEdge(parent_id, start_label, id, label, edge_label, None)
    return True


def insertEdge(
    start_id: int,
    end_id: int,
    label: str,
    edge_data: Dict[str, str] = {},
    wait: bool = False,
):
    graph = getGraph()

    properties_str = ", ".join(f"""{neo4j_escape(k)}: "{neo4j_escape(v)}" """.strip() for k, v in edge_data.items())
    query = f"""
    MATCH (s{{id:{start_id}}}), (e{{id:{end_id}}})
    MERGE (s)-[:{label}{{{properties_str}}}]->(e)
    """

    graph.run(query)
