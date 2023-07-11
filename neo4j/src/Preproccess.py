# GDPR Checker - Preprocess.py
# Patrick Thomas pwt5ca
# Created 201216
from PersonalData import PersonalDataMatcher
from concurrent import futures
from grp import getgrall
from os import name, setuid
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple, Union

from preprocessing.Pipeline import Pipeline
from preprocessing.filesystem.FileSystemPreprocessor import FileSystemPreprocessor
from preprocessing.filesystem.FileSystemToAstPreprocessor import FileSystemToAstPreprocessor
from preprocessing.html.HTMLPreprocessor import HTMLPreprocessor
from preprocessing.html.PHPAsHTMLPreprocessor import PHPAsHTMLPreprocessor
from preprocessing.htmltojs.HTMLToJSPreprocessor import HTMLToJSPreprocessor
from preprocessing.general.DeletePreprocessor import DeletePreprocessor
from visualize.Dotifier import Dotifier

# NB: Detectors detect node of interests. A node of interest is not necessarily a violation right away.
from Detectors.Detectors import AbstractDetector
from Detectors.Runtime import DATABASE_DIR, PLUGIN_NAME, SECURITY_DETECTOR_MANAGER, PLUGIN_DIR
from HTMLParser import HTMLNode, PhpHtmlParser
from NeoHelper import *
from Results import register_plugin, write_source_sink
from Settings import USEFUL_NODES
from SourcesSinks import SourceSinkManager
from Utls import progress_bar
from ClassStructure import getClassHierarchy, determineObjectType
from ValueResolver import evaluateExpression, evaluateExpressionUnjoined
from SQLParser import SQLToAST1, getSQLParentNodes
from DataFlowTracking import allTraversalTypeAPOC
from ActionHook import getHookedFnToWPAJAX
from jQuerySelectorParser import getSelectedHTMLFormInputs

from HTMLParser2 import *
from Detectors.Scores import ScoreType

__WPDB_QUERIES = [
    "dbDelta",
    "exec",
    "execute",
    "get_col",
    "get_results",
    "get_row",
    #"prepare",
    "query",
]
__WPDB_QUERIES_REGEX = f"({'|'.join(__WPDB_QUERIES)})"

# Some options to skip parts of the program. Only for development use.
__OPTIONS = {
    "skip_sql": False,    # Skip parts of the program that look for SQL commands and add them to Neo4j.
    "skip_html": False,    # Skip adding the HTML AST from embedded ECHO statements.
    "quick": False,    # Skip a lot of the long running, slower functions.
    "skip_if_already_preprocessed": False,    # Skip all of preprocessing if it has been done once already.
}

_step_counter: int = 0

_IDs_with_preprocessed_edges = set()
_ID_pairs_with_preprocessed_edges = set()
global classHierarchy
classHierarchy = None


def _preprocess_step(step_name: str):

    def _inner(function):

        def _wrapper(*args, **kwargs):
            global _step_counter
            _step_counter += 1
            print(f"""╔[{_step_counter}] Preprocessing step "{step_name}" ({function.__name__}) begin.""")
            start = datetime.now()
            try:
                result = function(*args, **kwargs)
            except Exception as e:
                delta = datetime.now() - start
                print(f"Preprocessing step [{step_name}] failed in {delta}.")
                print(e)
                raise e
            delta = datetime.now() - start
            print(
                f"""╚[{_step_counter}] Preprocessing step "{step_name}" ({function.__name__}) finished successfully in {delta}.\n"""
            )
            return result

        return _wrapper

    return _inner


def preprocess_graph(only_encryption: bool = False, skip_preprocessing=False):
    """Run commands that finalize the AST in Neo4j.

    This includes operations like adding the parent-to-self edges, converting SQL into ASTs, and also converting HTML to ASTs.
    """
    global SECURITY_DETECTOR_MANAGER
    if only_encryption:
        __OPTIONS["skip_sql"] = True

    print("### Starting preproccessing!")

    print("Registering plugin to plugin database... ", end="")
    register_plugin(DATABASE_DIR, PLUGIN_NAME)
    print("Plugin registration done")

    #This part is merged to the SECURITY_DETECTOR_MANAGER's constructor
    # Load function information from manual analysis.
    # load_function_info()

    if __OPTIONS["skip_if_already_preprocessed"] or skip_preprocessing:
        # node_count = getGraph().evaluate("""MATCH (n) WHERE EXISTS(n.preprocessed) RETURN COUNT(n)""")
        # if node_count or skip_preprocessing:
        print("SKIPPING ALL OF PREPROCESSING")
        if not SECURITY_DETECTOR_MANAGER:
            sys.exit(1)
        SECURITY_DETECTOR_MANAGER.run()
        return

    # Remove old preprocessed nodes.
    # getGraph().run("""MATCH (n) WHERE EXISTS(n.preprocessed) DETACH DELETE n""")
    # getGraph().run("""MATCH ()-[r]->() WHERE EXISTS(r.preprocessed) DELETE r""")
    # getGraph().run("""MATCH ()-[r]->() WHERE EXISTS(r.preprocessed) DELETE r""")
    getGraph().run("""MATCH (s:SINK) REMOVE s:SINK RETURN COUNT(s)""")
    getGraph().run("""MATCH (s:SOURCE) REMOVE s:SOURCE RETURN COUNT(s)""")

    preprocess_start = datetime.now()
    #the preprocessing tasks are done in steps. For each steps, the order in which the tasks are completed does not matter. However, each step depends on the previous step/steps to be completed.
    #Note that if the plugin is preprocessed before, some steps can be skipped by just reading from previously generated node/edge files, but some steps are still required,
    #and the boolean in each step denotes if the step is required.

    pipeline = Pipeline()
    pipeline.register(
        DeletePreprocessor('delete', 'Filesystem'),
        FileSystemPreprocessor('filesystem', PLUGIN_DIR),
        FileSystemToAstPreprocessor('filesystemtoast'),
        HTMLPreprocessor('html'),
        PHPAsHTMLPreprocessor('phphtml'),
        HTMLToJSPreprocessor('htmltojs'),
    )
    pipeline.trigger(getGraph())

    stepTasks = [
        ([__label_js_nodes], True),
        ([__create_indices], True),
        ([__fill_class_hierarchy], True),
        ([
            __handle_class_properties, __connect_ASTPARAM_to_var, __php_reach_edges, __parent_self_edges,
            __class_constant_hierarchy, __ast_assign_function_edges, __build_php_js_hierarchical_edges, js_to_wp_ajax
        ], False),
        ([__remove_wrong_hierarchical_edges], True),
        ([__iterated_create_call_edges, __html_to_php_reaches, html_form_input_to_jquery_find], False),
        ([__overtaintFunctionCalls], False),
        ([__add_sql_ast, __build_html_ast_in_php, __connect_html_php_ast, __do_action_to_function], False),
        ([__security_detectors], True),
        ([__storage_to_retrieval, __add_source_sink_to_db], True),
        ([remove_edge_from_key_to_sink], True),
        ([__taint_nodes], True),
    ]

    for step, required in stepTasks:
        print(f'starting step')
        setUp()
        for task in step:
            task()
        commit()


def __fill_class_hierarchy():
    global classHierarchy
    classHierarchy = getClassHierarchy()


@_preprocess_step(step_name="Connect JS jquery calls to PHP callbacks")
def js_to_wp_ajax():
    """
    JS jquery calls (.post, .get, .ajax) with url ajaxurl goes to the admin-ajax.php in wordpress core,
    which will fire a wp_ajax_myaction and a wp_ajax_nopriv_myaction. So this function aims to connect
    dataflow from JS to the callback functions hooked to those actions fired by wordpress core.
    """
    count = 0
    graph = getGraph()
    #locate all functions hooked to wp_ajax_* actions
    ajaxHooks = getHookedFnToWPAJAX()
    for callbackFnID, action in ajaxHooks:
        #find corresponding calls in JS with such action.
        #first try .ajax calls
        query = f"""
        MATCH (n:AST_JS{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(var2:AST_JS{{childnum:1,type:'string',code:'ajax'}})
        MATCH (n)-[:PARENT_OF]->(:AST_JS{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(:AST_JS{{childnum:0,type:'AST_ARRAY'}})-[:PARENT_OF]->(dataNode:AST_JS{{type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(:AST_JS{{childnum:1,code:'data'}})
        MATCH (dataNode)-[:PARENT_OF]->(dataArray:AST_JS{{childnum:0,type:'AST_ARRAY'}})-[:PARENT_OF]->(actionNode:AST_JS{{type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(:AST_JS{{childnum:1,code:'action'}})
        MATCH (actionNode)-[:PARENT_OF]->(actionString:AST_JS{{childnum:0,type:'string',code:'{action}'}})
        RETURN dataArray.id
        """
        results = graph.run(query).data()
        if not results:
            #try .post calls
            query = f"""
            MATCH (n:AST_JS{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(var2:AST_JS{{childnum:1,type:'string',code:'post'}})
            MATCH (n)-[:PARENT_OF]->(:AST_JS{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(:AST_JS{{childnum:0,type:'AST_ARRAY'}})-[:PARENT_OF]->(dataNode:AST_JS{{type:'AST_ARRAY_ELEM',childum:1}})
            MATCH (dataNode)-[:PARENT_OF]->(dataArray:AST_JS{{childnum:0,type:'AST_ARRAY'}})-[:PARENT_OF]->(actionNode:AST_JS{{type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(:AST_JS{{childnum:1,code:'action'}})
            MATCH (actionNode)-[:PARENT_OF]->(actionString:AST_JS{{childnum:0,type:'string',code:'{action}'}})
            RETURN dataArray.id
            """
            results = graph.run(query).data()
            if not results:
                continue
        for r in results:
            dataArrayID = r['dataArray.id']
            query = f"""
            MATCH (dataArray:AST_JS{{id:{dataArrayID}}})-[:PARENT_OF]->(elem:AST_JS{{type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(dataNode:AST_JS{{childnum:0}})
            MATCH (dataName:AST_JS{{childnum:1,type:'string'}})<-[:PARENT_OF]-(elem)-[:PARENT_OF]->(dataNode:AST_JS{{childnum:0}})
            WHERE NOT dataName.code = 'action'
            RETURN dataNode.id,dataName.code
            """
            dataResult = graph.run(query).data()
            if not dataResult:
                continue
            for data in dataResult:
                dataNodeID = data['dataNode.id']
                dataName = data['dataName.code']

                try:
                    personalDataType = PersonalDataMatcher.determine_category(dataName)
                    print('javascript personal data finder', personalDataType)
                except Exception as e:
                    print('Exception occured while extracting PII')
                    print(dataName)
                    print(e)

                connectQuery = f"""
                MATCH (n:AST{{type:'string',code:'{dataName}'}})<-[:PARENT_OF]-(x:AST{{type:'AST_DIM',funcid:{callbackFnID}}})-[:PARENT_OF]->(m:AST{{type:'AST_VAR'}})-[:PARENT_OF]->(y:AST{{type:'string'}})
                WHERE (y.code = '_POST' OR y.code = '_GET' OR y.code = '_REQUEST')
                RETURN COLLECT(DISTINCT x.id)
                """
                php_vars: List[int] = graph.evaluate(connectQuery)
                if not php_vars:
                    continue
                #create flows between JS ajax data values and php vars
                for var in php_vars:
                    count += addEdge(dataNodeID, "AST_JS", var, "AST", "JS_TO_PHP_REACHES")

    print(f"Added {count} JS_TO_PHP_REACHES edges.")


@_preprocess_step(step_name="Connect wp_localize_script() object fields to JS")
def wp_localize_script_to_js():
    count = 0
    # wp_localize_script() creates a js object. This function analyzes wp_localize_script() calls and connects dataflow to the object usage in js
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{type:'AST_CALL'}})-[:PARENT_OF]->(:AST{{childnum:0,type:'AST_NAME'}})-[:PARENT_OF]->(:AST{{code:'wp_localize_script'}})
    MATCH (n)-[:PARENT_OF]->(arg_list:AST{{childnum:1,type:'AST_ARG_LIST'}})
    RETURN arg_list.id
    """
    result = graph.run(cypher=query).data()
    if not result:
        print("No wp_localize_script() usage found. ")
        return
    for r in result:
        argListID = r['arg_list.id']

        query = f"""
        MATCH (arg_list:AST{{id:{argListID}}})-[:PARENT_OF]->(obj_name{{childnum:1,type:'string'}})
        RETURN obj_name.code
        """
        #name of js object
        obj_name = graph.evaluate(query)
        if not obj_name:
            continue
        query = f"""
        MATCH (arg_list:AST{{id:{argListID}}})-[:PARENT_OF]->(property{{childnum:2,type:'AST_ARRAY'}})-[:PARENT_OF]->(array_elem{{type:'AST_ARRAY_ELEM'}})
        MATCH (property_name{{childnum:1,type:'string'}})<-[:PARENT_OF]-(array_elem)-[:PARENT_OF]->(data_node{{childnum:0}})
        RETURN property_name.code,data_node.id
        """
        property_result = graph.run(cypher=query).data()
        if not property_result:
            continue
        #properties names and IDs of data nodes
        property_name_data_pairs = [(p['property_name.code'], p['data_node.id']) for p in property_result]

        #next, find their usages in JS and connect dataflows
        for property_name, data_node_id in property_name_data_pairs:
            query = f"""
            MATCH (:AST_JS{{childnum:1,type:'string',code:'{property_name}'}})<-[:PARENT_OF]-(prop:AST_JS{{type:'AST_PROP'}})-[:PARENT_OF]->(:AST_JS{{childnum:0,type:'AST_VAR'}})-[:PARENT_OF]->({{type:'string',code:'{obj_name}'}})
            RETURN prop.id
            """

            property_use_result = graph.run(cypher=query).data()
            if not property_use_result:
                continue
            # at this point, we have found the usage of the object property in js
            for property_use_id in property_use_result:
                count += addEdge(data_node_id, "AST", property_use_id['prop.id'], "AST_JS", "PHP_TO_JS_REACHES")

    print(f"Added {count} PHP_TO_JS_REACHES edges.")


def __iterated_create_call_edges():
    iteration = 0
    while True:
        iteration += 1
        #set a safe bound in case there's an infinite loop
        if iteration > 200:
            break
        callEdgeCount = __handle_class_hierarchy()
        functionCallEdgeCount = __function_call_edges()
        __ast_call_return_edges()
        if callEdgeCount == 0 and functionCallEdgeCount == 0:
            break


@_preprocess_step(step_name="Building edges from HTML form inputs to jquery .find functions")
def html_form_input_to_jquery_find():
    # find .find() usages and get the selector statement
    count = 0
    graph = getGraph()
    query = f"""
    MATCH (n:AST_JS{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(:AST_JS{{childnum:1,code:'find'}})
    MATCH (n)-[:PARENT_OF]->(:AST_JS{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(selector:AST_JS{{childnum:0,type:'string'}})
    RETURN n.id, selector.code
    """
    result = graph.run(cypher=query).data()
    if not result:
        print("No .find() calls found in JS")
        return
    for r in result:
        callID = r['n.id']
        selector_string = r['selector.code']

        # parse the selector statement and interpret it to locate the html form inputs
        nodeIDs = getSelectedHTMLFormInputs(selector_string)

        # connect dataflow edges from html form inputs to the .find statement
        for id in nodeIDs:
            count += addEdge(id, 'AST_HTML', callID, 'AST_JS', 'HTML_TO_JS_REACHES')
    print(f"Added {count} HTML_TO_JS_REACHES edges.")


@_preprocess_step(step_name="Building HTML ASTs")
def __build_html_ast(graph=None):
    print(f'starting __build_html_ast_in_php')
    start_time = datetime.now()
    #first find all source files that have html code and their directories, then parse the files using html parser.
    #PLUGIN_DIR = "/Users/zihaosu/Documents/GDPR-CCPA-violation-checker/navex_docker/exampleApps/gdprplugin"
    if not graph:
        graph = getGraph()

    listOfFiles = list()
    for (dirpath, _, filenames) in os.walk(PLUGIN_DIR):
        listOfFiles += [
            os.path.join(dirpath, file) for file in filenames if (file.endswith(".php") or (file.endswith(".html")))
        ]
    for dir in listOfFiles:
        filename = os.path.basename(dir)
        #create Filesystem and toplevel nodes if not present
        subdir = dir.replace(PLUGIN_DIR, "")
        folderHierarchy = os.path.dirname(subdir).split("/")
        folderHierarchy = [i for i in folderHierarchy if i]
        baseID = 0
        for subdir in folderHierarchy:
            query = f"""
            MATCH (n:Filesystem{{id:{baseID}}})-[:DIRECTORY_OF]->(m:Filesystem{{name:'{subdir}'}})
            RETURN m.id
            """
            result = graph.evaluate(cypher=query)
            if result:
                baseID = result
            else:
                print(f"Added new directory node for: {subdir}")
                newBaseID = addNode("Filesystem", "Directory", name=folderHierarchy[-1])
                addEdge(baseID, "Filesystem", newBaseID, "Filesystem", "DIRECTORY_OF")
                baseID = newBaseID
        query = f"""
        MATCH (n:Filesystem{{id:{baseID}}})-[:DIRECTORY_OF]->(m:Filesystem{{name:'{filename}'}})-[:FILE_OF]->(toplevel:AST)
        RETURN toplevel.id
        """
        toplevelID = graph.evaluate(cypher=query)
        if not toplevelID:
            print(f"Added new filesystem node for: {dir}")
            FileNodeID = addNode("Filesystem", "File", name=filename)
            toplevelID = addNode("AST", "AST_TOPLEVEL", flags=["TOPLEVEL_FILE"], lineno=1, endlineno=1, name=subdir)
            addEdge(baseID, "Filesystem", FileNodeID, "Filesystem", "DIRECTORY_OF")
            addEdge(FileNodeID, "Filesystem", toplevelID, "AST", "FILE_OF")
        parseHTML(dir, toplevelID)
    end_time = datetime.now()
    delta = end_time - start_time
    print(f'build_html_as_php completed in {delta.total_seconds() * 1000} seconds')


@_preprocess_step(step_name="Build HTML AST for HTML embedded in PHP code (HTML to PHP traversal)")
def __build_html_ast_in_php():
    # find php code 'echo xxx' and parse the echoed HTML code
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{type:'AST_ECHO'}})-[:PARENT_OF]->(m:AST) WHERE NOT (n)-[:PARENT_OF]->({{type:'string'}})
    RETURN m.id
    """
    result = graph.run(cypher=query).data()
    if result:
        for r in result:
            evaluatedString = evaluateExpression(r['m.id'])[0]
            if evaluatedString:
                parseHTML(evaluatedString, r['m.id'], True)

    query2 = f"""
    MATCH (n{{type:'AST_ECHO'}})-[:PARENT_OF]->(x{{type:'string'}}) WHERE NOT (:AST{{type:'NULL'}})-[:FLOWS_TO]->(n) AND NOT (n.lineno=1) RETURN x.code,x.id
    """
    result2 = graph.run(cypher=query2).data()
    if result2:
        for r in result2:
            if r['x.code']:
                parseHTML(r['x.code'], r['x.id'], True)


@_preprocess_step(step_name="Connect HTML AST and PHP AST trees (PHP to HTML traversal)")
def __connect_html_php_ast():
    #this function connects inline traversal from PHP to HTML (e.g., <p> <?php echo $foo ?> </p>)
    count = 0
    numfile = 0
    success = 0
    graph = getGraph()
    #first find all files with HTML code
    query = f"""
    MATCH (toplevel:AST{{type:'AST_TOPLEVEL'}})-[:PARENT_OF]->(root:AST_HTML{{type:'root'}})
    RETURN toplevel.id,root.id
    """
    result = graph.run(cypher=query).data()
    if result:

        for r in result:
            toplevel_id = r['toplevel.id']
            #find all php end tags in php ast. there are sometimes endtags for endif
            php_code_group_query = f"""
            MATCH (toplevel:AST{{id:{toplevel_id}}})-[:PARENT_OF*]->(nl:AST{{type:'NULL'}})-[:FLOWS_TO]->()
            RETURN nl.id ORDER BY nl.id
            """
            php_code_group_result = graph.run(cypher=php_code_group_query).data()
            php_end_tag_id = []
            if php_code_group_result:
                php_end_tag_id = [f['nl.id'] for f in php_code_group_result]

            root_id = r['root.id']
            #next, find all php placeholders in the html ast tree in sorted order. Note: endforeach has corresponding 'NULL' in PHP AST, so its PHP placeholder is not discarded.
            php_placeholder_query = f"""
            MATCH (root:AST_HTML{{id:{root_id}}})-[:PARENT_OF*]->(php:AST_HTML{{name:'?php'}})
            WHERE NOT (php.code CONTAINS ' endif ' OR php.code CONTAINS ' endwhile ' OR php.code CONTAINS ' endforeach ' OR php.code CONTAINS ' endfor ' OR php.code CONTAINS ' endswitch ')
            RETURN php.id ORDER BY php.id ASC
            """
            php_placeholder_result = graph.run(cypher=php_placeholder_query).data()
            php_placeholder_node_id = []
            if php_placeholder_result:
                php_placeholder_node_id = [f['php.id'] for f in php_placeholder_result]

            if php_end_tag_id and php_placeholder_node_id:
                numfile += 1
                #if we cannot match the number of php blocks in html AST and that in PHP AST, we give up on the current file.
                if not ((len(php_placeholder_node_id) == len(php_end_tag_id) + 1) or
                        (len(php_placeholder_node_id) == len(php_end_tag_id))):
                    print(
                        f"Cannot match corresponding html and php nodes due to unequal number of php end tags and php code's placeholders: {len(php_end_tag_id)} end tag vs {len(php_placeholder_node_id)} placeholders. toplevel id: {toplevel_id}"
                    )
                    continue
                else:
                    current = None
                    next = None
                    for i in range(len(php_end_tag_id)):
                        if i == 0:
                            startOfFileNode = f"""
                            MATCH (toplevel:AST{{id:{toplevel_id}}})-[:PARENT_OF]->(stmtList:AST{{type:'AST_STMT_LIST'}})-[:PARENT_OF]->(first:AST{{childnum:0}})
                            RETURN first.id
                            """
                            current = graph.evaluate(cypher=startOfFileNode)
                        else:
                            current = php_end_tag_id[i - 1]
                        next = php_end_tag_id[i]
                        #try to get a control flow path from current to next, and connect all the in-between nodes to the html node. Hard cap at length 15 to ensure run time efficiency.
                        pathQuery = f"""
                        MATCH p=((current:AST{{id:{current}}})-[:FLOWS_TO*1..15]-(next:AST{{id:{next}}}))
                        UNWIND nodes(p) AS ns
                        RETURN ns
                        """
                        pathResult = graph.run(cypher=pathQuery).data()
                        if pathResult:
                            count = 0
                            for n in pathResult:
                                nodeID = n['ns']['id']
                                if nodeID != current and nodeID != next and (
                                        not (n['ns']['type'] == 'AST_ECHO' and count == 1 and len(pathResult) > 3)):
                                    count += addEdge(nodeID, 'AST', php_placeholder_node_id[i], 'AST_HTML',
                                                     'PHP_TO_HTML_REACHES')
                                count += 1
                    success += 1
    print(
        f"Successfully connected PHP to HTML ASTs in {success} out of {numfile} files. Added {count} PHP_TO_HTML_REACHES edges."
    )


@_preprocess_step(step_name="Ensure PHP_REACHES Hierarchical Edge Coverage")
def __ensure_hierarchy_edge_coverage():
    # deprecated
    count = 0
    print("Finding all distinct parent nodes connected via PHP_REACHES...")
    graph = getGraph()
    query = f"""
    MATCH ()<-[:FLOWS_TO]-(root:AST)-[:PARENT_OF*]->(n:AST)-[:PHP_REACHES]-()
    RETURN DISTINCT root.id
    """
    result = graph.run(cypher=query).data()
    print("Checking missing hierarchical edges and building edges...")
    if not result:
        return

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(help_build_hierarchy_from_root, root['root.id']) for root in progress_bar(result)]
        for f in futures:
            count += f.result()

    print(f"Added {count} PHP_REACHES edges.")


def help_build_hierarchy_from_root(nodeID):
    global _IDs_with_preprocessed_edges
    count = 0
    if nodeID in _IDs_with_preprocessed_edges:
        return 0
    _IDs_with_preprocessed_edges.add(nodeID)
    first_tier_useful_nodes = eliminateUselessNodes(nodeID)
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(help_ast_connect_hierarchy, node) for node in first_tier_useful_nodes]
        for f in futures:
            count += f.result()
    return count


def __add_source_sink_to_db():
    ssm = SourceSinkManager()
    ssm.add_labels_to_database()


@_preprocess_step(step_name="Connect data flows for class constants")
def __class_constant_hierarchy():
    count = 0
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{type:'AST_CLASS_CONST_DECL'}})-[:PARENT_OF]->(:AST{{type:'AST_CONST_ELEM'}})-[:PARENT_OF]->(children:AST)
    RETURN COLLECT(children) AS childrens,n.id
    """
    result = graph.run(cypher=query).data()
    futures = []
    if not result:
        return

    with ThreadPoolExecutor() as executor:
        for i in result:
            for child in i['childrens']:
                if child['childnum'] == 1:
                    futures.append(executor.submit(__add_php_reaches_edge, child['id'], i['n.id']))
        for f in futures:
            count += f.result()
    print(f"Added {count} PHP_REACHES edges.")


@_preprocess_step(step_name="Label all of the personal data nodes and encrypted nodes")
def __taint_nodes():
    if not SECURITY_DETECTOR_MANAGER:
        print("security detector not initialized")
        sys.exit(1)
    status = __taint_personal_nodes()
    if status == 0:
        return
    __taint_encrypted_nodes()


def __taint_personal_nodes():
    #taint all nodes that contain PII in the graph
    graph = getGraph()
    #dictionary of personal data nodes and their personal data types
    #key: nodeID of personal data node. value: a set that contains all personal data types
    allIDs = {}
    for f in SECURITY_DETECTOR_MANAGER.allFindings:
        if f.score.is_personal():
            allIDs[f.node['id']] = set(f.score.get_data_types_personal())
    remainingNodes = list(allIDs.keys())
    if len(remainingNodes) == 0:
        return 0
    allSourceSinkPair = set()
    allSources = {}
    #for all source nodes, their sources are themselves.
    for id in allIDs:
        allSources[id] = set([id])
    #print(remainingNodes)
    #propagate the personal data label, and merge personal data types if two nodes join into a same path.
    while remainingNodes:
        newNodes = []
        for id in progress_bar(remainingNodes):
            query = f"""
            MATCH (n{{id:{id}}})
            CALL apoc.path.subgraphNodes(n, {{
                relationshipFilter: "{allTraversalTypeAPOC()}"
            }})
            YIELD node
            RETURN node;
            """
            result = graph.run(cypher=query).data()
            #print("Finished query")
            for i in result:
                mid = i['node']['id']
                if not id == mid:
                    allSourceSinkPair.add((id, mid))
                    if mid in allSources:
                        allSources[mid].add(id)
                    else:
                        allSources[mid] = set([id])
                    if mid in allIDs:
                        previousCopy = len(allIDs[mid])
                        #update personal data type
                        allIDs[mid].update(allIDs[id])
                        if not previousCopy == len(allIDs[mid]):
                            newNodes.append(mid)
                    else:
                        allIDs[mid] = allIDs[id]
        remainingNodes = newNodes
    print("Finished collecting propagation info for personal nodes")
    write_source_sink(list(allSourceSinkPair))
    print("Wrote source sink information to database")
    #print(allIDs)
    #at this point the data types for the nodes have converged. Now we put personal data label and data type property to the neo4j graph
    count = 1
    tx = graph.begin()
    for id in allIDs:

        query = f"""
        MATCH (n{{id:{id}}})
        SET n :PERSONAL
        SET n.personal_types = {list(allIDs[id])}, n.sources = {list(allSources[id])}
        """

        tx.run(query)
        if count % 1000 == 0 or count == len(allIDs):
            print(f"Tainted {count} nodes as PERSONAL")
            graph.commit(tx)
            tx = graph.begin()
        count += 1
        # graph.run(cypher=query)
    print(f"In total, tainted {len(allIDs)} nodes as PERSONAL")
    return 1


def __taint_encrypted_nodes():
    graph = getGraph()
    #taint cryptography nodes
    allIDs = {}
    for f in SECURITY_DETECTOR_MANAGER.allFindings:
        if f.score.score_type == ScoreType.CRYPTOGRAPHY:
            allIDs[f.node['id']] = [
                f.score.value,
                set([f.score.encryption_method if f.score.encryption_method else "generic"])
            ]
    remainingNodes = list(allIDs.keys())
    allSourceSinkPair = set()
    #print(remainingNodes)
    #propagate the personal data label, and
    while remainingNodes:
        newNodes = []
        for id in progress_bar(remainingNodes):
            query = f"""
            MATCH (n{{id:{id}}})
            CALL apoc.path.subgraphNodes(n, {{
                relationshipFilter: "{allTraversalTypeAPOC()}"
            }})
            YIELD node
            RETURN node;
            """
            result = graph.run(cypher=query).data()
            #print("Finished query")
            for i in result:
                mid = i['node']['id']
                if not id == mid:
                    allSourceSinkPair.add((id, mid))
                    if mid in allIDs:
                        previousCopy = len(allIDs[mid])
                        newEncryptionMethodSet = allIDs[mid][1].copy()
                        newEncryptionMethodSet.update(allIDs[id][1])
                        #update encryption info in the new node. If both nodes have encryption score before, use the minimum of the two as the new score.
                        allIDs[mid] = [min(allIDs[mid][0], allIDs[id][0]), newEncryptionMethodSet]
                        if not previousCopy == len(allIDs[mid]):
                            newNodes.append(mid)
                    else:
                        allIDs[mid] = allIDs[id]
        remainingNodes = newNodes
    print("Finished collecting propagation info for encrypted nodes")
    #write_source_sink(list(allSourceSinkPair))
    #print(allIDs)
    #at this point the encryption method for the nodes have converged. Now we put encryption data label and encryption info to the neo4j graph

    count = 1
    tx = graph.begin()
    for id in allIDs:

        query = f"""
        MATCH (n{{id:{id}}})
        SET n :SECURE
        SET n.encryption_score = {allIDs[id][0]}, n.encryption_method = {list(allIDs[id][1])}
        """
        #print(query)
        tx.run(query)
        if count % 1000 == 0 or count == len(allIDs):
            print(f"Tainted {count} nodes as ENCRYPTED")
            graph.commit(tx)
            tx = graph.begin()
        count += 1
        # graph.run(cypher=query)
    print(f"In total, tainted {len(allIDs)} nodes as ENCRYPTED")


@_preprocess_step(step_name="connect data flows for class properties")
def __handle_class_properties():
    global classHierarchy
    graph = getGraph()
    #connect dataflows for class variables
    count = 0
    for className in progress_bar(classHierarchy.classes):
        hasConnectedFlows = False
        classObj = classHierarchy.classes[className]
        for var in classObj.classVariables:
            dataNodeObj = classObj.classVariables[var]

            #first, if applicable, connect data flows from the default value of the class variable to the variable (so the source would be the value)
            if dataNodeObj.value:
                #this is a query to avoid the attempt to connect the dataflows if the edges are all created before.
                hasFlowsQuery = f"""
                MATCH r = (:AST{{id:{dataNodeObj.value}}})-[:PHP_REACHES]->(:AST{{id:{dataNodeObj.id}}})
                RETURN r
                """
                hasFlowsResult = graph.evaluate(hasFlowsQuery)
                if hasFlowsResult:
                    hasConnectedFlows = True
                    break
                count += __add_php_reaches_edge(dataNodeObj.value, dataNodeObj.id)
        if hasConnectedFlows:
            break

    #then, find all places where any class variables appear, and connect data flows there. If it is a usage, we connect a data flow from the class var to the usage. If it is an assign, we connect a data flow from the assign to the class var.
    classVarQuery = f"""
    MATCH (var:AST{{childnum:1}})<-[:PARENT_OF]-(n:AST{{type:'AST_PROP'}})-[:PARENT_OF]->({{childnum:0}})-[:PARENT_OF]->({{code:'this'}})
    MATCH (parent)-[:PARENT_OF]->(n)
    RETURN n,var.code,parent.type
    """
    classVarResult = graph.run(cypher=classVarQuery).data()
    for tempResult in progress_bar(classVarResult):
        varID = tempResult['n']['id']
        varChildnum = tempResult['n']['childnum']
        className = tempResult['n']['classname']
        varCode = tempResult['var.code']
        parentType = tempResult['parent.type']
        classVarID = classHierarchy.lookUpClassVarID(className, varCode)
        if classVarID:
            #if this is the case, then it is assigning values to the class var, so the data flow is from the current location to the class var.
            if parentType == 'AST_ASSIGN' and varChildnum == 0:
                count += __add_php_reaches_edge(varID, classVarID)
            #if this is the case, then it is using values of the class var, so the data flow is from the class var to the current location.
            else:
                count += __add_php_reaches_edge(classVarID, varID)

    print(f"Added {count} PHP_REACHES edges.")


@_preprocess_step(step_name="Handle class hierarchy and make CALLS edges and certain data flows")
def __handle_class_hierarchy():
    """
    This function does the following:
        1. connects CALLS edges for certain function calls through objects (it handles cases where objects are of class that implements certain interface)
        2. connects dataflows from class variables to its usage
    Prereq: This call must be run after __php_reach_edges()
    """
    global classHierarchy
    # classHierarchy = ClassHierarchy()
    # classHierarchy.fillClassHierarchy()
    # classHierarchy.fillFunctions()
    #print (classHierarchy.lookUpParamType("UninstallRequest","execute",'requestor'))
    #Note: all of the two parts below require the class hierarchy object above, and so they are included in this same function
    #Part 1: connect object's function
    #first, get method calls of objects that do not have CALLS edges
    #then, get the variable/object used for the function call, and try to determine its type
    graph = getGraph()
    objectCallQuery = f"""
    MATCH (methodName:AST{{childnum:1}})<-[:PARENT_OF]-(n:AST{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(m:AST{{childnum:0}})
    WHERE NOT (n)-[:CALLS]->()
    RETURN m,methodName.code,n.id
    """
    objectCallResult = graph.run(cypher=objectCallQuery).data()
    callEdgecount = 0

    for obj in progress_bar(objectCallResult):
        #we first determine the type of the object
        objType = determineObjectType(obj['m'])
        methodName = obj['methodName.code']
        methodCallID = obj['n.id']
        if objType:
            #we then look up the corresponding function given the object type is found
            methodIDs = classHierarchy.lookUpFunction(objType, methodName)
            for methodID in methodIDs:
                #we then build edges between method call and the method
                callEdgecount += __add_calls_edge(methodCallID, methodID)
                #print("call created for "+str(methodCallID)+" to "+str(methodID))
    print(f"Added {callEdgecount} CALLS edges.")

    return callEdgecount


@_preprocess_step(step_name="Security/storage detectors")
def __security_detectors():
    """
    Node/cryptography detectors stage

    The following operations are done on the AST here:
    -	Run ALL detectors in the submodule detectors

    This isn't just limited to cryptography and also covers storage, deletion, activation, etc.
    """
    global SECURITY_DETECTOR_MANAGER
    if not SECURITY_DETECTOR_MANAGER:
        sys.exit(1)
    AbstractDetector.SILENT_INITIALIZATION = True
    print("### Running detectors")
    SECURITY_DETECTOR_MANAGER.run()
    print("### Finished running detectors")
    SECURITY_DETECTOR_MANAGER.print_results()

    print("By data type:")
    grouped: Dict[str, List[AbstractDetector.Finding]] = {}
    for f in SECURITY_DETECTOR_MANAGER.allFindings:
        if not f.score.get_data_types():
            l = grouped.get("none", [])
            l.append(f)
            grouped["none"] = l
        else:
            for t in f.score.get_data_types():
                l = grouped.get(t, [])
                l.append(f)
                grouped[t] = l

    for k in sorted(grouped.keys()):
        print(k)
        strs = [
            f"""\t{v.parent_name}.{v.score.categories.get("code", "(unknown)")} - {v.score.get_data_types()}"""
            for v in grouped[k]
        ]
        for s in strs:
            print(s)


@_preprocess_step(step_name="Connect AST_PARAM edges")
def __connect_ASTPARAM_to_var():
    """
    Navex bug fix. Some AST_PARAM do not have reaches edges
    """
    count = 0
    graph = getGraph()
    query = """
    MATCH (n:AST)-[:PARENT_OF]->(str)
    WHERE n.type = 'AST_PARAM' AND NOT (n)-[:REACHES]->() AND str.type = 'string'
    WITH n,str
    MATCH (m)-[:PARENT_OF]->(x)
    WHERE m.funcid = n.funcid AND m.type = 'AST_VAR' AND x.code = str.code
    RETURN n.id,COLLECT(m.id) AS ms
    """
    result = graph.run(cypher=query).data()
    for i in result:
        # Choose the first element of ms to get the line closest to the parameter
        try:
            rootOfLine = getRootOfLine(i["ms"][0])
            if rootOfLine:
                rootID = rootOfLine["id"]
                count += addEdge(i['n.id'], "AST", rootID, "AST", "REACHES")

            # mergeQuery = f"""
            # MATCH (n),(m)
            # WHERE n.id = {i['n.id']} AND m.id = {rootOfLine}
            # MERGE (n)-[:REACHES]->(m)
            # """
            # graph.run(cypher=mergeQuery)
        except TypeError:    # Patch bug where root of line is None
            pass
    print(f"Added {count} REACHES edges for AST_PARAM to variables")


@_preprocess_step(step_name="Create HTML_TO_PHP_REACHES edges between form inputs and PHP request vars")
def __html_to_php_reaches():
    count = 0
    success = 0
    input_number = 0
    graph = getGraph()
    # find all forms
    query = f"""
    MATCH (form:AST_HTML{{name:'form',type:'tag'}})
    RETURN form.id
    """
    result = graph.run(cypher=query).data()

    if result:
        for r in result:
            form_node_id = r['form.id']
            #get the form action, method
            query = f"""
            MATCH (form:AST_HTML{{id:{form_node_id}}})-[:PARENT_OF]->(action:AST_HTML{{type:'attribute',name:'action'}})-[:PARENT_OF]->(action_value:AST_HTML{{type:'string'}})
            MATCH (form:AST_HTML{{id:{form_node_id}}})-[:PARENT_OF]->(method:AST_HTML{{type:'attribute',name:'method'}})-[:PARENT_OF]->(method_value:AST_HTML{{type:'string'}})
            
            RETURN action_value,method_value
            """
            form_result = graph.run(cypher=query).data()
            action_value = None
            method_value = None
            if form_result:
                if form_result[0]['action_value'] and 'code' in form_result[0]['action_value']:
                    action_value = form_result[0]['action_value']['code']
                if form_result[0]['method_value'] and 'code' in form_result[0]['method_value']:
                    method_value = form_result[0]['method_value']['code']

            #get all inputs in the form. Search their values (which we want to make traversals of), and their input names
            query = f"""
            MATCH (form:AST_HTML{{id:{form_node_id}}})-[:PARENT_OF*]->(form_input:AST_HTML{{type:'tag',name:'input'}})
            MATCH (form_input)-[:PARENT_OF]->(input_name:AST_HTML{{type:'attribute',name:'name'}})-[:PARENT_OF]->(name_value:AST_HTML{{type:'string'}})
            RETURN name_value,form_input.id
            """
            form_result2 = graph.run(cypher=query).data()
            # print(form_result2)
            if form_result2:
                for input in form_result2:
                    form_input_id = input['form_input.id']
                    input_number += 1
                    name_value = None
                    if input['name_value'] and 'code' in input['name_value']:
                        name_value = input['name_value']['code']
                    if name_value:
                        # find corresponding php request vars
                        get_or_post = "(y.code = '_POST' OR y.code = '_GET' OR y.code = '_REQUEST')"
                        if method_value:
                            if method_value.lower() == 'post':
                                get_or_post = "(y.code = '_POST')"
                            elif method_value.lower() == 'get':
                                get_or_post = "(y.code = '_GET')"
                        if action_value:
                            #TODO: implement action logic to make the flow more accurate (less false flows)
                            pass
                        query = f"""
                        MATCH (n:AST{{type:'string',code:'{name_value}'}})<-[:PARENT_OF]-(x:AST{{type:'AST_DIM'}})-[:PARENT_OF]->(m:AST{{type:'AST_VAR'}})-[:PARENT_OF]->(y:AST{{type:'string'}})
                        WHERE {get_or_post}
                        RETURN COLLECT(DISTINCT x.id)
                        """
                        php_vars: List[int] = graph.evaluate(query)
                        if not php_vars:
                            continue
                        success += 1
                        #create flows between html input values and php vars
                        for var in php_vars:
                            count += addEdge(form_input_id, "AST_HTML", var, "AST", "HTML_TO_PHP_REACHES")
    print(
        f"Added {count} HTML_TO_PHP_REACHES edges. Successfully connect {success} out of {input_number} inputs to PHP. "
    )


@_preprocess_step(step_name="Add AST_JS label to JS nodes")
def __label_js_nodes():
    query = """
    MATCH (file:Filesystem) WHERE file.name =~ ".*\\.js"
    MATCH (file)-[:PARENT_OF|FILE_OF*]->(n:AST)
    SET n:AST_JS
    REMOVE n:AST
    """
    getGraph().run(query)


@_preprocess_step(step_name="Build hierarchical data flow edges for php and js")
def __build_php_js_hierarchical_edges():
    print("Building hierarchical edges for PHP...")
    graph = getGraph()
    count = 0
    query = f"""
    MATCH (n:AST) WHERE n.type IN {list(USEFUL_NODES)} OR (n.type='AST_BINARY_OP' AND 'BINARY_CONCAT' IN n.flags)
    SET n:USEFUL_PHP
    """
    graph.run(query)

    query2 = f"""
    MATCH (n:USEFUL_PHP)
    call apoc.path.expandConfig(n,{{relationshipFilter: "<PARENT_OF", labelFilter:'/USEFUL_PHP', maxLevel:5, limit:1}}) yield path 
    return [node in nodes(path) | node.id] AS nodes
    """
    result = graph.run(query2).data()

    rels = []
    if result:
        for i in result:
            temp = i['nodes']
            if len(temp) > 1:
                start = temp[0]
                end = temp[-1]

                rels.append({
                    "start_id": start,
                    "start_label": "AST",
                    "end_id": end,
                    "end_label": "AST",
                    "type": "PHP_REACHES",
                    "var": None
                })

    addEdgeBulk(rels)
    count += len(rels)
    print(f"Added {count} PHP_REACHES edges. ")

    print("Building hierarchical edges for JS...")
    count_js = 0
    query_js = f"""
    MATCH (n:AST_JS) WHERE n.type IN {list(USEFUL_NODES)} OR (n.type='AST_BINARY_OP' AND 'BINARY_CONCAT' IN n.flags)
    SET n:USEFUL_JS
    """
    graph.run(query_js)

    query_js2 = f"""
    MATCH (n:USEFUL_JS)
    call apoc.path.expandConfig(n,{{relationshipFilter: "<PARENT_OF", labelFilter:'/USEFUL_JS', maxLevel:5, limit:1}}) yield path 
    return [node in nodes(path) | node.id] AS nodes
    """
    result_js = graph.run(query_js2).data()
    edges = []
    if result_js:
        for i in result_js:
            temp = i['nodes']
            if len(temp) > 1:
                start = temp[0]
                end = temp[-1]
                edges.append({
                    "start_id": start,
                    "start_label": "AST_JS",
                    "end_id": end,
                    "end_label": "AST_JS",
                    "type": "PHP_REACHES",
                    "var": None
                })

    addEdgeBulk(edges)
    count_js += len(edges)
    print(f"Added {count_js} JS_REACHES edges. ")


@_preprocess_step(step_name="Ensure var and varName consistency")
def __ensure_var_varname_consistency():
    """Ensure that the `var` property for `:PHP_REACHES` edges exists for new `:PHP_REACHES` edges for
    consistency with `:REACHES` edges, which only have a `var` property.
    """
    count = getGraph().evaluate("""
    MATCH ()-[r:PHP_REACHES]->()
    SET r.var = r.varName
    RETURN COUNT(r)
    """)

    print(f"Added var property for {count} :PHP_REACHES edges.")


@_preprocess_step(step_name="Create DB indices")
def __create_indices():
    print("Creating indices for commonly used features... ", end="", flush=True)
    graph = getGraph()
    tx = graph.begin()
    tx.run("""CREATE CONSTRAINT IF NOT EXISTS ON (n:AST) ASSERT n.id IS UNIQUE""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST) ON (n.type)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST) ON (n.code)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST) ON (n.funcid)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST) ON (n.classname)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST) ON (n.childnum)""")

    tx.run("""CREATE CONSTRAINT IF NOT EXISTS ON (n:AST_HTML) ASSERT n.id IS UNIQUE""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_HTML) ON (n.type)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_HTML) ON (n.code)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_HTML) ON (n.id)""")

    tx.run("""CREATE CONSTRAINT IF NOT EXISTS ON (n:AST_SQL) ASSERT n.id IS UNIQUE""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_SQL) ON (n.type)""")

    tx.run("""CREATE CONSTRAINT IF NOT EXISTS ON (n:AST_JS) ASSERT n.id IS UNIQUE""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_JS) ON (n.type)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_JS) ON (n.code)""")
    tx.run("""CREATE INDEX IF NOT EXISTS FOR (n:AST_JS) ON (n.childnum)""")
    graph.commit(tx)

    print("done.", flush=True)


def eliminateUselessNodes(nodeID: int, getChildren=False) -> List[int]:
    """Get the first tier useful nodes
    If getChildren is True, then only get the first tier useful nodes from the current node's children. Else, consider the node itself as well.
    """

    #first, if the current node is useful, return the current node
    if not getChildren:
        currentNode = getNode(nodeID)
        is_useful = bool(currentNode["type"] in USEFUL_NODES)
        is_bin_concat = bool(currentNode["type"] == "AST_BINARY_OP" and "BINARY_CONCAT" in currentNode.get("flags", []))
        if is_useful or is_bin_concat:
            return [nodeID]
    #else, examine the children nodes
    graph = getGraph()
    query = f"""
    MATCH (n{{id:{nodeID}}})-[:PARENT_OF]->(c)
    RETURN COLLECT(DISTINCT c)
    """
    results = graph.evaluate(query)
    if not results:
        return []

    output = []
    for node in results:
        d = dict(node)
        is_useful = bool(d["type"] in USEFUL_NODES)
        is_bin_concat = bool(d["type"] == "AST_BINARY_OP" and "BINARY_CONCAT" in d.get("flags", []))
        if is_useful or is_bin_concat:
            output.append(d["id"])
        else:
            output.extend(eliminateUselessNodes(d["id"], getChildren=True))

    return output


def __add_php_reaches_edge(id1: int, id2: int) -> int:
    try:
        # global _ID_pairs_with_preprocessed_edges
        # if (id1,id2) in _ID_pairs_with_preprocessed_edges:
        #     return 0
        #varName = concatTree(id1)

        # _ID_pairs_with_preprocessed_edges.add((id1,id2))
        return addEdge(id1, "AST", id2, "AST", "PHP_REACHES")
        # if result:
        #     return 1
        # else:
        #     return 0
    except Exception as e:
        print(e)
        return 0


def __add_js_reaches_edge(id1: int, id2: int) -> int:
    try:
        global _ID_pairs_with_preprocessed_edges
        if (id1, id2) in _ID_pairs_with_preprocessed_edges:
            return 0
        varName = concatTree(id1)

        _ID_pairs_with_preprocessed_edges.add((id1, id2))
        return addEdge(id1, "AST_JS", id2, "AST_JS", "JS_REACHES", var=varName)
    except Exception as e:
        print(e)
        return 0


def __add_calls_edge(id1: int, id2: int) -> int:
    try:
        # global _ID_pairs_with_preprocessed_edges
        # if (id1,id2) in _ID_pairs_with_preprocessed_edges:
        #     return 0
        # query = f"""
        # MATCH (n:AST{{id:{id1}}}), (m:AST{{id:{id2}}})
        # MERGE (n)-[:CALLS]->(m)
        # """
        # getGraph().run(query)

        # _ID_pairs_with_preprocessed_edges.add((id1,id2))
        return addEdge(id1, "AST", id2, "AST", "CALLS")
    except Exception as e:
        print(e)
        return 0


@_preprocess_step(step_name="Remove wrong/excessive hierarchical edges")
def __remove_wrong_hierarchical_edges():
    graph = getGraph()
    count = 0
    query = f"""
    MATCH (n:AST)<-[:PARENT_OF]-(m:AST)
    WHERE m.type IN ['AST_VAR','AST_CLOSURE_VAR'] OR (m.type='AST_NAME' AND NOT ((m)<-[:PARENT_OF]-({{type:'AST_CONST'}}))) OR (m.type IN ['AST_STATIC_CALL','AST_METHOD_CALL','AST_PROP','AST_DIM'] AND n.type='string' AND n.childnum=1)
    MATCH (n:AST)-[r:PHP_REACHES]->()
    DELETE r
    RETURN COUNT(r)
    """

    count = graph.evaluate(cypher=query)

    count_js = 0
    query_js = f"""
    MATCH (n:AST_JS)<-[:PARENT_OF]-(m:AST_JS)
    WHERE m.type IN ['AST_VAR','AST_CLOSURE_VAR'] OR (m.type='AST_NAME' AND NOT ((m)<-[:PARENT_OF]-({{type:'AST_CONST'}}))) OR (m.type IN ['AST_STATIC_CALL','AST_METHOD_CALL','AST_PROP','AST_DIM'] AND n.type='string' AND n.childnum=1)
    MATCH (n:AST_JS)-[r:JS_REACHES]->()
    DELETE r
    RETURN COUNT(r)
    """

    count_js = graph.evaluate(cypher=query_js)
    print(f"Deleted {count} incorrect PHP_REACHES edges. Deleted {count_js} incorrect JS_REACHES edges.")


@_preprocess_step(step_name="Remove dataflow edges from keys to data storage sinks")
def remove_edge_from_key_to_sink():
    print("Removing dataflow edges from keys to data storage sinks", end="", flush=True)

    if not SECURITY_DETECTOR_MANAGER:
        return
    graph = getGraph()
    tx = graph.begin()
    count = 0
    count2 = 1
    print()
    for finding in SECURITY_DETECTOR_MANAGER.allFindings:
        if (hasattr(finding, 'function_annotation') and ((hasattr(finding.function_annotation, 'data_param') and
                                                          (not finding.function_annotation.data_param == -1)) or
                                                         (hasattr(finding.function_annotation, 'key_param') and
                                                          (not finding.function_annotation.key_param == -1)))):
            if hasattr(finding.function_annotation, 'data_param'):
                #if we know the data param, delete all other edge
                data_param = finding.function_annotation.data_param
                # print(finding.code)
                # print(data_param)
                query = f"""
                MATCH (n:AST{{id:{finding.node['id']}}})-[:PARENT_OF]->(:AST{{type:'AST_ARG_LIST'}})-[:PARENT_OF]->(k:AST)
                WHERE NOT k.childnum = {data_param}
                MATCH (k)-[r:PHP_REACHES]->(n)
                DELETE r
                """
            else:
                key_param = finding.function_annotation.key_param
                query = f"""
                MATCH (n:AST{{id:{finding.node['id']}}})-[:PARENT_OF]->(:AST{{type:'AST_ARG_LIST'}})-[:PARENT_OF]->(k:AST)
                WHERE k.childnum = {key_param}
                MATCH (k)-[r:PHP_REACHES]->(n)
                DELETE r
                """
            tx.run(query)
            count += 1
        if (count > 0 and count % 1000 == 0) or count2 == len(SECURITY_DETECTOR_MANAGER.allFindings):
            print(f"Deleted PHP_REACHES edges from key to sink for {count} sinks")
            graph.commit(tx)
            tx = graph.begin()

        count2 += 1
    print(f"Deleted PHP_REACHES edges from keys to storage sinks.")


@_preprocess_step(step_name="Overtaint Function Calls")
def __overtaintFunctionCalls():
    #modified: if the function call has CALLS edge, we remove the overtainted edges
    graph = getGraph()
    count = 0
    noCallEdgeQuery = f"""
    MATCH (n:AST)
    WHERE n.type in ['AST_METHOD_CALL','AST_STATIC_CALL','AST_NEW','AST_CALL'] AND ((n)-[:CALLS]->())
    MATCH (n)<-[r:PHP_REACHES]-(m)
    WHERE (n)-[:PARENT_OF*]->(m)
    DELETE r
    RETURN COUNT(r)
    """
    count = graph.evaluate(cypher=noCallEdgeQuery)
    print(f"Deleted {count} PHP_REACHES edges that overtaint function call data flows.")


def help_ast_connect_hierarchy(currentNodeID: int) -> int:
    """Recursively connects PHP_REACHES edges in the current Tree (with currentNodeID being the root)
    Returns the number of edges created
    """
    global _IDs_with_preprocessed_edges
    #if the edges under currentNodeID have been built, we do not repeat the propcess.
    if currentNodeID in _IDs_with_preprocessed_edges:
        return 0

    count = 0
    currentNodeType = getNodeType(currentNodeID)

    #connect data flow paths by different types
    if currentNodeType in ["AST_VAR", "AST_CONST", "string", "integer", "AST_NAME", "AST_CLASS_CONST"]:
        #if this is a node type that has no data flow from its children, then we don't need to create any more edges
        return 0

    skipCurrent = False
    #if the current node is a function call, then we skip making edges from its children to itself, because the intended data flow path should be from a function return.
    if currentNodeType in ['AST_METHOD_CALL', 'AST_STATIC_CALL', 'AST_NEW', 'AST_CALL']:
        skipCurrent = True

    firstTierIDs: List[int] = eliminateUselessNodes(currentNodeID, True)
    #if there is no useful children node, return 0
    if not firstTierIDs:
        return 0
    #if we don't want to skip the current node, we connect data flow from all the useful children to the current node
    if not skipCurrent:
        for nodeID in firstTierIDs:
            count += __add_php_reaches_edge(nodeID, currentNodeID)
    _IDs_with_preprocessed_edges.add(currentNodeID)
    #we recursively build dataflows for the usefu children nodes
    for nodeID in firstTierIDs:
        count += help_ast_connect_hierarchy(nodeID)
    #we update the list of ids we have built the edges for

    return count


@_preprocess_step(step_name="Create PHP_REACHES edges between function returns and callers")
def __ast_call_return_edges():
    if __OPTIONS["quick"]:
        print("Skipping __ast_call_return_edges.")
        return
    count = 0
    graph = getGraph()
    returnQuery = f"""
    MATCH (call:AST)-[:CALLS]->(function:AST)
    WHERE function.type in ['AST_FUNC_DECL','AST_METHOD']
    WITH function,call
    MATCH (ret:AST{{type:"AST_RETURN"}})
    WHERE ret.funcid = function.id AND NOT (ret)-[:PHP_REACHES]->(call)
    RETURN call.id, COLLECT(DISTINCT ret.id)
    """
    returnResult = graph.run(cypher=returnQuery).data()

    if not returnResult:
        return

    with ThreadPoolExecutor() as executor:
        for result in progress_bar(returnResult):

            currentNodeID = result['call.id']
            returnNodes = list(result['COLLECT(DISTINCT ret.id)'])
            futures = [executor.submit(__add_php_reaches_edge, returnNode, currentNodeID) for returnNode in returnNodes]
            for f in futures:
                count += f.result()

    print(f"Added {count} PHP_REACHES edges.")


@_preprocess_step(step_name="Create hierarchy PHP_REACHES edges for multiple types of nodes")
def __ast_hierarchy_edges():
    """
    This function creates PHP_REACHES edges within the tree hierarchy of AST CALL, AST STATIC CALL, AST METHOD CALL, and AST_RETURN
    """
    if __OPTIONS["quick"]:
        print("Skipping __ast_hierarchy_edges.")
        return
    count = 0
    #part 1: we connect edges in all lines of code that are function returns
    # Link RETURN to the assigned var
    graph = getGraph()
    assignQuery = """
    MATCH (n:AST)
    WHERE n.type in ["AST_RETURN"]
    RETURN n.id
    """
    result = graph.run(cypher=assignQuery).data()

    for callNode in progress_bar(result):

        currentTier = callNode["n.id"]
        help_ast_connect_hierarchy(currentTier)
        # currentTier = eliminateUselessNodes(currentTier)
        # for node_id in currentTier:
        #     count += help_ast_connect_hierarchy(node_id)

    #part 2: we connect edges in all lines of code where there is a function call
    #get lines of code where there is a function call
    assignQuery2 = """
    MATCH (n:AST)
    WHERE n.type in ["AST_CALL", "AST_STATIC_CALL","AST_METHOD_CALL", "AST_NEW"]
    RETURN n.id
    """
    result2 = graph.run(cypher=assignQuery2).data()

    for callNode in progress_bar(result2):

        currentTier = callNode["n.id"]
        temp = getRootOfLine(currentTier)
        if temp:
            currentTier = temp['id']
        currentTier = eliminateUselessNodes(currentTier)
        for node_id in currentTier:
            count += help_ast_connect_hierarchy(node_id)
    print(f"Added {count} PHP_REACHES edges.")


def ast_assign_subtask(assigner, assignee):
    count = 0
    currentTier = eliminateUselessNodes(assigner)
    for node_id in currentTier:
        count += __add_php_reaches_edge(node_id, assignee)
        #no longer need to build hierarchical edges here
        #count += help_ast_connect_hierarchy(node_id)
    return count


@_preprocess_step(step_name="Create AST assign hierarchy PHP_REACHES edges")
def __ast_assign_function_edges():
    """
    Benchmarks for BePro listings:
        5/7/21:
            adding AST assign hierarchy PHP_REACHES edges completed. Added 29986 PHP_REACHES edgesFinished in 4122.075 seconds.
            Added var property for 37014 :PHP_REACHES edges.
        5/19/21 (queries with node labels):
            Adding AST assign hierarchy PHP_REACHES edges completed. Added 57551 PHP_REACHES edgesFinished in 2603.282 seconds.
            Added var property for 75199 :PHP_REACHES edges.
    """

    if __OPTIONS["quick"]:
        print("Skipping __ast_assign_function_edges.")
        return

    count = 0
    # Link RETURN to the assigned var
    graph = getGraph()
    assignQuery = """
    MATCH (n:AST)-[:PARENT_OF]->(m:AST{childnum:0})
    WHERE n.type in ["AST_ASSIGN", "AST_ASSIGN_OP"]
    OPTIONAL MATCH (n)-[:PARENT_OF]->(assigner:AST{childnum:1})
    RETURN n.id, assigner.id, m.id
    """
    result = graph.run(cypher=assignQuery).data()

    nodes_without_assigners: Set[int] = set()
    futures = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for assignNode in progress_bar(result):
            assignID = assignNode["n.id"]
            currentTier = assignNode["assigner.id"]
            assigneeID = assignNode["m.id"]

            if not currentTier:
                # print("AST_ASSIGN does not have assigner for node :" + str(assignID))
                nodes_without_assigners.add(assignID)
                continue
            futures.append(executor.submit(ast_assign_subtask, currentTier, assigneeID))
        for f in futures:
            count += f.result()

    if nodes_without_assigners:
        print(f"The following nodes are without assigners: {sorted(nodes_without_assigners)}")
    print(f"Added {count} PHP_REACHES edges.")


def __function_call_edges__subtask(nodeID, resultCalls, resultArgs) -> int:
    # For every function that this function calls. There can be several because we canont be sure which function is called sometimes (and we need to overtaint)
    graph = getGraph()
    count = 0
    if resultCalls:
        for call in resultCalls:
            allParam = ASTMethodGetParameterList(call)
            if not allParam:
                print(
                    f"Error! AST Method should have parameters but the parameters cannot be matched. FuncID: {resultCalls[0]}"
                )
                return 0
            for param in resultArgs:
                try:
                    childnum = param["childnum"]
                    #varChild = eliminateUselessNodes(param["id"])
                    varChild = eliminateUselessNodes(param['id'])
                    for var in varChild:
                        if childnum < len(allParam[1]):
                            count += __add_php_reaches_edge(var, allParam[1][childnum])
                except IndexError and KeyError as e:
                    print(e)
                    continue

    return count


@_preprocess_step(step_name="Create function call edges")
def __function_call_edges():
    """Create edges with name PHP_REACHES and attribute of the variable name between a parameter within a function call and the parameter in the function definition

    BePro Listings benchmark: Adding function call edges... adding function call edges completed. Added 19448 PHP_REACHES edges to function parameters. Finished in 4402.698 seconds.

    """
    if __OPTIONS["quick"]:
        print("Skipping __function_call_edges.")
        return

    graph = getGraph()

    count = 0
    #overTaintCount = 0

    query = """
    MATCH (n:AST) WHERE n.type in ['AST_METHOD_CALL','AST_STATIC_CALL','AST_CALL','AST_NEW']
    MATCH (n)-[:PARENT_OF]->(:AST{type: "AST_ARG_LIST"})-[:PARENT_OF]->(args:AST)
    
    MATCH (n)-[:CALLS]->(called:AST)
    RETURN n.id as id, COLLECT(DISTINCT called.id) as called, COLLECT(DISTINCT args) as args
    """
    results = graph.run(query).data()
    if not results:
        return

    for result in progress_bar(results):

        nodeID = result["id"]
        resultCalls = result["called"]
        resultArgs = [dict(n) for n in result["args"]]

        #get the args.
        sampleArg = eliminateUselessNodes(resultArgs[0]['id'])
        #If there's no arg for the current call, then there's no need to create edges for this call.
        if not sampleArg:
            #print(resultArgs[0]['id'])
            continue
        #first check if there are outgoing edges for the arguments. If so, there's no need to recreate the data flow edges
        edgeQuery = f"""
        MATCH r = (n:AST{{id:{sampleArg[0]}}})-[:PHP_REACHES]->(m:AST{{type:'AST_PARAM'}})
        RETURN r
        """
        edgeResult = graph.evaluate(cypher=edgeQuery)
        if not edgeResult:
            count += __function_call_edges__subtask(nodeID, resultCalls, resultArgs)

    print(f"Added {count} PHP_REACHES edges to function parameters.")
    return count


@_preprocess_step(step_name="Create PHP_REACHES edges")
def __php_reach_edges():
    # Benchmark Adding PHP reaches edges completed. Added 60536 :PHP_REACHES for original REACHES edges.
    # Benchmark Adding PHP reaches edges completed. Added 5836 :PHP_REACHES for original REACHES edges.
    # Should be around 13000 for BePro
    count = 0
    graph = getGraph()
    query = """
    MATCH
        (nVarName:AST{type:"string"})<-[:PARENT_OF]-(nVarChild:AST)<-[:PARENT_OF*0..10]-(reachSrc)-[r:REACHES]->(reachDst)-[:PARENT_OF*0..10]->(mVarChild:AST)-[:PARENT_OF]->(mVarName:AST{type:"string"})
    WHERE
        reachSrc <> reachDst
        AND nVarName.code = mVarName.code
        AND mVarName.code = r.var
        AND nVarChild.type in ["AST_VAR", "AST_PARAM"]
        AND mVarChild.type in ["AST_VAR", "AST_PARAM"]
    RETURN nVarChild.id AS n, mVarChild.id AS m, nVarName AS var
    """

    result = graph.run(query).data()
    if not result:
        return
    for i in result:
        nid = i['n']
        mid = i['m']
        var = i['var']
        count += addEdge(nid, "AST", mid, "AST", "PHP_REACHES", var)
    print(f"Added {count} :PHP_REACHES for original :REACHES edges.")


@_preprocess_step(step_name="Create source to sink edges")
def __storage_to_retrieval():

    print("Adding storage reaches edges... ", end="", flush=True)

    if not SECURITY_DETECTOR_MANAGER:
        return

    # First find all nodes that save some information as found in the Encryption Detectors stage.
    storage_nodes: Set[int] = set()
    retrieve_nodes: Set[int] = set()
    for finding in SECURITY_DETECTOR_MANAGER.allFindings:
        if finding.score.is_storage() and not finding.score.is_database():
            storage_nodes.add(finding.node["id"])
        elif finding.score.is_retrieval() and not finding.score.is_database():
            retrieve_nodes.add(finding.node["id"])
    print("Finished collecting storage and retrieval nodes from detectors")
    # Now look for all SQL query operations.
    SQLParentNodes = getSQLParentNodes()
    for sql_node in SQLParentNodes:
        sql_info = getStatementSQLInfo(sql_node)
        if not sql_info:
            continue
        elif "insert" == sql_info.operation or "update" == sql_info.operation:
            storage_nodes.add(sql_node)
        elif "select" == sql_info.operation:
            retrieve_nodes.add(sql_node)
    print("Finished collecting sql insert, update, and select nodes")
    storage_node_info: Dict[int, List[Union[AbstractDetector.Finding, SQLInfo]]] = {
        i: list(SECURITY_DETECTOR_MANAGER.lookup_node_id(i))
        for i in storage_nodes
    }
    retrieve_node_info: Dict[int, List[Union[AbstractDetector.Finding, SQLInfo]]] = {
        i: list(SECURITY_DETECTOR_MANAGER.lookup_node_id(i))
        for i in retrieve_nodes
    }
    for node_id, findings in storage_node_info.items():
        sql_info = getStatementSQLInfo(node_id)
        if not findings and sql_info:
            storage_node_info[node_id].append(sql_info)
    for node_id, findings in retrieve_node_info.items():
        sql_info = getStatementSQLInfo(node_id)
        if not findings and sql_info:
            retrieve_node_info[node_id].append(sql_info)
    print("Finished collecting SQL statement info")
    num_added: int = 0

    edges: Set[Tuple[int, int]] = set()
    print("Start inserting STORE_REACHES")
    for retrieve_id, retrieve_results in retrieve_node_info.items():
        for storage_id, storage_results in storage_node_info.items():
            # Not as bad as it looks; normally only 1 to 4 loops from here on.
            for retrieve_result in retrieve_results:
                for storage_result in storage_results:
                    # Case 1: retrieving node is SQL -> storage node is also SQL
                    if (isinstance(retrieve_result, SQLInfo) and isinstance(storage_result, SQLInfo)
                            and "count" not in retrieve_result.code.lower()):
                        is_matching = SQLInfo.table_equals(retrieve_result, storage_result) and SQLInfo.field_equals(
                            retrieve_result, storage_result)
                        if is_matching and not (storage_id, retrieve_id) in edges:
                            num_added += 1
                            edges.add((storage_id, retrieve_id))
                            addEdge(
                                storage_id,
                                "AST",
                                retrieve_id,
                                "AST",
                                "STORE_REACHES",
                            )
                    # Case 2: both WordPress functions
                    elif isinstance(retrieve_result, AbstractDetector.Finding) and isinstance(
                            storage_result, AbstractDetector.Finding):
                        modified_types = storage_result.score.get_data_types()
                        if (retrieve_result.score.matches_data_type(modified_types)
                                and not (storage_id, retrieve_id) in edges):
                            num_added += 1
                            edges.add((storage_id, retrieve_id))
                            addEdge(
                                storage_id,
                                "AST",
                                retrieve_id,
                                "AST",
                                "STORE_REACHES",
                            # {"data_type": "wordpress"},
                            )

    print(f"Done adding storage edges. Added {num_added} edges in all.")


@_preprocess_step(step_name="Create do_action and apply_filter edges")
def __do_action_to_function():
    count = 0
    graph = getGraph()
    query = """
    MATCH (func_call:AST{type:"AST_CALL"})-[:PARENT_OF]->(func_name:AST{type:"AST_NAME"})-[:PARENT_OF]->(func_name_str:AST{type:"string"})
    WHERE func_name_str.code =~ "(do_action|apply_filters|add_action|add_filter)"
    MATCH (func_call)-[:PARENT_OF]->(:AST{type:"AST_ARG_LIST"})-[:PARENT_OF]->(arg:AST)
    WITH func_call, func_name_str, arg ORDER BY func_call.id, arg.childnum
    RETURN func_call.id, func_name_str.code, COLLECT(arg.id)
    """
    results = graph.run(query)

    do_calls: Dict[int, Dict[str, Any]] = dict()
    add_calls: Dict[int, Dict[str, Any]] = dict()
    for r in results:
        if not r:
            continue
        func_call_id, func_call_name, args = r
        if args:
            if func_call_name == "do_action" or func_call_name == "apply_filters":
                do_calls[func_call_id] = {
                    "call_id": func_call_id,
                    "call_name": func_call_name,
                    "arg_ids": args,
                    "hook_name": evaluateExpression(args[0])[0],
                }
            else:
                add_calls[func_call_id] = {
                    "call_id": func_call_id,
                    "call_name": func_call_name,
                    "arg_ids": args,
                    "hook_name": evaluateExpression(args[0])[0],
                }

    print(
        f"Found {len(do_calls)} do_action/apply_filters calls and {len(add_calls)} add_action/add_filter calls. Now connecting do-add pairs."
    )

    do_pairs: List[Tuple[str, int]] = [(v["hook_name"], v["call_id"]) for v in do_calls.values()]
    add_pairs: List[Tuple[str, int]] = [(v["hook_name"], v["call_id"]) for v in add_calls.values()]
    pairs: Dict[str, List[Set[int]]] = dict()
    for do_name, do_id in do_pairs:
        for add_name, add_id in add_pairs:
            # Require that pair is action-action or filter-filter.
            if not (("action" in do_calls[do_id]["call_name"] and "action" in add_calls[add_id]["call_name"]) or
                    ("filter" in do_calls[do_id]["call_name"] and "filter" in add_calls[add_id]["call_name"])):
                continue

            if do_name == add_name:
                if do_name not in pairs.keys():
                    pairs[do_name] = [set([do_id]), set([add_id])]
                else:
                    pairs[do_name][0].add(do_id)
                    pairs[do_name][1].add(add_id)

    for hook_name, pair in progress_bar(pairs.items()):
        do_ids, add_ids = pair
        # Have to determine what the add IDs call.
        for add_id in add_ids:
            if len(add_calls[add_id]["arg_ids"]) > 1:
                func_param_node = getNode(add_calls[add_id]["arg_ids"][1])

                # Pair arguments with their var name.
                all_do_args = []
                for i in do_ids:
                    for arg_id in do_calls[i]["arg_ids"][1:]:
                        s = concatTree(arg_id)
                        all_do_args.append((arg_id, s))

                # Do nothing if there are no arguments to pair.
                if not all_do_args:
                    continue

                if func_param_node["type"] == "string":
                    # Looking for a func decl.
                    query = f"""
                    MATCH (action_dest:AST{{type:"AST_FUNC_DECL", name:"{func_param_node["code"]}"}})
                        -[:PARENT_OF]->(action_dest_params:AST{{type:"AST_PARAM_LIST"}})
                        -[:PARENT_OF]->(action_dest_param:AST)
                    UNWIND [{",".join([str(list(i)) for i in all_do_args])}] AS do_arg_pair
                    MATCH (do_arg:AST{{id: do_arg_pair[0], childnum: action_dest_param.childnum + 1}})
                    RETURN do_arg.id AS nid, action_dest_param.id AS mid, do_arg_pair[1] AS var
                    """

                    # MERGE p=(do_arg)-[r:PHP_REACHES{{var: do_arg_pair[1], preprocessed: true}}]->(action_dest_param)
                    # RETURN COUNT(r)
                    result = graph.run(cypher=query).data()
                    if result:
                        for rst in result:
                            nid = rst['nid']
                            mid = rst['mid']
                            var = rst['var']
                            count += addEdge(nid, "AST", mid, "AST", "PHP_REACHES", var)
                elif func_param_node["type"] == "AST_ARRAY":
                    # Looking for a method declaration.
                    query = f"""
                    MATCH (:AST{{id: {func_param_node["id"]}}})-[:PARENT_OF]->(:AST{{childnum: 1}})-[:PARENT_OF]->(method_name:AST{{childnum: 0}})
                    MATCH (action_dest:AST{{name:method_name.code}})
                        -[:PARENT_OF]->(action_dest_params:AST{{type:"AST_PARAM_LIST"}})
                        -[:PARENT_OF]->(action_dest_param:AST)
                    WHERE action_dest.type =~ "AST_METHOD"
                    UNWIND [{",".join([str(list(i)) for i in all_do_args])}] AS do_arg_pair
                    MATCH (do_arg:AST{{id: do_arg_pair[0], childnum: action_dest_param.childnum + 1}})
                    RETURN do_arg.id AS nid, action_dest_param.id AS mid, do_arg_pair[1] AS var
                    """
                    result = graph.run(cypher=query).data()
                    if result:
                        for rst in result:
                            nid = rst['nid']
                            mid = rst['mid']
                            var = rst['var']
                            count += addEdge(nid, "AST", mid, "AST", "PHP_REACHES", var)

    print(f"Added {count} :PHP_REACHES edges.")


@_preprocess_step(step_name="Create parent-to-self edges")
def __parent_self_edges():
    addParentSelfEdges()


@_preprocess_step(step_name="Create SQL AST")
def __add_sql_ast():
    if __OPTIONS.get("skip_sql"):
        print("Skipping __add_sql_ast")
        return
    count = 0
    graph = getGraph()

    # Delete existing SQL?
    query = """MATCH (n:AST_SQL) DETACH DELETE n"""
    graph.run(query)

    # Parse SQL
    query = f"""
    MATCH (call:AST)-[:PARENT_OF*1..2]->(stmt_str:AST)
    WHERE stmt_str.code =~ '{__WPDB_QUERIES_REGEX}' AND call.type =~ "AST.*CALL"
    RETURN COLLECT(call.id)
    """
    results = graph.evaluate(query)
    total = len(results if results else [])
    success = 0

    if results:
        print(f"{total} SQL operations to process.")

        error_calls = []
        for call_id in progress_bar(results):
            result = None
            try:
                result = SQLToAST1(call_id)
            except Exception:
                pass
            finally:
                if not result:
                    error_calls.append(call_id)
                else:
                    success += 1
                    count += result
                # getStatementSQLInfo(call_id)

        if error_calls:
            print(f"The following function calls could not successfully be analyzed for SQL content: {error_calls}")

        print(f"Added {count} SQL nodes. {success} out of {total} calls were analyzed successfully.")
    else:
        print("No SQL nodes to process.")


def html_php_subtask(file_id, toplevel_id):
    added_nodes = 0
    success = 0
    graph = getGraph()
    entry_id, relationships, has_echo = traverse_cfg(toplevel_id)
    if not relationships or not has_echo:
        return
    # Parse the HTML/PHP into nodes/tokens
    file_name = getNode(file_id)["name"]

    # Make sure new HTMLNodes are created with the correct IDs
    HTMLNode.set_file_id(file_id)
    HTMLNode.set_next_id(getMaxNodeID() + 1)
    # Make a new HTML parser for each file.
    p = PhpHtmlParser(file_name)
    #print("4")
    unresolved_sources = set()

    # Need to organize the relationships into a queue-like data structure.
    relationships = list(relationships)
    id_stack: List[List[int]] = [[int(entry_id)]]
    travelled_nodes: Set[int] = set()
    echo_strings = []
    while id_stack:
        # 1. Search for child echo statements.
        current_ids = [i for i in id_stack.pop() if i not in travelled_nodes]

        # Find nodes pointed to by the returned edges.
        candidates = [r for r in relationships if r[0] in current_ids]
        # Sort such that CALLS edges are LAST such that they are placed on the top of the stack.
        candidates_dict = {t: [] for _, _, t in candidates}
        for _, e, t in candidates:
            candidates_dict[t].append(e)

        for _, v in sorted(candidates_dict.items(), key=lambda x: 1 if x[0] == "CALLS" else 0):
            id_stack.append(v)

        # 2. Now start to process the current node, finding the text returned by it.
        travelled_nodes.update(current_ids)
        for current_id in current_ids:
            query = f"""
            OPTIONAL MATCH (echo:AST{{type:"AST_ECHO", id:{current_id}}})-[:PARENT_OF]->(echoarg:AST)
            OPTIONAL MATCH (e_arg:AST{{childnum:0}})<-[:PARENT_OF]-(:AST{{childnum:1}})<-[:PARENT_OF]-(e_call:AST{{type:"AST_CALL", id:{current_id}}})-[:PARENT_OF]->(:AST{{childnum:0}})-[:PARENT_OF]->(name_str:AST)
            WHERE name_str.code = "_e"
            RETURN [COLLECT(echoarg.id), COLLECT(e_arg.id)]
            """
            results = graph.evaluate(query)
            if not results:
                continue
            all_ids = []
            for r in results:
                all_ids.extend(r)
            if not all_ids:
                continue
            for echo_arg_id in all_ids:

                echo_parts, sources = evaluateExpressionUnjoined(echo_arg_id)
                unresolved_sources.update(sources)
                source_evals = {s: evaluateExpression(s)[0] for s in unresolved_sources}

                for echo_return in echo_parts:
                    echo_return = str(echo_return)
                    echo_strings.append(echo_return)
                    # Feed some more partial HTML to the parser.
                    p.feed(echo_return)

                    # String subset? Requires new nodes.
                    source_id = None
                    if p.new_nodes:
                        for k, v in source_evals.items():
                            if str(v).strip() in echo_return.strip():
                                source_id = k
                                source_evals.pop(k)
                                unresolved_sources.remove(k)
                                break
                    for n in p.new_nodes:
                        added_nodes += 1

                        insertChildNode(classname=n.classname,
                                        code=n.code,
                                        desired_childnum=n.childnum,
                                        desired_id=n.id,
                                        doccomment=n.doccomment,
                                        edge_label="PARENT_OF" if not n.type == "AST_HTML_ROOT" else "FILE_OF",
                                        endlineno=n.endlineno,
                                        flags=n.flags,
                                        funcid=n.funcid,
                                        label=n.labels,
                                        lineno=n.lineno,
                                        name=n.name,
                                        namespace=n.namespace,
                                        parent_id=n.parentID,
                                        type=n.type,
                                        start_label="Filesystem" if n.type == 'AST_HTML_ROOT' else "AST_HTML"
                        # wait=True,  # Save some back and forth queries by inserting at the end.
                                        )
                        if echo_return in n.code:
                            addEdge(
                                echo_arg_id,
                                "AST",
                                n.id,
                                "AST_HTML",
                                "HTML_FLOWS_TO",
                            # wait=True,  # Save some back and forth queries by inserting at the end.
                            )

                    for n in p.new_nodes:
                        # Or string in node code? Still requires new nodes.
                        specific_source_id = None
                        for k, v in source_evals.items():
                            for n in p.new_nodes:
                                if str(v).strip() in n.code.strip():
                                    specific_source_id = k
                                    source_evals.pop(k)
                                    unresolved_sources.remove(k)
                                    break
                            if specific_source_id:
                                break
                        if specific_source_id:
                            varname = concatTree(specific_source_id)
                            var = None
                            if varname:
                                var = varname
                            addEdge(
                                specific_source_id,
                                "AST",
                                n.id,
                                "AST_HTML",
                                "PHP_TO_HTML_REACHES",
                                var=var,
                            # wait=True,  # Save some back and forth queries by inserting at the end.
                            )
                        elif source_id:
                            varname = concatTree(source_id)
                            var = None
                            if varname:
                                var = varname
                            addEdge(
                                source_id,
                                "AST",
                                n.id,
                                "AST_HTML",
                                "PHP_TO_HTML_REACHES",
                                var=var,
                            # wait=True,  # Save some back and forth queries by inserting at the end.
                            )
    # Close the parser.
    p.close()

    success += 1 if echo_strings else 0
    return added_nodes, success


@_preprocess_step(step_name="Create HTML AST")
def __html_in_php():
    if __OPTIONS.get("skip_html"):
        print("Skipping __html_in_php")
        return

    added_nodes = 0

    graph = getGraph()
    query = """
    MATCH (n:Filesystem)-[:FILE_OF]->(tl:AST{type:"AST_TOPLEVEL"})
    WHERE n.type="File" AND (n.name =~ ".*(php|html)")
    RETURN COLLECT([n.id, tl.id])
    """
    result = graph.evaluate(query)
    if not result:
        result = []
    toplevels = sorted(result)
    total = len(toplevels if toplevels else [])
    success = 0
    #print("1")
    print(f"{len(toplevels)} files to scan.")
    futures = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for file_id, toplevel_id in progress_bar(toplevels):
            #print("2")
            futures.append(executor.submit(html_php_subtask, file_id, toplevel_id))
        for f in futures:
            if f.result():
                added_nodes_temp, succcess_temp = f.result()
                added_nodes += added_nodes_temp
                success += succcess_temp
    print(f"{added_nodes} new HTML nodes inserted into the AST. {success} out of {total} nodes contained HTML output.")


"""fix the bugs in navex: add all the edges for parent::call() and self::call()
"""


def addParentSelfEdges():

    def __edgesMethodCall(callNodeID, callName, className) -> int:
        graph = getGraph()
        num_added = 0
        try:
            query = f"""
			MATCH (n:AST)-[:PARENT_OF]->(x:AST)-[:PARENT_OF]->(m:AST)
			WHERE n.type = 'AST_CLASS' AND n.name = '{className}' AND x.type = 'AST_NAME' AND m.type = 'string'
			RETURN m.code
			"""
            result = graph.run(cypher=query).data()
            if not result:
                return num_added
            resultParentClass = result[0]["m.code"]

            query = f"""
			MATCH (n:AST)
			WHERE n.classname = '{resultParentClass}' AND n.type = 'AST_METHOD' AND n.name = '{callName}'
			RETURN n.id
			"""
            result = graph.run(cypher=query).data()
            if not result:
                return num_added
            resultTarget = result[0]["n.id"]

            # queryMergeEdge = f"""
            # MATCH (n),(m) WHERE n.id = {callNodeID} AND m.id = {resultTarget}
            # MERGE (n)-[:CALLS]->(m)
            # """
            # graph.run(cypher=queryMergeEdge)
            num_added += addEdge(callNodeID, "AST", resultTarget, "AST", "CALLS")
        except IndexError as e:
            traceback.print_exc()
            pass
        except TypeError as e:
            traceback.print_exc()
            pass
        return num_added

    def __edgesSelf(callNodeID, callName, className) -> int:
        graph = getGraph()
        num_added = 0
        try:
            query = f"""
			MATCH (n:AST)
			WHERE n.classname = '{className}' AND n.type = 'AST_METHOD' AND n.name = '{callName}'
			RETURN n.id
			"""
            result = graph.run(cypher=query).data()
            if not result:
                return num_added
            resultTarget = result[0]["n.id"]

            # queryMergeEdge = (
            #     f"""
            # MATCH (n),(m) WHERE n.id = {callNodeID} AND m.id = """
            #     + str(resultTarget)
            #     + """
            # MERGE (n)-[:CALLS]->(m)
            # """
            # )
            # graph.run(cypher=queryMergeEdge)
            num_added += addEdge(callNodeID, "AST", resultTarget, "AST", "CALLS")
        except IndexError as e:
            traceback.print_exc()
        except TypeError as e:
            traceback.print_exc()
        return num_added

    def __edgesClassCall(callNodeID, callName, className) -> int:
        graph = getGraph()
        num_added = 0
        try:
            escaped_classname = className.replace("\\", "\\\\")
            query = f"""
			MATCH (n:AST)
			WHERE n.classname = '{escaped_classname}' AND n.type = 'AST_METHOD' AND n.name = '{callName}'
			RETURN n.id
			"""
            result = graph.run(cypher=query).data()
            if not result:
                return num_added
            targetID = result[0]["n.id"]

            # queryMergeEdge = f"""
            # MATCH (n),(m) WHERE n.id = {callNodeID} AND m.id = {targetID}
            # MERGE (n)-[:CALLS]->(m)
            # """
            # graph.run(cypher=queryMergeEdge)

            num_added += addEdge(callNodeID, "AST", targetID, "AST", "CALLS")
        except IndexError as e:
            traceback.print_exc()
        except TypeError as e:
            traceback.print_exc()
        return num_added

    def __edgesClassVar(varNodeID, varName, className, is_parent_self) -> int:
        graph = getGraph()
        num_added = 0
        try:
            escaped_classname = ""
            if is_parent_self == 'self':
                escaped_classname = className
            elif is_parent_self == 'parent':
                query = f"""
                MATCH (n:AST)-[:PARENT_OF]->(x:AST)-[:PARENT_OF]->(m:AST)
                WHERE n.type = 'AST_CLASS' AND n.name = '{className}' AND x.type = 'AST_NAME' AND m.type = 'string'
                RETURN m.code
                """
                result = graph.run(cypher=query).data()
                if not result:
                    return num_added
                escaped_classname = result[0]["m.code"]
            else:
                #if it is not self or parent, it should be the classname for the class constant
                escaped_classname = is_parent_self
            escaped_classname = escaped_classname.replace("\\", "\\\\")
            query = f"""
			MATCH (n:AST)-[:PARENT_OF]->(:AST{{type:'AST_CONST_ELEM'}})-[:PARENT_OF]->(m:AST{{childnum:0,type:'string'}})
			WHERE n.classname = '{escaped_classname}' AND n.type = 'AST_CLASS_CONST_DECL' AND m.code = '{varName}'
			RETURN n.id
			"""
            result = graph.run(cypher=query).data()
            if not result:
                return num_added
            targetID = result[0]["n.id"]

            # queryMergeEdge = f"""
            # MATCH (n),(m) WHERE n.id = {varNodeID} AND m.id = {targetID}
            # MERGE (n)-[:PHP_REACHES{{var:'{concatTree(varNodeID)}'}}]->(m)
            # """
            # graph.run(cypher=queryMergeEdge)

            num_added += addEdge(varNodeID, "AST", targetID, "AST", "PHP_REACHES", var=concatTree(varNodeID))
        except IndexError as e:
            traceback.print_exc()
        except TypeError as e:
            traceback.print_exc()
        return num_added

    graph = getGraph()
    num_added = 0
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_list = []
        param_list = []
        # parent: can be parent::methodCall() or parent::$var
        query = """
		MATCH (y:AST)<-[:PARENT_OF]-(n:AST)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(x:AST)
		WHERE (n.type = 'AST_METHOD_CALL' OR n.type = 'AST_STATIC_CALL') AND m.type = 'AST_NAME' AND x.type = 'string' AND x.code = 'parent' AND y.type = 'string'
		RETURN n.id AS callNodeID, y.code AS callName, n.classname AS className
		"""
        result = graph.run(cypher=query).data()
        for r in result:
            callNodeID = r["callNodeID"]
            callName = r["callName"]
            className = r["className"]
            future_list.append(executor.submit(__edgesMethodCall, callNodeID, callName, className))
            param_list.append((callNodeID, callName, className))

        # self: can be self::xx
        query1 = """
		MATCH (y:AST)<-[:PARENT_OF]-(n:AST)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(x:AST)
		WHERE (n.type = 'AST_METHOD_CALL' OR n.type = 'AST_STATIC_CALL') AND m.type = 'AST_NAME' AND x.type = 'string' AND x.code = 'self' AND y.type = 'string'
		RETURN n.id AS callNodeID, y.code AS callName, n.classname AS className
		"""
        result = graph.run(cypher=query1).data()
        for r in result:
            callNodeID = r["callNodeID"]
            callName = r["callName"]
            className = r["className"]
            future_list.append(executor.submit(__edgesSelf, callNodeID, callName, className))
            param_list.append((callNodeID, callName, className))

        # create PHP_REACHES edges for parent::var and self::var
        query1 = f"""
		MATCH (varName:AST{{type:'string',childnum:1}})<-[:PARENT_OF]-(classConst:AST{{type:'AST_CLASS_CONST'}})-[:PARENT_OF]->({{childnum:0,type:'AST_NAME'}})-[:PARENT_OF]->(str{{type:'string'}})
		RETURN classConst.id AS varID, varName.code AS varname, classConst.classname AS className, str.code AS parentSelf
		"""
        result = graph.run(cypher=query1).data()
        for r in result:
            varName = r["varname"]
            varID = r["varID"]
            className = r["className"]
            isparentSelf = r['parentSelf']
            future_list.append(executor.submit(__edgesClassVar, varID, varName, className, isparentSelf))
            param_list.append((varID, varName, className))

        # other cases like class::call
        query1 = """
		MATCH (y:AST)<-[:PARENT_OF]-(n:AST)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(x:AST)
		WHERE (n.type = 'AST_METHOD_CALL' OR n.type = 'AST_STATIC_CALL') AND m.type = 'AST_NAME' AND x.type = 'string' AND NOT (x.code = 'self' OR x.code = 'parent') AND y.type = 'string'
		RETURN n.id AS callNodeID, y.code AS callName, x.code AS className
		"""
        result = graph.run(cypher=query1).data()
        for r in result:
            callNodeID = r["callNodeID"]
            callName = r["callName"]
            className = r["className"]
            future_list.append(executor.submit(__edgesClassCall, callNodeID, callName, className))
            param_list.append((callNodeID, callName, className))

        # Get results.
        for future in concurrent.futures.as_completed(future_list):
            index = future_list.index(future)
            params = param_list[index]
            try:
                num_added += future.result()
            except Exception as e:
                print(f"Failed to get number of parent edges added for {params}")
                print(e)

    print(f"Added {num_added} CALLS edges.")
