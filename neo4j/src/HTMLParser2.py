from Naked.toolshed.shell import muterun_js
from NodeEdgeManager import *
import json
import os
from pathlib import Path
from Settings import SRC_DIR, ROOT_DIR

PARSER = Path(__file__).resolve().parents[0] / 'htmlparser.js'

def parseHTML(fileDir, toplevel_nodeID, handleHTMLinPHP=False):
    count = 0
    edgeCount = 0
    response = None
    htmlstring = ''
    if handleHTMLinPHP:
        htmlstring = fileDir.replace("'", "\\'")
        htmlstring = f"$'{htmlstring}'"
        response = muterun_js(str(PARSER), arguments=f"""{htmlstring}""")
    else:
        response = muterun_js(str(PARSER), arguments=f"""{fileDir} -from_file""")
    response = response.stdout.decode("utf-8")
    if response:
        nodeList = json.loads(response)
        if len(nodeList) == 2 and (nodeList[1].get("name", None) == '?php' or nodeList[1].get("type",None)=='text'):
            #if the current file is pure php, return
            return
        OldNewIDs = {}
        for node in nodeList:
            newID = addHTMLNode("AST_HTML", "string" if node['type'] == 'text' else node['type'],
                                node.get("startIndex", None), node.get("endIndex", None), node.get("code", None),
                                node.get("childnum", None), node.get("name", None))
            OldNewIDs[node['id']] = newID
            count += 1
        #scan the node list again to make sure all ids have been replaced by new ones by now. Now, add all edges
        #add reaches edge between the HTML root node and the PHP AST_ECCHO node (for html inside php)
        if handleHTMLinPHP:
            edgeCount += addEdge(OldNewIDs[nodeList[0]['id']], "AST_HTML", toplevel_nodeID, "AST", "HTML_TO_PHP_REACHES")
        #Or, add edge between file's Toplevel node and the HTML root node (for pure html)
        else:
            edgeCount += addEdge(toplevel_nodeID, "AST", OldNewIDs[nodeList[0]['id']], "AST_HTML", "PARENT_OF")
        for node in nodeList:
            parentID = node.get("parentID", -1)
            if not parentID == -1:
                edgeCount += addEdge(OldNewIDs[parentID], "AST_HTML", OldNewIDs[node['id']], "AST_HTML", "PARENT_OF")
        print(f"Added {count} AST_HTML nodes and {edgeCount} PARENT_OF edges.")
    else:
        if handleHTMLinPHP:
            print(f"HTML code '{htmlstring}' cannot be parsed correct.")
        else:
            print(f"HTML code from file '{fileDir}' cannot be parsed correct.")
