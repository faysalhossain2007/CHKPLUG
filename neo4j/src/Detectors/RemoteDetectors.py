# GDPR Checker - RemoteDetectors.py
# Patrick Thomas pwt5ca
# Created 200615

from datetime import date
from json import loads
from typing import List

import py2neo
from NeoHelper import getNode, isURLThirdParty,isUrlValid
from Settings import DATA_TYPE_REMOTE
from NeoGraph import getGraph
from ValueResolver import evaluateExpression,evaluateURLExpression
from DataFlowTracking import getMaxTraversalLength
from .Detectors import AbstractDetector
from .FunctionFinding import FunctionFinding
from .Scores import Score, ScoreType

def findThirdPartyURLNodes():
    """This function intends to find all third party url strings in the plugin, which can be used to trace how they are being used.
    """
    thirdPartyNodes = []
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{type:string}})
    WHERE n.code CONTAINS 'http'
    RETURN n.id,n.code 
    """
    results = graph.run(cypher=query).data()
    if results:
        for result in results:
            potentialURL = result['n.code']
            if isUrlValid(potentialURL) and isURLThirdParty(potentialURL):
                thirdPartyNodes.append(result['n.id'])
    return thirdPartyNodes

# class jQueryRequestDetector(AbstractDetector):

    
#     def __init__(self, graph: py2neo.Graph):
#         #detects $.post, $.get, $.ajax, jQuery.post, jQuery.get, jQuery.ajax. Check jquery docs: https://api.jquery.com/jquery.get/
#         super().__init__(graph, date(2022, 6, 1))
#         self.finding_type = ScoreType.API

#     def __find(self):
#         #get method calls for $.post, $.get, $.ajax, jQuery.post, jQuery.get, jQuery.ajax
#         query = f"""
#         MATCH (n:AST_JS{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(:AST_JS{{childnum:0,type:'AST_VAR'}})-[:PARENT_OF]->(var:AST_JS{{type:'string'}})
#         WHERE var.code in ['$','jQuery']
#         WITH n
#         MATCH (n)-[:PARENT_OF]->(var2:AST_JS{{childnum:1,type:'string'}})
#         WHERE var2.code in ['post','get','ajax']
#         OPTIONAL MATCH (n)-[:PARENT_OF]->(:AST_JS{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(url:AST_JS{{childnum:0}})
#         WHERE NOT url.type='AST_ARRAY'
#         OPTIONAL MATCH (n)-[:PARENT_OF]->(:AST_JS{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(:AST_JS{{childnum:0,type:'AST_ARRAY'}})-[:PARENT_OF]->(:AST_JS{{childnum:0,type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(url2:AST_JS{{childnum:0}})
#         RETURN n,url.id,url2.id
#         """
#         results = self.graph.run(query).data()
#         if not results:
#             return
#         for r in results:
#             n = r['n']

#             url1 = r['url.id']
#             url2 = r['url2.id']
#             url_id = url1 if url1 else url2
#             # print(url_id)
#             url_str = evaluateURLExpression(url_id)
#             # print(url_str)
#             score = Score.api_score(True, url_str)
#             self.new_finding(
#                 n,
#                 score,
#                 f"External request to possible URLs {url_str}.",
#             )
            


#     def _run(self):
#         print(f"### Start running {self.__class__.__name__}")
#         self.__find()
#         print(f"### Finish running {self.__class__.__name__}")
    

class PhpCurlDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Look for PHP cURL usages: https://www.php.net/manual/en/book.curl.php.

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2020, 10, 10))
        self.finding_type = ScoreType.API

    def __find_curl(self):
        curl_calls = self._simple_match_call("curl_exec")

        for call_id in curl_calls:
            query = f"""
            MATCH p=(stmt_list:AST{{type:"AST_STMT_LIST"}})-[:PARENT_OF]->(root)-[:PARENT_OF*0..]->(call:AST{{id:{call_id}}})
            WITH stmt_list, call, root ORDER BY LENGTH(p) ASC LIMIT 1
            OPTIONAL MATCH (root)<-[:REACHES]-(reaches:AST)-[:PARENT_OF{getMaxTraversalLength()}]->(init_call:AST{{type:"AST_CALL"}})-[:PARENT_OF]->(:AST{{type:"AST_NAME"}})-[:PARENT_OF]->(init_name:AST{{type:"string", code:"curl_init"}})
            OPTIONAL MATCH (init_call)-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(init_url:AST)
            OPTIONAL MATCH (reaches)-[:REACHES{getMaxTraversalLength()}]->(more_reaches:AST)
            OPTIONAL MATCH (more_reaches)-[:PARENT_OF{getMaxTraversalLength()}]->(setopt_call:AST{{type:"AST_CALL"}})-[:PARENT_OF]->(:AST{{type:"AST_NAME"}})-[:PARENT_OF]->(setopt_name:AST{{type:"string", code:"curl_setopt"}})
            OPTIONAL MATCH (setopt_call)-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(setopt_arg:AST)
            OPTIONAL MATCH (more_reaches)-[:PARENT_OF{getMaxTraversalLength()}]->(setopt_array_call:AST{{type:"AST_CALL"}})-[:PARENT_OF]->(:AST{{type:"AST_NAME"}})-[:PARENT_OF]->(setopt_array_name:AST{{type:"string", code:"curl_setopt_array"}})
            OPTIONAL MATCH (setopt_array_call)-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(setopt_array_arg:AST)
            RETURN call.id, init_call.id, setopt_call.id, setopt_array_call.id, COLLECT(DISTINCT [init_url.id, init_url.childnum]), COLLECT(DISTINCT [setopt_arg.id, setopt_arg.childnum]), COLLECT(DISTINCT [setopt_array_arg.id, setopt_array_arg.childnum])
            """
            results = self.graph.run(query)
            if not results:
                continue
            for r in results:
                if not r:
                    continue
                (
                    call_id,
                    init_call_id,
                    setopt_call_id,
                    setopt_array_call_id,
                    init_args,
                    setopt_args,
                    setopt_array_args,
                ) = r
                if init_call_id and init_args and init_args[0] and init_args[0][0]:
                    # URL is passed in curl_init.
                    init_args_list = sorted(init_args, key=lambda x: x[1])
                    v = evaluateURLExpression(init_args_list[0][0])
                    score = Score.api_score(True, v)
                    self.new_finding(
                        getNode(call_id),
                        score,
                        f"External request to possible URLs {v}.",
                    )
                    break
                elif setopt_call_id and setopt_args and setopt_args[0] and setopt_args[0][0]:
                    # URL is passed in curl_setopt
                    setopt_args_list = sorted(setopt_args, key=lambda x: x[1])
                    try:
                        k, _ = evaluateExpression(setopt_args_list[1][0])
                        v = evaluateURLExpression(setopt_args_list[2][0])
                        if k == "CURLOPT_URL":
                            score = Score.api_score(True, v)
                            for url in v:
                                if not (url.startswith("https://") or url.startswith("http://")):
                                    self.new_finding(
                                        getNode(call_id),
                                        score,
                                        f"External request to unknown URL (unable to statically determine).",
                                    )
                                else:
                                    self.new_finding(
                                        getNode(call_id),
                                        score,
                                        f"External request to URL {url}.",
                                    )
                    except:
                        pass
                    break
                elif (
                    setopt_array_call_id
                    and setopt_array_args
                    and setopt_array_args[0]
                    and setopt_array_args[0][0]
                ):
                    # URL is passed in curl_setopt_array.
                    setopt_array_args_list = sorted(setopt_array_args, key=lambda x: x[1])
                    arg_array_id = setopt_array_args_list[1][0]
                    arg_array_json, _ = evaluateExpression(arg_array_id)
                    try:
                        arg_array = loads(arg_array_json)
                        if "CURLOPT_URL" in arg_array.keys():
                            url = [str(arg_array.get("CURLOPT_URL", ""))]
                            score = Score.api_score(True, url)
                            if not (url.startswith("https://") or url.startswith("http://")):
                                self.new_finding(
                                    getNode(call_id),
                                    score,
                                    f"External request to unknown URL (unable to statically determine).",
                                )
                            else:
                                self.new_finding(
                                    getNode(call_id),
                                    score,
                                    f"External request to URL {url}.",
                                )
                    except:
                        pass
                    break

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_curl()
        print(f"### Finish running {self.__class__.__name__}")


class WordPressRemoteDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Look for WordPress remote requests and posts.

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2020, 10, 10))
        self.finding_type = ScoreType.API

    def __find_wp_remote(self):
        regex = f"(?i)(wp_remote_(post|get|head|request))"

        for finding in FunctionFinding.findings_from_function_name(
            self.graph, regex, self.finding_type, self
        ):
            # Evaluate the first arg to determine the URL.
            query = f"""
            MATCH (call:AST{{id: {finding.node["id"]}}})-[:PARENT_OF]->(:AST{{type: "AST_ARG_LIST"}})-[:PARENT_OF]->(url:AST{{childnum: 0}})
            RETURN COLLECT(DISTINCT url.id)
            """
            results = self.graph.evaluate(query)
            if results:
                url_ids: List[int] = list(results)
                for url_id in url_ids:
                    url_str = evaluateURLExpression(url_id)
                    # finding.score.categories["url"] = url_str
                    uses_https = True
                    for url in url_str:
                        if not "https://" in url:
                            uses_https = False
                    finding.score = Score.api_score(uses_https,url_str)
                    # finding.score.categories["uses_https"] = uses_https
                    break
            finding.score.types = DATA_TYPE_REMOTE
            self.add_finding(finding)

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_wp_remote()
        print(f"### Finish running {self.__class__.__name__}")
