# GDPR Checker - PhpDetectors.py
# Patrick Thomas pwt5ca
# Created 210625

from datetime import date

import py2neo
from NeoHelper import getNode
from ValueResolver import evaluateExpression

from .Detectors import AbstractDetector
from .Scores import Score, ScoreType
from Settings import DATA_TYPE_IP

class PhpVarDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2021, 6, 25))
        self.finding_type = ScoreType.RETRIEVAL

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        query = """
        MATCH (dim:AST{type:"AST_DIM"})
            -[:PARENT_OF]->(var:AST{type:"AST_VAR", childnum:0})
            -[:PARENT_OF]->(name:AST{type:"string", code:"_REQUEST"})
        MATCH (dim)-[:PARENT_OF]->(index:AST{childnum:1})
        RETURN dim.id, index.id
        """
        results = self.graph.run(query)
        if not results:
            return
        for r in results:
            if not r:
                continue
            dim_id, index_id = r

            index_val, _ = evaluateExpression(index_id)
            if index_val in {
                "REMOTE_ADDR",
                "HTTP_CLIENT_IP",
                "HTTP_X_FORWARDED_FOR",
            }:  # Thanks Mike
                score = Score(1.0, {"data_types":list(DATA_TYPE_IP)}, None, ScoreType.RETRIEVAL)
                score.store_data_type_info("ip")
                self.new_finding(getNode(dim_id), score, "Remote request IP (user IP) is accessed.")
        print(f"### Finish running {self.__class__.__name__}")
