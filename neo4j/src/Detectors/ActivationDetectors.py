# GDPR Checker - ActivationDetector.py
# Patrick Thomas pwt5ca
# Created 201209

from datetime import date
from typing import Set

import py2neo

from .Detectors import AbstractDetector
from .Scores import Score, ScoreType
from .Utils import search_scopes


class ActivationDetector(AbstractDetector):

    stmt_lists_set: Set[int] = set()

    __ACTIVATION_HOOK_NAME = "register_activation_hook"

    def __init__(self, graph: py2neo.Graph):
        """Detector that looks for activation methods for a plugin.

        See https://developer.wordpress.org/plugins/plugin-basics/activation-deactivation-hooks/

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2020, 12, 10))
        self.finding_type = ScoreType.ACTIVATION

    def __find(self):
        query = f"""
        MATCH
            (n:AST)<-[:PARENT_OF]-()<-[:PARENT_OF]-(call:AST)
        WHERE
            (n.code = "{self.__ACTIVATION_HOOK_NAME}" OR n.code = "add_action")
            AND call.type =~ "AST_CALL"
        OPTIONAL MATCH
            (call:AST)-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(hookname:AST{{type:"string", childnum:0}})
        MATCH
            (call:AST)-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(funcname:AST{{type:"string", childnum:1}})
        WHERE
            (n.code = "add_action" AND hookname.code = "init")
            OR n.code = "{self.__ACTIVATION_HOOK_NAME}"
        WITH
            funcname.code AS hook
        MATCH
            (n:AST) WHERE n.name = hook AND n.type = "AST_FUNC_DECL"
        MATCH
            (n)-[:PARENT_OF]->(m:AST{{type:"AST_STMT_LIST"}})
        RETURN m.id
        """
        results = self.graph.run(query)
        for stmt_list_id in results:
            if stmt_list_id:
                self.stmt_lists_set.add(stmt_list_id["m.id"])

    def __search_for_table_creation(self):
        query = f"""
        UNWIND [{", ".join((f'{i}' for i in self.stmt_lists_set))}] AS i
        MATCH (stmt_list:AST{{id:i}})-[:PARENT_OF*]->(s:AST{{type:"AST_SQL_START"}})-[:PARENT_OF*]->(n) WHERE n.type =~ "AST_SQL.*CREATE"
        MATCH (s)-[:PARENT_OF*]->(:AST{{type:"AST_SQL_IdentifierList"}})-[:PARENT_OF]->(:AST{{type:"AST_SQL_Identifier"}})-[:PARENT_OF]->(m:AST{{type:"AST_SQL_Name"}})
        WITH n, s, COLLECT(m.code) as fields
        OPTIONAL MATCH (n)-[:SQL_FLOWS_TO*]->(o:AST)
        WHERE o.type =~ "AST_SQL_(Name|Placeholder)"
        RETURN s, fields, COLLECT(DISTINCT o)[0] as table_name
        """
        results = self.graph.run(query)
        if not results:
            return
        for sql_start_node, field_names, table_name in results:  # type: ignore
            self.new_finding(
                sql_start_node,
                Score(
                    1.0,
                    {
                        "activation": True,
                        "table creation": True,
                        "table name": table_name["code"],
                        "fields": field_names,
                    },
                    None,
                    ScoreType.ACTIVATION,
                ),
                f"Table created with the following fields: {str(field_names)}",
            )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        self.stmt_lists_set = set(search_scopes(self.graph, list(self.stmt_lists_set)))
        self.__search_for_table_creation()
        print(f"### Finish running {self.__class__.__name__}")
