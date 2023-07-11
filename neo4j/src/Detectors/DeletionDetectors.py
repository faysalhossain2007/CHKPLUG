# GDPR Checker - UninstallDetector.py
# Patrick Thomas pwt5ca
# Created 201209

from datetime import date
from typing import Dict, List, Set
from PersonalData import PersonalDataMatcher
import py2neo
from NeoGraph import getGraph
from NeoHelper import concatTree,getStatementSQLInfo,getNode
from Settings import (
    DATA_TYPE_ATTACHMENT,
    DATA_TYPE_BLOG,
    DATA_TYPE_CATEGORY,
    DATA_TYPE_COMMENT,
    DATA_TYPE_COMMENT_META,
    DATA_TYPE_OPTION,
    DATA_TYPE_POST,
    DATA_TYPE_POST_META,
    DATA_TYPE_SITE_META,
    DATA_TYPE_SITE_TRANSIENT,
    DATA_TYPE_TERM,
    DATA_TYPE_USER,
    DATA_TYPE_USER_META,
)
from SQLParser import getSQLParentNodes
from .Detectors import AbstractDetector
from .FunctionFinding import FunctionFinding
from .Scores import Score, ScoreType
from .Utils import search_scopes
from ValueResolver import evaluateExpression

# Functions from https://codex.wordpress.org/Function_Reference
_WP_DELETE_FUNCTIONS = [
    # "confirm_delete_users",
    "delete_blog_option",
    "delete_comment_meta",
    "delete_option",
    "delete_post_meta",
    "delete_site_option",
    "delete_site_transient",
    "delete_transient",
    "delete_user_meta",
    # "get_delete_post_link",
    # "wp_delete_attachment",
    # "wp_delete_category",
    # "wp_delete_comment",
    "wp_delete_post",
    "wp_delete_term",
    "wp_delete_user",
    "wpmu_delete_blog",
    "wpmu_delete_user",
]
_WP_DELETE_FUNCTIONS_REGEX = f"""(?i)({"|".join(_WP_DELETE_FUNCTIONS)})"""


class AbstractDeletionDetector(AbstractDetector):

    stmt_lists_set: Set[int] = set()
    stmt_lists_contents: Dict[int, str] = dict()

    def _register_result(self, call, call_name, arg, arglist: List[str] = None, uninstall=False):
        findings = FunctionFinding.findings_from_node_id(
            getGraph(), call["id"], ScoreType.DELETION, self
        )
        for f in findings:
            f.score.categories["uninstall"] = uninstall
            if uninstall:
                f.recommendation = "Uninstall deletion call: " + f.recommendation
            else:
                f.score.categories["uninstall"] = uninstall
            self.add_finding(f)


class UninstallDetector(AbstractDeletionDetector):

    __UNINSTALL_HOOK_NAME = "register_uninstall_hook"

    def __init__(self, graph: py2neo.Graph):
        """Detector that looks for uninstall methods for a plugin.

        See https://developer.wordpress.org/plugins/plugin-basics/uninstall-methods/

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 5, 25))
        self.finding_type = ScoreType.DELETION

        self.has_uninstall_hook = False
        self.has_uninstall_file = False

    def __find_uninstall_hook(self):
        """Look for uninstall via deactivation hook."""
        query = f"""
        MATCH (n:AST{{code:"{self.__UNINSTALL_HOOK_NAME}"}})<-[:PARENT_OF]-()<-[:PARENT_OF]-(call:AST)
        WHERE call.type =~ "AST_CALL"
        WITH call
        MATCH (call:AST)-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(funcname:AST{{type:"string", childnum:1}})
        WITH funcname.code AS uninstall_hook_name
        MATCH (n:AST) WHERE n.name = uninstall_hook_name AND n.type = "AST_FUNC_DECL"
        MATCH (n)-[:PARENT_OF]->(m:AST{{type:"AST_STMT_LIST"}})
        RETURN m.id
        """
        results = self.graph.run(query)
        for stmt_list_id in results:
            self.stmt_lists_set.add(stmt_list_id["m.id"])
            self.has_uninstall_hook = True

    def __find_uninstall_php(self):
        """Look for uninstall via uninstall.php."""
        query = """
        MATCH (n:Filesystem{name:"uninstall.php"})
        WITH n
        MATCH (n)-[:FILE_OF]->(:AST{type:"AST_TOPLEVEL"})-[:PARENT_OF]->(m:AST{type:"AST_STMT_LIST"})
        RETURN m.id
        """
        results = self.graph.run(query)
        for stmt_list_id in results:
            self.stmt_lists_set.add(stmt_list_id["m.id"])
            self.has_uninstall_file = True

    def __analyze_statement_list(self):
        query = f"""
        UNWIND [{", ".join([str(i) for i in self.stmt_lists_set])}] as i
        MATCH (:AST{{id:i}})-[:PARENT_OF*]->(stmt_str:AST)
        WHERE stmt_str.code =~ '{_WP_DELETE_FUNCTIONS_REGEX}'
        WITH i, stmt_str ORDER BY stmt_str.lineno
        MATCH (stmt_str)<-[:PARENT_OF]-(:AST{{type:"AST_NAME"}})<-[:PARENT_OF]-(call:AST{{type:"AST_CALL"}})-[:PARENT_OF]->(:AST{{type:"AST_ARG_LIST"}})-[:PARENT_OF]->(first_arg:AST{{childnum:0}})
        RETURN call, stmt_str, first_arg
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, call_name, arg = r
            self._register_result(call, call_name, arg, uninstall=True)

    def __analyze_statement_list_query(self):
        # Get DROP calls
        query = f"""
        UNWIND [{", ".join((str(i) for i in self.stmt_lists_set))}] AS i
        MATCH p=(stmt_list:AST{{id:i}})-[:PARENT_OF*]->(d:AST_SQL{{type:"AST_SQL_DROP"}})-[:SQL_FLOWS_TO]->(:AST_SQL{{type:"AST_SQL_TABLE"}})-[:SQL_FLOWS_TO*]->(n:AST_SQL)
        WHERE n.type =~ "AST_SQL_(NAME|Placeholder)"
        RETURN d, COLLECT(n), LENGTH(p) ORDER BY LENGTH(p)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, names, _ = r
            name = names[0]
            self.new_finding(
                call,
                Score(
                    1.0,
                    {"table deletion": True, "code": name["name"], "uninstall": True},
                    None,
                    ScoreType.DELETION,
                ),
                f"During uninstall, a table dropped: \"{name['code']}\"",
            )

        # Get DELETE calls
        query = f"""
        UNWIND [{", ".join((str(i) for i in self.stmt_lists_set))}] AS i
        MATCH p=(stmt_list:AST{{id:i}})-[:PARENT_OF*]->(d:AST_SQL{{type:"AST_SQL_DELETE"}})-[:SQL_FLOWS_TO]->(:AST_SQL{{type:"AST_SQL_TABLE"}})-[:SQL_FLOWS_TO*]->(n:AST_SQL)
        WHERE n.type =~ "AST_SQL_(NAME|Placeholder)"
        RETURN d, COLLECT(n), LENGTH(p) ORDER BY LENGTH(p)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, names, _ = r
            name = names[0]
            self.new_finding(
                call,
                Score(
                    1.0,
                    {"table deletion": True, "code": name["name"], "uninstall": True},
                    None,
                    ScoreType.DELETION,
                ),
                f"During uninstall, data from table deleted: \"{name['code']}\"",
            )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_uninstall_hook()
        self.__find_uninstall_php()
        self.stmt_lists_set = set(
            search_scopes(self.graph, stmt_list_ids=list(self.stmt_lists_set))
        )
        self.__analyze_statement_list()
        self.__analyze_statement_list_query()
        print(f"### Finish running {self.__class__.__name__}")


class DeletionDetector(AbstractDeletionDetector):
    def __init__(self, graph: py2neo.Graph):
        """Detector that looks for uninstall methods for a plugin.

        See https://developer.wordpress.org/plugins/plugin-basics/uninstall-methods/

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2020, 12, 10))
        self.finding_type = ScoreType.DELETION

    def __find(self, search_str: str, childnum: int, data_types: Set[str]):
        findings = FunctionFinding.findings_from_function_name(
            self.graph, search_str, ScoreType.DELETION, self
        )
        for f in findings:
            self.add_finding(f)

    def __find_deletes_db(self):
        SQLParentNodes = getSQLParentNodes()
        for sql_node in SQLParentNodes:
            sql_info = getStatementSQLInfo(sql_node)
            if not sql_info:
                continue
            if sql_info.operation in ['delete','drop']:
                fields = []
                #find fields for the delete/drop through searching the create sql
                for sql_node2 in SQLParentNodes:
                    sql_info2 = getStatementSQLInfo(sql_node2)
                    if sql_info2.table_name==sql_info.table_name and sql_info2.operation == 'create':
                        fields = sql_info2.fields
                        break
                self.new_finding(
                    getNode(sql_node),
                    Score(
                        1.0,
                        {
                            "drop": True if sql_info=='drop' else False,
                            "code": sql_info.code,
                            "database": True,
                            "wordpress": False,
                            "fields":fields,
                            'data_types':set(PersonalDataMatcher.determine_categories_from_list(fields)),
                            'table_name':sql_info.table_name,
                            'operations':sql_info.operation
                        },
                        None,
                        ScoreType.DELETION,
                    ),
                    f'Table {sql_info.table_name} dropped: "{sql_info.code}"' if sql_info=='drop' else f'Data from table {sql_info.table_name} deleted: "{sql_info.code}"',
                )
    def __find_deletes_wpdb(self):
        graph = getGraph()
        query = f"""
        MATCH (prep:AST{{childnum:1,type:'string',code:'delete'}})<-[:PARENT_OF]-(n:AST{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(var:AST{{childnum:0,type:'AST_VAR'}})-[:PARENT_OF]->(str:AST{{type:'string',code:'wpdb'}})
        MATCH (n)-[:PARENT_OF]->(arg_list:AST{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(args:AST{{childnum:0}})
        RETURN args.id,n
        """
        result = graph.run(cypher=query).data()
        if result:
            for r in result:
                argsID = r['args.id']
                table_name = evaluateExpression(argsID)[0]
                code = concatTree(r['n']['id'])
                self.new_finding(
                    r['n'],
                    Score(
                        1.0,
                        {
                            "drop": False,
                            "code": code,
                            "database": True,
                            "wordpress": False,
                            "fields":[],
                            'data_types':set(),
                            'table_name':table_name,
                            'operations':'delete'
                        },
                        None,
                        ScoreType.DELETION,
                    ),
                    f'Data from table {table_name} deleted: "{code}"',
                )

        # Get DROP calls
        # query = f"""
        # MATCH p=(d:AST{{type:"AST_SQL_DROP"}})-[:SQL_FLOWS_TO]->(:AST_SQL{{type:"AST_SQL_TABLE"}})-[:SQL_FLOWS_TO*]->(n:AST_SQL)
        # WHERE n.type =~ "AST_SQL_(Name|Placeholder)"
        # RETURN d, COLLECT(n), LENGTH(p) ORDER BY LENGTH(p)
        # """
        # results = self.graph.run(query)
        # for r in results:
        #     if not r:
        #         continue
        #     call, names, _ = r
        #     code = concatTree(call["id"])
        #     name = names[0]
        
        # # Get DELETE calls
        # query = f"""
        # MATCH p=(d:AST{{type:"AST_SQL_DELETE"}})-[:SQL_FLOWS_TO]->(:AST_SQL{{type:"AST_SQL_TABLE"}})-[:SQL_FLOWS_TO*]->(n:AST_SQL)
        # WHERE n.type =~ "AST_SQL_(NAME|Placeholder)"
        # RETURN d, COLLECT(n), LENGTH(p) ORDER BY LENGTH(p)
        # """
        # results = self.graph.run(query)
        # for r in results:
        #     if not r:
        #         continue
        #     call, names, _ = r
        #     code = concatTree(call["id"])
        #     name = names[0]
        #     self.new_finding(
        #         call,
        #         Score(
        #             1.0,
        #             {
        #                 "drop": False,
        #                 "code": name["name"],
        #                 "database": True,
        #                 "wordpress": False,
        #             },
        #             None,
        #             ScoreType.DELETION,
        #         ),
        #         f'Data from table deleted: "{code}"',
        #     )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # self.__find("delete_blog_option", 1, "blog_option")
        # self.__find("delete_comment_meta", 1, "comment_meta")
        # self.__find("delete_option", 0, "option")
        # self.__find("delete_post_meta", 1, "post_meta")
        # self.__find("delete_site_meta", 0, "site_meta")
        # self.__find("delete_site_transient", 1, "site_transient")
        # self.__find("delete_user_meta", 0, "user_meta")
        # self.__find("wp_delete_attachment", 0, "attachment")
        # self.__find("wp_delete_category", 0, "category")
        # self.__find("wp_delete_comment", 0, "comment")
        # self.__find("wp_delete_post", 0, "post")
        # self.__find("wp_delete_term", 0, "term")
        # self.__find("wp_delete_user", 0, "user")
        # self.__find("wpmu_delete_blog", 0, "blog")
        # self.__find("wpmu_delete_user", 0, "user")
        self.__find("delete_blog_option", 1, DATA_TYPE_OPTION)
        self.__find("delete_comment_meta", 1, DATA_TYPE_COMMENT_META)
        self.__find("delete_option", 0, DATA_TYPE_OPTION)
        self.__find("delete_post_meta", 1, DATA_TYPE_POST_META)
        self.__find("delete_site_meta", 0, DATA_TYPE_SITE_META)
        self.__find("delete_site_transient", 1, DATA_TYPE_SITE_TRANSIENT)
        self.__find("delete_user_meta", 0, DATA_TYPE_USER_META)
        self.__find("wp_delete_attachment", 0, DATA_TYPE_ATTACHMENT)
        self.__find("wp_delete_category", 0, DATA_TYPE_CATEGORY)
        self.__find("wp_delete_comment", 0, DATA_TYPE_COMMENT)
        self.__find("wp_delete_post", 0, DATA_TYPE_POST)
        self.__find("wp_delete_term", 0, DATA_TYPE_TERM)
        self.__find("wp_delete_user", 0, DATA_TYPE_USER)
        self.__find("wpmu_delete_blog", 0, DATA_TYPE_BLOG)
        self.__find("wpmu_delete_user", 0, DATA_TYPE_USER)
        self.__find_deletes_db()
        self.__find_deletes_wpdb()
        print(f"### Finish running {self.__class__.__name__}")
