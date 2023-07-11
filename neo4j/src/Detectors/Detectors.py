# GDPR Checker - Detectors.py
# Patrick Thomas pwt5ca
# Created 200615

import json
from abc import ABC, abstractmethod
from datetime import date
from os.path import dirname, join, realpath
from traceback import print_exc
from typing import Any, Dict, List, Optional, Set, Tuple

import py2neo
from NeoHelper import getNodeChildren, getStatementSQLInfo
from Settings import ALL_WORDPRESS_FUNCTIONS

from .Scores import Score, ScoreType
from .Utils import find_reaches_relationship, get_node_filename, get_php_uses_map
from DataFlowTracking import getMaxTraversalLength

GENERIC_MAX_LEN = 40

"""
SCORE_BOUNDS is defined as follows: the first element of an element of the list indicates the
maximum score required to classify into the category named after the second element of the sublist.
By default, [0.0, 0.25) is failing, [0.25, 0.75) is a risk, and [0.75, 1.0] is passing. By default,
anything outside of 0.0 and 1.0 is classified as WARNING.
"""
SCORE_BOUNDS = {0.25: "FAIL", 0.75: "RISK", 1.00: "PASS"}  # type: Dict[float, str]
WARNING_STR = "WARNING"
WARNING = -1.0

SCORE_MAX = 1.0

IGNORE_MD5 = False
IGNORE_SHA1 = False

TEST_DIR_NAME = "EncryptionTests"


class AbstractDetector(ABC):
    """A generic class for an object that detects some sort of security."""

    SILENT_INITIALIZATION = True

    # Load the list of approved security functions from the configured JSON file.
    f = None
    with open(join(dirname(realpath(__file__)), "SecurityFunctions.json"), "r") as f:
        settings = json.load(f)
    del f

    _uses_map = {}  # type: Dict[str, List[str]]
    __uses_map_loaded = False  # type: bool

    def __init__(self, graph: py2neo.Graph, date_created: date) -> None:
        """Initialize the security detector. Needs some connection to Neo4j.

        Args:
            graph (py2neo.Graph): Connection to Neo4j.
        """

        self.graph = graph
        self.findings: List[AbstractDetector.Finding] = []
        self.__date_created = date_created
        if not AbstractDetector.__uses_map_loaded:
            AbstractDetector._uses_map = get_php_uses_map(self.graph)
            AbstractDetector.__uses_map_loaded = True

        if not AbstractDetector.SILENT_INITIALIZATION:
            print(
                f"  - {type(self).__name__} last updated on {self.__date_created}, {(date.today() - self.__date_created).days} days ago"
            )

        self.finding_type = ScoreType.ERROR

    class Finding:
        """Finding represents the output of some test on the graph."""

        __next_id = 0

        def __init__(
            self,
            graph: py2neo.Graph,
            node_dict: dict,
            recommendation: str,
            score: Score,
            detector,
        ):

            self.node = node_dict
            self.graph = graph
            self.file = get_node_filename(graph, self.node["id"])
            self.line = self.node["lineno"] if "lineno" in self.node else 0
            self.recommendation = recommendation
            self.score: Score = score
            self.parent = detector
            self.parent_name = type(detector).__name__

            AbstractDetector.Finding.__next_id += 1
            self.__id = AbstractDetector.Finding.__next_id

            self.sql_info = None
            if self.score.is_database():
                self.sql_info = getStatementSQLInfo(self.node["id"])

        def __str__(self) -> str:
            """Return a string representation of the Finding, for usage in a report.

            Returns:
                str: A line in the report.
            """
            data_type_str = ", ".join(self.get_data_types())
            if self.recommendation and data_type_str:
                return f"{self.file}:{self.node['lineno']}\n  - {self.recommendation}\n  - Data types: {data_type_str}"
            elif self.recommendation:
                return f"{self.file}:{self.node['lineno']}\n  - {self.recommendation}"
            else:
                return f"{self.file}:{self.node['lineno']}\n"

        def __repr__(self) -> str:
            """Return a string representation of the Finding, for usage in a report.

            Returns:
                str: A line in the report.
            """
            category = self.classify_score()
            return f"{type(self.parent).__name__}.Finding[{category}, {self.file}]"

        def get_data_types(self) -> Set[str]:
            """Helper function to get the data types from the Score.

            Returns:
                Set[str]: Set of strings representing the score.
            """
            return self.score.get_data_types()

        def get_function_info(self) -> dict:
            """Get the function info dict for the function call.

            Returns:
                dict: Dict of function info. See ALL_WORDPRESS_FUNCTIONS.
            """
            call_name = self.get_call_name()
            if call_name:
                return ALL_WORDPRESS_FUNCTIONS.get(call_name, dict())
            return dict()

        def get_call_name(self) -> Optional[str]:
            if "CALL" in self.node["type"]:
                if "METHOD" in self.node["type"] or "STATIC" in self.node["type"]:
                    children = getNodeChildren(self.node["id"])
                    if len(children) >= 2:
                        return children[1]["code"]
                else:
                    children = getNodeChildren(self.node["id"])
                    if children:
                        name_children = getNodeChildren(children[0]["id"])
                        if name_children:
                            return name_children[0]["code"]
            elif self.node["type"] == "string":
                return self.node["code"]
            return None

        def classify_score(self) -> str:
            if self.score.value < 0.0 or self.score.value > 1.0:
                return "WARNING"
            for upper_bound, category in SCORE_BOUNDS.items():
                if self.score.value <= upper_bound:
                    return category
            return "WARNING"

        def short_desc(self) -> str:
            return f"""[{type(self.parent).__name__}.{self.__id}, score={100.0*self.score.value/SCORE_MAX:.1f}%, {self.classify_score()}]"""

    def _simple_match(self, keyword: str) -> List[Dict[str, Any]]:
        """Run a simple query on the graph to match all code occurrences of query.

        Args:
            query (str): The keyword to search for; can contain regular expressions

        Returns:
            list: List of nodes whose code property matches the query.
        """
        query = f"""match (n) where n.code =~ "{keyword}" return collect(n)"""
        results = self.graph.evaluate(query)
        if not results:
            return []
        return results

    def _simple_match_call(self, keyword: str) -> List[int]:
        """Run a simple query on the graph to match all call names by this name.

        Args:
            query (str): The keyword to search for; can contain regular expressions

        Returns:
            list: List of nodes whose code property matches the query.
        """
        output: List[int] = []

        query = f"""
        MATCH (c:AST)-[:PARENT_OF]->(name:AST{{childnum:1}})
        WHERE c.type =~ "AST_METHOD_CALL" AND name.code =~ "{keyword}"
        RETURN COLLECT(DISTINCT c.id)
        """
        results = self.graph.evaluate(query)
        if results:
            output.extend(results)

        query = f"""
        MATCH (c:AST)-[:PARENT_OF]->(:AST{{type:"AST_NAME"}})-[:PARENT_OF]->(name:AST)
        WHERE c.type =~ "AST(_STATIC|)_CALL" AND name.code =~ "{keyword}"
        RETURN COLLECT(DISTINCT c.id)
        """
        results = self.graph.evaluate(query)
        if results:
            output.extend(results)

        return output

    def _find_object_class(self, var_name_id: int) -> str:
        """Find the parent class of a method call from some instantiated object from the PHP AST.

        Args:
            var_name_id (int): Node ID of a AST_NAME node, typically the first child of a AST_METHOD_CALL node.

        Returns:
            str: Name of the class, otherwise returns "".
        """

        children: List[int] = [n["id"] for n in getNodeChildren(var_name_id)]
        du_pair = find_reaches_relationship(self.graph, children[0])
        if du_pair is None:
            return ""

        d, u = du_pair
        if d["type"] == "AST_ASSIGN":
            query = f"""
            match
                (assign)-[:PARENT_OF]->(new)-[:PARENT_OF]->(name)-[:PARENT_OF]->(str)
            where
                assign.id = {d['id']} and
                new.childnum = 1 and
                new.type = "AST_NEW" and
                name.type = "AST_NAME" and
                str.type = "string"
            return str.code
            """
            class_name = self.graph.evaluate(query)
            if class_name is not None:
                return class_name
        return ""

    def run(self) -> list:
        """Run the detector on the graph.

        Returns:
            dict: Empty dictionary; see UserWarning.
        """
        self.findings.clear()
        try:
            self._run()
        except Exception as e:
            print(f"Error in {type(self).__name__}:")
            print_exc()
        return self.findings

    @abstractmethod
    def _run(self):
        """Version of run to be implemented. Should make calls to new_finding.

        Raises:
            NotImplementedError: Raised by default since this is a stub.
        """
        raise NotImplementedError("Not implemented.")

    def report(self) -> str:
        """Generate a report for this criteria and store it in a string.

        Returns:
            str: The report.
        """
        if self.findings is []:
            self.run()

        # Sort findings by file name and line number
        self.findings.sort(key=lambda x: f"{x.file}{x.line:05d}")

        str_list = []
        finding: AbstractDetector.Finding
        for finding in self.findings:
            str_list.append(str(finding))
            # str_list.append("      " + str(finding.score.long_description()))
        return "\n".join(str_list)

    def new_finding(self, node_dict: dict, score: Score, reason: str):
        """Shortcut to instantiate a new finding.

        Args:
            node_dict ({str: object}): Some mapping from Neo4j and the PHP AST to a node's properties.
            is_passing (bool): Is the usage secure/state-of-the-art?
            reason (str): Reason for the verdict, can also be recommendation.
            attribs (dict, optional): Extra attributes to give to the report. Defaults to {}.
        """
        assert isinstance(score, Score)

        if node_dict.get("n", None) is not None:
            node_dict = node_dict["n"]

        self.add_finding(
            AbstractDetector.Finding(
                graph=self.graph,
                node_dict=node_dict,
                score=score,
                recommendation=reason,
                detector=self,
            )
        )

    def add_finding(self, finding):
        self.findings.append(finding)

    def post(self, detectors: list):
        """Do something after the fact. This is called after all other detectors have ran."""
        pass

    def tally(self) -> Dict[str, int]:
        """Gets a dictionary of score category to number of scores in said category.

        Returns:
            Dict[str, int]: Mapping from category (defined in SCORE_BOUNDS) to number of findings that fall into said category.
        """
        output = {}  # type: Dict[str, int]
        for finding in self.findings:
            category = finding.classify_score()
            if category not in output.keys():
                output[category] = 1
            else:
                output[category] += 1
        return output

    def score(self) -> Tuple[float, float]:
        """Compute the average score of the findings.

        Requires that the detector has already been ran once.

        Returns:
            float: Score. Should range from 0.00 to 1.00, and dividing the score by SCORE_MAX also scales the score.
        """
        output = 0.0
        count = 0
        for finding in self.findings:
            if 0.0 <= finding.score.value <= 1.0:
                output += finding.score.value
                count += 1
        return output, count

    def _find_with_arg(self, search_re: str, target_child_num: int) -> dict:
        """For some call to a function `foo(bar, baz)`, find some function named `foo` and return the nth numbered child of the arg list.

        Args:
            search_re (str): Function name to search for.
            target_child_num (int): The index of the child of the AST_ARG_LIST node.

        Returns:
            dict: Node dictionary for child number n.
        """
        query = f"""
        match (arg_list:AST)<-[:PARENT_OF]-(call:AST)-[:PARENT_OF*..2]->(call_name:AST) 
        where 
            call.type =~ "AST_CALL" and call_name.code =~ "{search_re}" and arg_list.type =~ "AST_ARG_LIST"
        optional match (arg_list)-[:PARENT_OF]->(nth_child:AST)
        where
            nth_child.childnum = {target_child_num}
        optional match (nth_child)-[:PARENT_OF*]->(children:AST)
        where
            children.type =~ "string"
        return call_name, nth_child, collect(children)
        """
        results = self.graph.run(query)

        found_params: Dict[dict, Set[dict]] = dict()
        for call, nth_child, children in results:
            found_params[call] = set()
            if nth_child["code"] is not None:
                found_params[call].add(nth_child)
            for c in children:
                found_params[call].add(c)

        return found_params

    def _db_test_if_local(self, start_node: int) -> bool:
        """Given a starting node that is some child of a call to a database_connect, return if "localhost" is apparent
        in the entire tree.

        Args:
            start_node (int): Node that is child of last relevant call in functions to setup a database connection.

        Returns:
            (bool): true if "localhost" is defined in the tree, otherwise false.
        """
        query = f"""
        match (child_node) where child_node.id = {start_node}
        match q=(stmt_list:AST{{type:"AST_STMT_LIST"}})-[:PARENT_OF]->(stmt)-[:PARENT_OF*]->(child_node)
        with child_node, stmt order by length(q) limit 1
        optional match (reaches_parent)-[:REACHES{getMaxTraversalLength()}]->(stmt)-[:PARENT_OF{getMaxTraversalLength()}]->(child_node)
        optional match (reaches_parent)-[:PARENT_OF{getMaxTraversalLength()}]->(flag) where flag.code =~ ".*(localhost|127\\\\.0\\\\.0\\\\1).*"
        return distinct child_node, collect(distinct flag)
        """
        results = self.graph.run(query)
        for _, flags in results:
            if flags is not None and len(flags) >= 1:
                return True
        return False
