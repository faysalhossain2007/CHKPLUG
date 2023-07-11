# GDPR Checker - FunctionFinding.py
# Patrick Thomas pwt5ca
# Created 210525

from typing import Any, Dict, List, Set

from Functions import FUNCTION_SENSITIVITY
from NeoHelper import concatTree,getCallArguments
from py2neo import Graph
from Settings import ALL_WORDPRESS_FUNCTIONS
from ValueResolver import evaluateExpression

from Detectors.Utils import map_args_with_name

from .Detectors import AbstractDetector
from .Scores import Score, ScoreType
from PersonalData import PersonalDataMatcher


class FunctionFinding(AbstractDetector.Finding):
    def __init__(
        self,
        graph: Graph,
        call_node: dict,
        name_node: Dict[str, Any],
        score: Score,
        detector: AbstractDetector,
    ):
        self.graph: Graph = graph

        # Get function info.
        self.function_annotation = FUNCTION_SENSITIVITY.get(name_node["code"], None)
        self.function_info = ALL_WORDPRESS_FUNCTIONS.get(name_node["code"], dict())

        self.is_wordpress: bool = bool(self.function_info)
        self.code = concatTree(call_node["id"])

        # Now get return type and argument info if possible.
        if self.function_info:
            self.arg_map = map_args_with_name(self.graph, call_node["id"], name_node["code"])
            self.arg_info = {
                k: dict(self.function_info.get(v, {})) for k, v in self.arg_map.items()
            }
            self.return_types: List[str] = list(
                self.function_info.get("returns", {}).get("types", [])
            )
            #arg_value stores the value of arguments 
        else:
            self.arg_map = dict()
            self.arg_info = dict()
            self.return_types = list()
        self.arg_values = dict()

        #get the resolved value for the call arguments
        args = getCallArguments(call_node["id"])
        for arg in args:
            resolved_value = evaluateExpression(arg['id'])
            #if we don't know the value of the parameter, we will just use the name of the parameter, which is later used to approximate whether it's personal data or not.
            if not resolved_value[0]:
                self.arg_values[arg['childnum']] = concatTree(arg['id'])
            else:
                self.arg_values[arg['childnum']] = resolved_value[0]
        self.keyValue = None
        self.data_types: Set[str] = score.get_data_types()
        if self.function_annotation and self.function_annotation.data_type:
            self.data_types.update(self.function_annotation.data_type)
            if self.function_annotation.key_param and (not self.function_annotation.key_param==-1):
                keyValue = ''
                if self.function_annotation.key_param in self.arg_values:
                    keyValue = self.arg_values[self.function_annotation.key_param]
                self.data_types.update(PersonalDataMatcher.determine_category(keyValue))
                self.keyValue = keyValue


        self.score = score
        self.score.categories = {
            **self.score.categories,
            **{
                "name": name_node["code"],
                "function": name_node["code"],
                "code": self.code,
                "data_types": self.data_types,
                "function_info": self.function_info,
                "wordpress": self.is_wordpress,
                "arg_map": self.arg_map,
                "arg_info": self.arg_info,
                "return_types": self.return_types,
            },
        }
        self.score.types.update(self.data_types)
        arg_info_s = [
            f"{k}: {v} ({'|'.join(self.arg_info[k].get('type', []))})"
            for k, v in self.arg_map.items()
        ]
        alter_s = f""" alters data types {self.data_types}""" if self.data_types else ""
        arg_info_s_combined = f" Passed arguments: {', '.join(arg_info_s)}." if arg_info_s else ""
        return_s = "" if not self.return_types else f" Returns ({'|'.join(self.return_types)})."

        recommendation = f"""{score.score_type.name} call to {self.code}{alter_s}.{arg_info_s_combined}{return_s}"""

        super().__init__(graph, call_node, recommendation, score, detector)

    @staticmethod
    def findings_from_function_name(
        graph: Graph,
        call_name_pattern: str,
        # recommendation_pattern: FunctionType,
        score_type: ScoreType,
        detector: AbstractDetector,
        node_label: str = "AST",
        data_types: Set[str] = set(),
    ) -> List[AbstractDetector.Finding]:
        query = f"""
        MATCH (call:{node_label}{{type:"AST_CALL"}})-[:PARENT_OF]->
            (:{node_label}{{type:"AST_NAME", childnum:0}})-[:PARENT_OF]->
            (name:{node_label}{{type:"string"}})
        WHERE name.code =~ "{call_name_pattern}"
        RETURN call, name
        UNION
        MATCH (call:{node_label}{{type:"AST_STATIC_CALL"}})-[:PARENT_OF]->
            (:{node_label}{{type:"AST_NAME", childnum:1}})-[:PARENT_OF]->
            (name:{node_label}{{type:"string"}})
        WHERE name.code =~ "{call_name_pattern}"
        RETURN call, name
        UNION
        MATCH (call:{node_label}{{type:"AST_METHOD_CALL"}})-[:PARENT_OF]->
            (name:{node_label}{{type:"string", childnum:1}})
        WHERE name.code =~ "{call_name_pattern}"
        RETURN call, name
        """
        results = graph.run(query)
        if not results:
            return []

        output: List[AbstractDetector.Finding] = []
        for r in results:
            if not r:
                continue
            call, name = r
            call_d = dict(call)
            name_d = dict(name)
            # recommendation = recommendation_pattern(call_d)
            score = Score(1, {}, None, score_type)
            score.store_data_type_info(data_types)

            finding = FunctionFinding(graph, call_d, name_d, score, detector)
            output.append(finding)

        return output

    @staticmethod
    def findings_from_node_id(
        graph: Graph,
        call_node_id: int,
        score_type: ScoreType,
        detector: AbstractDetector,
        node_label: str = "AST",
    ) -> List[AbstractDetector.Finding]:
        query = f"""
        MATCH (call:{node_label}{{type:"AST_CALL"}})-[:PARENT_OF]->
            (:{node_label}{{type:"AST_NAME", childnum:0}})-[:PARENT_OF]->
            (name:{node_label}{{type:"string"}})
        WHERE call.id = {call_node_id}
        RETURN call, name
        UNION
        MATCH (call:{node_label}{{type:"AST_STATIC_CALL"}})-[:PARENT_OF]->
            (:{node_label}{{type:"AST_NAME", childnum:1}})-[:PARENT_OF]->
            (name:{node_label}{{type:"string"}})
        WHERE call.id = {call_node_id}
        RETURN call, name
        UNION
        MATCH (call:{node_label}{{type:"AST_METHOD_CALL"}})-[:PARENT_OF]->
            (name:{node_label}{{type:"string", childnum:1}})
        WHERE call.id = {call_node_id}
        RETURN call, name
        """
        results = graph.run(query)
        if not results:
            return []

        output: List[AbstractDetector.Finding] = []
        for r in results:
            if not r:
                continue
            call, name = r
            call_d = dict(call)
            name_d = dict(name)
            # recommendation = recommendation_pattern(call_d)
            score = Score(1, {}, None, score_type)

            finding = FunctionFinding(graph, call_d, name_d, score, detector)
            output.append(finding)

        return output
