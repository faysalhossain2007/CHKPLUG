
from NeoGraph import getGraph
from .Detectors import AbstractDetector
from .Scores import Score
import py2neo
from datetime import date
from NeoHelper import concatTree
from PersonalData import PersonalDataMatcher

class VariableDetector(AbstractDetector):

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to catch variables that have sensitive names (e.g., $email)

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 10, 15))

    def __find(self):
        pii_list = PersonalDataMatcher.get_pii_list_regex()
        graph = getGraph()
        for pii in pii_list:
            query = f"""
            MATCH (n:AST{{type:'AST_VAR'}})-[:PARENT_OF]->(x{{type:'string'}})
            WHERE x.code =~ '{pii}'
            RETURN n
            """
            result = graph.run(cypher = query).data()
            if result:
                for i in result:
                    varName = concatTree(i['n']['id'])
                    temp_score = Score.variable_score(varName)
                    self.new_finding(
                        node_dict=i['n'],
                        score=temp_score,
                        reason=f"variable '{varName}' of personal types {temp_score.types} is found.",
                    )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")

class PropertyDetector(AbstractDetector):
    

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to catch variable properties that have sensitive names (e.g., $obj->email)

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 10, 15))

    def __find(self):
        pii_list = PersonalDataMatcher.get_pii_list_regex()
        graph = getGraph()
        for pii in pii_list:
            query = f"""
            MATCH (n:AST{{type:'AST_PROP'}})-[:PARENT_OF]->(x{{childnum:1,type:'string'}})
            WHERE x.code =~ '{pii}'
            RETURN n
            """
            result = graph.run(cypher = query).data()
            if result:
                for i in result:
                    varName = concatTree(i['n']['id'])
                    temp_score = Score.variable_score(varName)
                    self.new_finding(
                        node_dict=i['n'],
                        score=temp_score,
                        reason=f"object property '{varName}' of personal types {temp_score.types} is found.",
                    )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")
class ArrayElementDetector(AbstractDetector):
    

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to catch array element that have sensitive names (e.g., $obj['email']). This includes request variables (e.g., $GET['email']).

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 10, 15))

    def __find(self):
        pii_list = PersonalDataMatcher.get_pii_list_regex()
        graph = getGraph()
        for pii in pii_list:
            query = f"""
            MATCH (y:AST{{type:'string'}})<-[:PARENT_OF]-(var:AST{{type:'AST_VAR'}})<-[:PARENT_OF]-(n:AST{{type:'AST_DIM'}})-[:PARENT_OF]->(x{{childnum:1,type:'string'}})
            WHERE x.code =~ '{pii}' AND (y.code = '_POST' OR y.code = '_GET' OR y.code = '_REQUEST')
            RETURN n
            """
            result = graph.run(cypher = query).data()
            if result:
                for i in result:
                    varName = concatTree(i['n']['id'])
                    temp_score = Score.variable_score(varName)
                    self.new_finding(
                        node_dict=i['n'],
                        score=temp_score,
                        reason=f"Request variable '{varName}' of personal types {temp_score.types} is found.",
                    )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")
