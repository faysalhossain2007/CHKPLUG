from NeoGraph import getGraph
from .Detectors import AbstractDetector
from .Scores import Score
from datetime import date
import py2neo
from PersonalData import PersonalDataMatcher

class UserInputDetector(AbstractDetector):

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to catch intialized WP_User objects

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 12, 2))

    def __find(self):
        graph = getGraph()
        query = f"""
        MATCH (n:AST_HTML{{type:'tag',name:'input'}})-[:PARENT_OF]->(attribute_name:AST_HTML{{type:'attribute',name:'name'}})-[:PARENT_OF]->(x:AST_HTML{{type:'string'}})
        OPTIONAL MATCH (form:AST_HTML)-[:PARENT_OF*1..10]->(n)
        OPTIONAL MATCH (n)-[:PARENT_OF]->(attribute_name2:AST_HTML{{type:'attribute',name:'type'}})-[:PARENT_OF]->(x2:AST_HTML{{type:'string'}})
        OPTIONAL MATCH (n)-[:PARENT_OF]->(attribute_name3:AST_HTML{{type:'attribute',name:'value'}})-[:PARENT_OF]->(x3:AST_HTML)
        RETURN n,x,form.id,x2.code,x3
        """
        result = graph.run(cypher = query).data()
        if result:
            for i in result:
                inputNode = i['n']
                inputName = i['x']['code'] if (i['x'] and 'code' in i['x']) else ''
                inputType = i['x2.code']
                inputValue = i['x3']['code'] if (i['x3'] and 'code' in i['x3']) else ''
                # inputValueID = i['x3']['id']
                inputFormID = i['form.id']
                personalDataType = PersonalDataMatcher.determine_category(inputName)
                if personalDataType:
                    self.new_finding(
                        node_dict=inputNode,
                        score=Score.user_input_score(personalDataType,inputName,inputType,inputValue,inputFormID),
                        reason=f"Form input with personal data with input name {inputName} is found.",
                    )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")