
from NeoGraph import getGraph
from .Detectors import AbstractDetector
from .Scores import Score
from datetime import date
import py2neo
class ConsentDetector(AbstractDetector):

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to catch intialized WP_User objects

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 12, 3))

    def __find(self):
        graph = getGraph()
        query = f"""
        MATCH (n:AST{{type:'AST_NEW'}})-[:PARENT_OF]->({{childnum:0}})-[:PARENT_OF]->(x{{type:'string'}})
        WHERE x.code in ['WP_User','\WP_User']
        RETURN n
        """
        result = graph.run(cypher = query).data()
        if result:
            for i in result:
                self.new_finding(
                    node_dict=i['n'],
                    score=Score.wp_user_score(concatTree(i['n']['id'])),
                    reason="WP_User object is created.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")