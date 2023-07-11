from py2neo import Graph

from Settings import NEO4J_BOLT_CONNECTION_STRING, NEO4J_PASSWORD, NEO4J_USER

global __GRAPH
__GRAPH: Graph = Graph(auth=(NEO4J_USER, NEO4J_PASSWORD), uri=NEO4J_BOLT_CONNECTION_STRING)


def getGraph() -> Graph:
    """Connect to the Neo4j database that contains the AST.

    Returns:
        Graph: Neo4j Graph.
    """
    return __GRAPH
