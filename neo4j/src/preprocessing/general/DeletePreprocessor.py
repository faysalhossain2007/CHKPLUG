from ..Preprocessor import Preprocessor

from py2neo import Graph


class DeletePreprocessor(Preprocessor):
    """General purpose processor to delete nodes."""

    def process_graph(self, graph: Graph) -> Graph:
        # NB (nphair): currently, only deleting by label is supported.
        self._delete_nodes_by_label(graph)
        return graph

    def _delete_nodes_by_label(self, graph: Graph) -> Graph:
        match_clause = f'(a:{self._label})' if self._label else '(a)'
        print(f'match clause is {match_clause}')
        graph.run(f'MATCH {match_clause} DETACH DELETE a')

    def __init__(self, name, label=None):
        super().__init__(name)
        self._label = label
