from ..Preprocessor import Preprocessor

from py2neo import Graph, Relationship

from itertools import chain


class DataDashStarPreprocessor(Preprocessor):
    """Relates HTML5 data-* attributes to the scripts that use them."""

    def process_graph(self, graph: Graph) -> Graph:
        dataset_rels = self._dataset_relationships(graph)
        name_rels = self._name_relationships(graph)

        tx = graph.begin()
        for rel in chain(dataset_rels, name_rels):
            tx.create(rel)
        graph.commit(tx)

        return graph

    def _dataset_relationships(self, graph: Graph):
        """Construct relationships for all attributes accessed by dataset objects."""
        data_attr_nodes = self._data_attr_nodes(graph)
        script_content_nodes = self._script_content_nodes(graph)
        _related = [self._relate_by_dataset(dan, script_content_nodes) for dan in data_attr_nodes]
        related = [r for r in _related if r]
        return list(chain.from_iterable(related))

    def _relate_by_dataset(self, attr_node, script_nodes):
        """Build relationships to script nodes that access attr_node through the dataset property."""
        data_attr = attr_node['name']
        attr = DataDashStarPreprocessor._data_attr_to_dataset_obj(data_attr)
        return [Relationship(sn, 'ACCESSES', attr_node) for sn in script_nodes if attr in sn['code']]

    @staticmethod
    def _data_attr_to_dataset_obj(data_attr):
        attr = data_attr.removeprefix('data-')
        if not attr:
            return ''
        split = attr.split('-')
        capitalized = ''.join(s.capitalize() for s in split[1:])
        return f'dataset.{split[0]}{capitalized}'

    def _name_relationships(self, graph: Graph):
        """Construct relationships for all attributes accessed by name."""
        data_attr_nodes = self._data_attr_nodes(graph)
        script_content_nodes = self._script_content_nodes(graph)
        _related = [self._relate_by_name(dan, script_content_nodes) for dan in data_attr_nodes]
        related = [r for r in _related if r]
        return list(chain.from_iterable(related))

    def _relate_by_name(self, attr_node, script_nodes):
        """Build relationships to script nodes that access attr_node by name."""
        attr = attr_node['name']
        return [Relationship(sn, 'ACCESSES', attr_node) for sn in script_nodes if attr in sn['code']]

    def _script_content_nodes(self, graph: Graph):
        start_node = '(n:AST_HTML {type: "script"})'
        end_node = '(m:AST_HTML {type: "string"})'
        relationship = '[:PARENT_OF]'
        cursor = graph.run(f'MATCH {start_node}-{relationship}->{end_node} WHERE m.code IS NOT NULL RETURN m')
        return [record['m'] for record in cursor]

    def _data_attr_nodes(self, graph: Graph):
        return self._attr_nodes(graph).where('_.name STARTS WITH "data-"')

    def _attr_nodes(self, graph: Graph):
        return graph.nodes.match('AST_HTML', type='attribute')

    def __init__(self, name):
        super().__init__(name)
