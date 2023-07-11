from py2neo import Graph, Node, Relationship
import graphviz

from html import escape
import random


class Dotifier():
    """Render a Neo4j Graph object with graphviz."""

    def dotify(self):
        for label in self._graph.schema.node_labels:
            self._build_subgraph(label)
        self._build_edges()

    def source(self):
        return self._dot.source

    def render(self, view=False):
        self._dot.render(view=view)

    def _build_subgraph(self, name):
        node_attr = {'fillcolor': Dotifier.random_color()}
        with self._dot.subgraph(name=name, node_attr=node_attr) as sg:
            sg.attr(label=name)
            for n in self._graph.nodes.match(name):
                sg.node(str(n.identity), self._label_from_node(n))

    @staticmethod
    def _escape(label):
        escape_chars = ['{', '}']

        elabel = escape(label)
        for c in escape_chars:
            elabel = elabel.replace(c, f'\\{c}')

        return elabel

    def _label_from_node(self, node):
        # NB (nphair): Be careful to escape special characters e.g., '>', '}', '"', etc.
        props = dict(node)

        _node_label = ', '.join(list(node.labels))
        node_label = Dotifier._escape(_node_label)

        _edge_label = ' '.join([f'+ {k}: {v}\\l' for k, v in props.items()])
        edge_label = Dotifier._escape(_edge_label)

        return f'{{ {str(node.identity)} | {node_label} | {edge_label} }}'

    def _build_edges(self):
        for rel in self._graph.relationships.match():
            start_id = str(rel.start_node.identity)
            end_id = str(rel.end_node.identity)
            label = rel.__class__.__name__

            self._dot.edge(start_id, end_id, label, **dict(rel))

    @staticmethod
    def random_color():
        r = random.randint
        return f'#{r(0, 255):02x}{r(0, 255):02x}{r(0, 255):02x}'

    def __init__(self, graph, filename=None):
        node_attr = {'color': 'black', 'style': 'filled', 'shape': 'record'}

        self._graph = graph
        self._dot = graphviz.Digraph(name=graph.name,
                                     filename=filename,
                                     node_attr=node_attr)
