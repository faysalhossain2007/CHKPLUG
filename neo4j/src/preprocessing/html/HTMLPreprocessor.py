from ..Preprocessor import Preprocessor
from ..utils.NodeIdGenerator import NodeIdGenerator

from Naked.toolshed.shell import muterun_js
from py2neo import Graph, Relationship, Node

from collections import defaultdict
from itertools import chain
from pathlib import Path
import json
import sys

HTML_PARSER = Path(__file__).resolve().parents[2] / 'htmlparser.js'


class HTMLPreprocessor(Preprocessor):
    HTML_REGEX = '"(?i).*\\.html?"'

    def process_graph(self, graph: Graph) -> Graph:
        """Parses HTML files into a subgraph and merges into the current graph.

        First, locates HTML files from the filesystem_new graph. Then, parse these
        files into their own AST_HTML graphs. Lastly, connect to 
        the filesystem_new graph via newly constructed toplevel AST nodes.

        e.g. 
         before: (filesystem)
         after: (filesystem) -> (AST) -> (AST_HTML) -> ...
        """
        fs_html_nodes = self.collect_html_nodes(graph)

        # Build the nodes and their relationships.
        tl_html_nodes = [self._to_ast_toplevel_node(n) for n in fs_html_nodes]
        html_graphs = [self._graph_from_path(n['path']) for n in fs_html_nodes]
        fs_to_tl_rels = self._relate_fs_nodes_to_toplevel_nodes(fs_html_nodes, tl_html_nodes)
        tl_to_graph_rels = self._relate_toplevel_nodes_to_graphs(tl_html_nodes, html_graphs)

        tx = graph.begin()
        for x in chain(tl_html_nodes, *html_graphs, fs_to_tl_rels, tl_to_graph_rels):
            tx.create(x)
        graph.commit(tx)

        return graph

    def collect_html_nodes(self, graph: Graph):
        """Return all of the HTML nodes from the filesystem graph."""
        return graph.nodes.match('Filesystem', type='File').where(f'_.filename =~ {HTMLPreprocessor.HTML_REGEX}')

    def _to_ast_toplevel_node(self, fs_node):
        """Construct a TOPLEVEL AST node from a corresponding filesystem node."""
        return Node('AST',
                    type='AST_TOPLEVEL',
                    endlineno=1,
                    flags='[TOPLEVEL_FILE]',
                    lineno=1,
                    id=NodeIdGenerator.generate_id(),
                    name=fs_node['filename'])

    def _graph_from_path(self, path):
        """Build the graph of an HTML file.

        returns: collection of nodes and relationships in the graph.
        """
        raw_node_map = {node['id']: node for node in self._parse_html(path)}
        raw_rel_map = self._relationship_map(raw_node_map)

        node_map = {k: self._to_ast_html_node(v) for k, v in raw_node_map.items()}
        rels = []
        for pid, children in raw_rel_map.items():
            parent_node = node_map[pid]
            children_nodes = [node_map[child] for child in children]
            rels += self._relate_ast_html_nodes(parent_node, children_nodes)

        return list(node_map.values()) + rels

    def _parse_html(self, path):
        """Parse an HTML file into a json object using htmlparser2 library."""
        response = muterun_js(str(HTML_PARSER), arguments=f'{path} -from_file')
        if response.exitcode != 0:
            print(f'error. failed to parse {path}', file=sys.stderr)
            print(response.stderr, file=sys.stderr)
            return {}

        return json.loads(response.stdout.decode('utf-8'))

    def _to_ast_html_node(self, parsed):
        """Convert a parsed HTML token into an AST_HTML node."""
        return Node(
            'AST_HTML',
            type='string' if parsed.get('type') == 'text' else parsed.get('type'),
            startIndex=parsed.get('startIndex'),
            endIndex=parsed.get('endIndex'),
            code=parsed.get('code'),
            childnum=parsed.get('childnum'),
            name=parsed.get('name'),
            id=NodeIdGenerator.generate_id(),
        )

    def _relationship_map(self, node_map):
        """Map AST HTML nodes to their parents."""
        rel_map = defaultdict(list)
        for node in node_map.values():
            pid = node['parentID']
            if pid == -1:
                continue

            nid = node['id']
            rel_map[pid].append(nid)
        return rel_map

    def _relate_ast_html_nodes(self, parent, children):
        """Build relationships between AST_HTML nodes."""
        return [Relationship(parent, 'PARENT_OF', child) for child in children]

    def _relate_fs_nodes_to_toplevel_nodes(self, fs_nodes, toplevel_nodes):
        """Build relationships between AST nodes and AST_HTML graph roots."""
        assert len(fs_nodes) == len(toplevel_nodes)

        return [Relationship(fs, 'FILE_OF', tl) for fs, tl in zip(fs_nodes, toplevel_nodes)]

    def _relate_toplevel_nodes_to_graphs(self, toplevel_nodes, graphs):
        """Build relationships between AST nodes and AST_HTML graph roots."""
        assert len(toplevel_nodes) == len(graphs)

        return [Relationship(tl, 'PARENT_OF', graph[0]) for tl, graph in zip(toplevel_nodes, graphs)]

    def __init__(self, name):
        super().__init__(name)
