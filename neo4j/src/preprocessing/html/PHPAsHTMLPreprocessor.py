from ..Preprocessor import Preprocessor
from ..utils.NodeIdGenerator import NodeIdGenerator

from Naked.toolshed.shell import muterun_js
from py2neo import Graph, Relationship, Node, Subgraph

from collections import defaultdict
from pathlib import Path
import json
import sys

HTML_PARSER = Path(__file__).resolve().parents[2] / 'htmlparser.js'


class PHPAsHTMLPreprocessor(Preprocessor):
    PHP_REGEX = '"(?i).*\\.php"'

    def process_graph(self, graph: Graph) -> Graph:
        """Treats PHP files as HTML and parses them as such.

        NB (nphair): This is to be compatible with the previous behavior of HTML parsing.
        NB (nphair): If it sticks around, parsing should be refactored.
        """
        php_nodes = self.collect_php_nodes(graph)

        subgraphs = []
        for php in php_nodes:
            path = self.php_node_to_path(php, graph)
            parsed = self._graph_from_path(path)
            if not parsed:
                continue

            nodes, rels = parsed
            root = next((x for x in nodes if x['type'] == 'root'))
            rel = Relationship(php, 'PARENT_OF', root)
            rels.append(rel)
            subgraphs.append(Subgraph(nodes=nodes, relationships=rels))

        tx = graph.begin()
        for sg in subgraphs:
            tx.create(sg)
        graph.commit(tx)

        return graph

    def collect_php_nodes(self, graph: Graph):
        """Return all of the HTML nodes from the filesystem graph."""
        return graph.nodes.match('AST', type='AST_TOPLEVEL').where(f'_.name =~ {PHPAsHTMLPreprocessor.PHP_REGEX}')

    def php_node_to_path(self, node, graph: Graph):
        return graph.nodes.match('Filesystem', rel_path=node['name']).first()['path']

    def _is_pure_php(self, parsed):
        # NB (nphair): Previous parsing aborted when this condition was met. Keeping for compatibility.
        print(f'file is pure php. not html graph will be made')
        return len(parsed) == 2 and (parsed[1].get('name', None) == '?php' or parsed[1].get('type') == 'text')

    def _is_valid(self, parsed):
        return parsed and not self._is_pure_php(parsed) 
    

    def _graph_from_path(self, path):
        """Build the HTML graph of a PHP file.

        returns: collection of nodes and relationships in the graph.
        """

        parsed = self._parse_html(path)
        if not self._is_valid(parsed):
            return ()

        raw_node_map = {node['id']: node for node in parsed}
        raw_rel_map = self._relationship_map(raw_node_map)

        node_map = {k: self._to_ast_html_node(v) for k, v in raw_node_map.items()}
        rels = []
        for pid, children in raw_rel_map.items():
            parent_node = node_map[pid]
            children_nodes = [node_map[child] for child in children]
            rels += self._relate_ast_html_nodes(parent_node, children_nodes)

        return list(node_map.values()), rels

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

    def __init__(self, name):
        super().__init__(name)
