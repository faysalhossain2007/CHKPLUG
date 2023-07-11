import sys

from ..Preprocessor import Preprocessor

from py2neo import Graph, Relationship, Node

from itertools import chain
import re


class SubmitEventNativePreprocessor(Preprocessor):
    """Connect forms to their native js handlers.

    https://www.w3schools.com/jsref/event_onsubmit.asp

    Note, the upstream parsers do not handle inline js. We connect the
    nodes the best we can here.
    """

    ONSUBMIT_JS_REGEX = '"(?s).*\\.onsubmit ?=.*"'
    ELEMENT_BY_ID_REGEX = r'.*getElementById\("(.*)"\).*'

    def process_graph(self, graph: Graph) -> Graph:
        os_html_rels = self.relate_onsubmit_html_nodes(graph)
        os_js_rels = self.relate_onsubmit_js_nodes(graph)

        tx = graph.begin()
        for rel in chain(os_html_rels, os_js_rels):
            tx.create(rel)
        graph.commit(tx)

        return graph

    def relate_onsubmit_html_nodes(self, graph: Graph):
        onsubmit = self._onsubmit_html_nodes(graph)
        rels = [(n, self._matching_onsubmit_attribute_handler(graph, n)) for n in onsubmit]
        return [Relationship(html, 'ACCESSES', js) for html, js in rels]

    def relate_onsubmit_js_nodes(self, graph: Graph):
        """NB: Without support for evaluating expressions we are limited to
        grepping to find the corresponding forms. Pattern matching of this
        kind is fragile, but is the best we can do at this time.
        """
        onsubmit = self._onsubmit_js_nodes(graph)
        rels = [(n, self._matching_onsubmit_js_handler(graph, n)) for n in onsubmit]
        return [Relationship(html, 'ACCESSES', js) for html, js in rels]

    def _extract_form_by_id(self, onsubmit: Node):
        code = onsubmit['code']
        element = code.split('onsubmit')[0]
        if '.getelementbyid' not in element.lower():
            return None

        match = self._element_by_id_regex.match(element)
        return match.group(1)


    def _onsubmit_js_nodes(self, graph: Graph):
        start_node = '(n:AST_HTML {type: "script"})'
        end_node = '(m:AST_HTML {type: "string"})'
        relationship = '[:PARENT_OF]'

        match = f'MATCH {start_node}-{relationship}->{end_node}'
        clause = f'm.code IS NOT NULL AND m.code =~ {SubmitEventNativePreprocessor.ONSUBMIT_JS_REGEX}'
        query = f'{match} WHERE {clause} return m'

        cursor = graph.run(query)
        return [record['m'] for record in cursor]


    def _onsubmit_html_nodes(self, graph: Graph):
        start_node = '(n:AST_HTML {name: "onsubmit", type: "attribute"})'
        end_node = '(m:AST_HTML {type: "string"})'
        relationship = '[:PARENT_OF]'
        cursor = graph.run(f'MATCH {start_node}-{relationship}->{end_node} WHERE m.code IS NOT NULL RETURN m')
        return [record['m'] for record in cursor]

    def _matching_onsubmit_attribute_handler(self, graph: Graph, onsubmit: Node):
        """Given an onsubmit attribute node, find its handler"""
        fs_node = self._filesystem_node(graph, onsubmit)
        script_node = '(n:AST_HTML {type: "script"})'
        any_relationship = '[*0..]'
        ast_relationship = '[:PARENT_OF]'
        ast_node = '(m:AST_HTML {type: "string"})'

        match = f'match {str(fs_node)}-{any_relationship}->{script_node}-{ast_relationship}->{ast_node}'
        clause = f'm.code IS NOT NULL AND m.code CONTAINS "function {onsubmit["code"]}"'
        query = f'{match} WHERE {clause} return m'

        cursor = graph.run(query)
        results = [record['m'] for record in cursor]

        if len(results) > 1:
            print('multiple nodes matched, picking first', file=sys.stderr)
        return results[0]

    def _matching_onsubmit_js_handler(self, graph: Graph, onsubmit: Node):
        """Given an onsubmit attribute node, find its handler"""
        fs_node = self._filesystem_node(graph, onsubmit)
        any_relationship = '[*0..]'
        attr_node = '(n:AST_HTML {type: "attribute"})'
        attr_relationship = '[:PARENT_OF]'
        form_id = self._extract_form_by_id(onsubmit)
        form_node = f'(m:AST_HTML {{code: "{form_id}"}})'

        match = f'match {str(fs_node)}-{any_relationship}->{attr_node}-{attr_relationship}->{form_node}'
        query = f'{match} return m'

        cursor = graph.run(query)
        results = [record['m'] for record in cursor]

        if len(results) > 1:
            print('multiple nodes matched, picking first', file=sys.stderr)
        return results[0]

    def _filesystem_node(self, graph: Graph, node: Node):
        """Given an AST HTML node find its filesystem root node."""
        filesystem_node = '(m:Filesystem)'
        toplevel_node = '(n:AST {type: "AST_TOPLEVEL"})'
        ast_relationship = '[:PARENT_OF*0..]'
        file_relationship = '[:FILE_OF]'
        query = f'match {str(node)}<-{ast_relationship}-{toplevel_node}<-{file_relationship}-{filesystem_node} return m'
        cursor = graph.run(query)
        results = [record['m'] for record in cursor]

        assert len(results) == 1
        return results[0]

    def _script_content_nodes(self, graph: Graph):
        start_node = '(n:AST_HTML {type: "script"})'
        end_node = '(m:AST_HTML {type: "string"})'
        relationship = '[:PARENT_OF]'
        cursor = graph.run(f'MATCH {start_node}-{relationship}->{end_node} WHERE m.code IS NOT NULL RETURN m')
        return [record['m'] for record in cursor]

    def __init__(self, name):
        self._element_by_id_regex = re.compile(SubmitEventNativePreprocessor.ELEMENT_BY_ID_REGEX, re.IGNORECASE | re.DOTALL)
        super().__init__(name)
