from src.preprocessing.html.HTMLPreprocessor import HTMLPreprocessor
from src.preprocessing.filesystem.FileSystemPreprocessor import FileSystemPreprocessor

from py2neo import Graph
from py2neo.bulk import create_nodes
import pytest

from pathlib import Path

TEST_PLUGIN_DIR = Path(
    __file__).resolve().parents[2] / 'test_wp_plugins/filesystem01'


@pytest.fixture(scope='module')
def test_htmlpreprocessor_graph(neo4j_service, neo4j_env):
    name = 'testhtmlpreprocessor'

    auth = neo4j_env['NEO4J_AUTH'].split('/')
    graph = Graph(neo4j_service, auth=tuple(auth))
    graph.run(f'CREATE DATABASE {name} WAIT')
    yield Graph(neo4j_service, auth=tuple(auth), name=name)

    graph.run(f'DROP DATABASE {name} WAIT')


def test_collect_html_nodes(empty_graph):
    data = [
        {
            'type': 'File',
            'filename': 'foo.html'
        },
        {
            'type': 'File',
            'filename': 'foo.htm'
        },
        {
            'type': 'File',
            'filename': 'foo.hTMl'
        },
        {
            'type': 'File',
            'filename': 'foo.HTML'
        },
    ]

    create_nodes(empty_graph.auto(), data, labels={'Filesystem'})

    processor = HTMLPreprocessor('htmlpreprocessor')
    match = processor.collect_html_nodes(empty_graph)
    assert 4 == match.count()


def test_process_graph(test_htmlpreprocessor_graph):
    fs_processor = FileSystemPreprocessor('filesystem', TEST_PLUGIN_DIR)
    fs_processor.process_graph(test_htmlpreprocessor_graph)

    html_processor = HTMLPreprocessor('htmlpreprocessor')

    # Before processing, expect only 2 FILE_OF relationships (php and js).
    assert 2 == test_htmlpreprocessor_graph.relationships.match(
        node=None, r_type='FILE_OF').count()

    html_processor.process_graph(test_htmlpreprocessor_graph)

    # New FILE_OF relationship for HTML.
    assert 3 == test_htmlpreprocessor_graph.relationships.match(
        node=None, r_type='FILE_OF').count()

    # New AST node for HTML.
    toplevel = test_htmlpreprocessor_graph.nodes.match(
        'AST',
        type='AST_TOPLEVEL',
    ).where(f'_.name =~ {HTMLPreprocessor.HTML_REGEX}')
    assert 1 == toplevel.count()

    assert 0 < test_htmlpreprocessor_graph.nodes.match('AST_HTML').count()
