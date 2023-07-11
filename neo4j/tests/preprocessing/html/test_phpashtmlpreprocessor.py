from src.preprocessing.html.PHPAsHTMLPreprocessor import PHPAsHTMLPreprocessor
from src.preprocessing.filesystem.FileSystemPreprocessor import FileSystemPreprocessor

from py2neo import Graph, Node, Relationship
from py2neo.bulk import create_nodes
import pytest

from pathlib import Path

TEST_PLUGIN_DIR = Path(
    __file__).resolve().parents[2] / 'test_wp_plugins/filesystem01'


@pytest.fixture(scope='module')
def test_phpashtmlpreprocessor_graph(neo4j_service, neo4j_env):
    name = 'testphpashtmlpreprocessor'

    auth = neo4j_env['NEO4J_AUTH'].split('/')
    graph = Graph(neo4j_service, auth=tuple(auth))
    graph.run(f'CREATE DATABASE {name} WAIT')
    yield Graph(neo4j_service, auth=tuple(auth), name=name)

    graph.run(f'DROP DATABASE {name} WAIT')


def test_collect_php_nodes(empty_graph):
    data = [
        {
            'type': 'AST_TOPLEVEL',
            'name': 'foo.php'
        },
        {
            'type': 'AST_TOPLEVEL',
            'name': 'foo.pHp'
        },
        {
            'type': 'AST_TOPLEVEL',
            'name': 'foo.PHP'
        },
    ]

    create_nodes(empty_graph.auto(), data, labels={'AST'})

    processor = PHPAsHTMLPreprocessor('phpashtmlpreprocessor')
    match = processor.collect_php_nodes(empty_graph)
    assert 3 == match.count()


def test_process_graph(test_phpashtmlpreprocessor_graph):
    fs_processor = FileSystemPreprocessor('filesystem', TEST_PLUGIN_DIR)
    fs_processor.process_graph(test_phpashtmlpreprocessor_graph)

    # Seed with the AST node upstream navex would produce.
    ast_node = Node('AST', name='test.php', type='AST_TOPLEVEL')
    fs_node = test_phpashtmlpreprocessor_graph.nodes.match('Filesystem', rel_path='test.php').first()
    fs_to_ast = Relationship(fs_node, 'FILE_OF', ast_node)
    tx = test_phpashtmlpreprocessor_graph.begin()
    tx.create(ast_node)
    tx.create(fs_node)
    tx.create(fs_to_ast)
    test_phpashtmlpreprocessor_graph.commit(tx)

    processor = PHPAsHTMLPreprocessor('phpashtmlpreprocessor')
    processor.process_graph(test_phpashtmlpreprocessor_graph)

    cursor = test_phpashtmlpreprocessor_graph.run('MATCH (ast:AST) --> (ast_html:AST_HTML) RETURN ast_html')
    assert 1 == len(list(cursor))
