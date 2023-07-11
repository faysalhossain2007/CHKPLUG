from src.preprocessing.filesystem.FileSystemToAstPreprocessor import FileSystemToAstPreprocessor

from py2neo import Node

from pathlib import Path

TEST_PLUGIN_DIR = Path(
    __file__).resolve().parents[2] / 'test_wp_plugins/filesystem01'


def test_filesystemtoast_graph(empty_graph):
    ast_node = Node('AST', type='AST_TOPLEVEL', name='foobar.txt')
    fs_node = Node('Filesystem', rel_path='foobar.txt', name='foobar.txt')

    tx = empty_graph.begin()
    tx.create(ast_node)
    tx.create(fs_node)
    empty_graph.commit(tx)

    assert 0 == empty_graph.relationships.match().count()
    processor = FileSystemToAstPreprocessor('filesystem')
    processor.process_graph(empty_graph)
    assert 1 == empty_graph.relationships.match().count()
