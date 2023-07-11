from src.preprocessing.filesystem.FileSystemPreprocessor import FileSystemPreprocessor

from pathlib import Path

TEST_PLUGIN_DIR = Path(
    __file__).resolve().parents[2] / 'test_wp_plugins/filesystem01'
TEST_PLUGIN_DIR2 = Path(
    __file__).resolve().parents[2] / 'test_wp_plugins/filesystem02'


def test_filesystem_graph(empty_graph):
    processor = FileSystemPreprocessor('filesystem', TEST_PLUGIN_DIR)
    processor.process_graph(empty_graph)
    assert 5 == empty_graph.nodes.match('Filesystem').count()

    assert 3 == empty_graph.nodes.match('Filesystem', type='File').count()
    assert 2 == empty_graph.nodes.match('Filesystem', type='Directory').count()
    assert 4 == empty_graph.relationships.match().count()


def test_filesystem_graph2(empty_graph):
    processor = FileSystemPreprocessor('filesystem', TEST_PLUGIN_DIR2)
    processor.process_graph(empty_graph)
    assert 9 == empty_graph.nodes.match('Filesystem').count()

    assert 3 == empty_graph.nodes.match('Filesystem', type='File').count()
    assert 6 == empty_graph.nodes.match('Filesystem', type='Directory').count()
    assert 1 == empty_graph.nodes.match('Filesystem', type='File').where(f'_.filename ENDS WITH "php"').count()
    assert 1 == empty_graph.nodes.match('Filesystem', type='File').where(f'_.filename ENDS WITH "js"').count()
    assert 1 == empty_graph.nodes.match('Filesystem', type='File').where(f'_.filename ENDS WITH "html"').count()
    assert 0 == empty_graph.nodes.match('Filesystem', type='File').where(f'_.filename ENDS WITH "txt"').count()
    assert 0 == empty_graph.nodes.match('Filesystem', type='File').where(f'_.filename ENDS WITH "ttf"').count()
    assert 0 == empty_graph.nodes.match('Filesystem', type='File').where(f'_.filename ENDS WITH "css"').count()


def test_relative_dir_property(empty_graph):
    processor = FileSystemPreprocessor('filesystem', TEST_PLUGIN_DIR)
    processor.process_graph(empty_graph)

    for x in empty_graph.nodes.match('Filesystem'):
        print(x)

    assert 'js/test.js' == empty_graph.nodes.match('Filesystem', filename='test.js').first()['rel_path']

