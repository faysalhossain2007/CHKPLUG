from src.preprocessing.htmltojs.DataDashStarPreprocessor import DataDashStarPreprocessor
from src.preprocessing.filesystem.FileSystemPreprocessor import FileSystemPreprocessor
from src.preprocessing.html.HTMLPreprocessor import HTMLPreprocessor
from src.preprocessing.Pipeline import Pipeline

from py2neo import Graph
import pytest

from pathlib import Path

TEST_PLUGIN_DIR = Path(__file__).resolve().parents[2] / 'test_wp_plugins/htmljs01'


@pytest.fixture(scope='module')
def test_graph(neo4j_service, neo4j_env):
    name = 'testdatadashstarpreprocessor'

    auth = neo4j_env['NEO4J_AUTH'].split('/')
    graph = Graph(neo4j_service, auth=tuple(auth))
    graph.run(f'CREATE DATABASE {name} WAIT')
    test_graph = Graph(neo4j_service, auth=tuple(auth), name=name)

    # Run processor dependencies.
    pipeline = Pipeline()
    pipeline.register(FileSystemPreprocessor('filesystem', TEST_PLUGIN_DIR), HTMLPreprocessor('htmlpreprocessor'))
    pipeline.trigger(test_graph)
    yield test_graph

    graph.run(f'DROP DATABASE {name} WAIT')


def test_process_graph(test_graph):
    ddsp = DataDashStarPreprocessor('ddsp')
    initial_rel_count = test_graph.relationships.match().count()

    ddsp.process_graph(test_graph)
    expected_rel_count = initial_rel_count + 3
    actual_rel_count = test_graph.relationships.match().count()

    assert expected_rel_count == actual_rel_count


def test_dataset_relationships(test_graph):
    ddsp = DataDashStarPreprocessor('ddsp')
    relationships = ddsp._dataset_relationships(test_graph)
    assert 2 == len(relationships)

    start_height = relationships[0].start_node
    end_height = relationships[0].end_node
    assert 'leaves' in start_height['code']
    assert 'data-leaves' in end_height['name']

    start_leaves = relationships[1].start_node
    end_leaves = relationships[1].end_node
    assert 'plantHeight' in start_leaves['code']
    assert 'data-plant-height' in end_leaves['name']


def test_name_relationships(test_graph):
    ddsp = DataDashStarPreprocessor('ddsp')
    relationships = ddsp._name_relationships(test_graph)

    assert 1 == len(relationships)

    start = relationships[0].start_node
    end = relationships[0].end_node
    assert 'data-fruit' in start['code']
    assert 'data-fruit' in end['name']


def test_attr_to_camelcase():
    input1 = 'data-moe-larry-curly'
    expected1 = 'dataset.moeLarryCurly'
    actual1 = DataDashStarPreprocessor._data_attr_to_dataset_obj(input1)
    assert expected1 == actual1

    input2 = 'data-shemp'
    expected2 = 'dataset.shemp'
    actual2 = DataDashStarPreprocessor._data_attr_to_dataset_obj(input2)
    assert expected2 == actual2

    input3 = 'data-'
    expected3 = ''
    actual3 = DataDashStarPreprocessor._data_attr_to_dataset_obj(input3)
    assert expected3 == actual3
