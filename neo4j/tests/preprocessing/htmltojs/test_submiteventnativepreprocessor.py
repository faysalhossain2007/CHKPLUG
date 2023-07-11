from src.preprocessing.htmltojs.SubmitEventNativePreprocessor import SubmitEventNativePreprocessor
from src.preprocessing.filesystem.FileSystemPreprocessor import FileSystemPreprocessor
from src.preprocessing.html.HTMLPreprocessor import HTMLPreprocessor
from src.preprocessing.Pipeline import Pipeline

from py2neo import Graph
import pytest

from pathlib import Path

TEST_PLUGIN_DIR = Path(__file__).resolve().parents[2] / 'test_wp_plugins/htmljs02'


@pytest.fixture(scope='module')
def test_graph(neo4j_service, neo4j_env):
    name = 'testsubmiteventnativepreprocessor'

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
    senp = SubmitEventNativePreprocessor('senp')

    initial_rel_count = test_graph.relationships.match().count()
    senp.process_graph(test_graph)
    expected_rel_count = initial_rel_count + 2
    actual_rel_count = test_graph.relationships.match().count()

    assert expected_rel_count == actual_rel_count


def test_relate_onsubmit_html_nodes(test_graph):
    senp = SubmitEventNativePreprocessor('senp')
    rels = senp.relate_onsubmit_html_nodes(test_graph)

    assert len(rels) == 1


def test_relate_onsubmit_js_nodes(test_graph):
    senp = SubmitEventNativePreprocessor('senp')
    rels = senp.relate_onsubmit_js_nodes(test_graph)

    assert len(rels) == 1
