from src.preprocessing.general.DeletePreprocessor import DeletePreprocessor

from py2neo import Graph, Node, Relationship
from py2neo.bulk import create_nodes
import pytest


@pytest.fixture(scope='module')
def test_deletepreprocessor_graph(neo4j_service, neo4j_env):
    name = 'testdeletepreprocessor'

    auth = neo4j_env['NEO4J_AUTH'].split('/')
    graph = Graph(neo4j_service, auth=tuple(auth))
    graph.run(f'CREATE DATABASE {name} WAIT')
    yield Graph(neo4j_service, auth=tuple(auth), name=name)

    graph.run(f'DROP DATABASE {name} WAIT')


def test_delete_all_nodes(empty_graph):
    data_foo = [{'filename': 'foo.html'}, {'filename': 'foo.htm'}]
    data_bar = [{'type': 'File'}, {'type': 'File'}]

    create_nodes(empty_graph.auto(), data_foo, labels={'foo'})
    create_nodes(empty_graph.auto(), data_bar, labels={'bar'})

    processor = DeletePreprocessor('delete', )
    processor.process_graph(empty_graph)

    assert 0 == empty_graph.nodes.match().count()


def test_delete_nodes_by_label(empty_graph):
    data_foo = [{'filename': 'foo.html'}, {'filename': 'foo.htm'}]
    data_bar = [{'type': 'File'}, {'type': 'File'}]

    create_nodes(empty_graph.auto(), data_foo, labels={'foo'})
    create_nodes(empty_graph.auto(), data_bar, labels={'bar'})

    processor = DeletePreprocessor('delete', label='foo')
    processor.process_graph(empty_graph)

    assert 0 == empty_graph.nodes.match('foo').count()
    assert 2 == empty_graph.nodes.match('bar').count()
    assert 2 == empty_graph.nodes.match().count()


def test_downstream_nodes_preserved(empty_graph):
    a = Node('a')
    b = Node('b')
    ab = Relationship(a, 'POINTS_TO', b)

    tx = empty_graph.begin()
    tx.create(a)
    tx.create(b)
    tx.create(ab)
    empty_graph.commit(tx)

    processor = DeletePreprocessor('delete', label='a')
    processor.process_graph(empty_graph)

    assert 0 == empty_graph.nodes.match('a').count()
    assert 1 == empty_graph.nodes.match('b').count()
    assert 0 == empty_graph.relationships.match().count()
