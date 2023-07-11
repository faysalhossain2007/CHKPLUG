from src.visualize.Dotifier import Dotifier

from py2neo import Graph
from py2neo.data import Node, Relationship
import graphviz
import pytest


@pytest.fixture(scope='function')
def test_dotify_graph(empty_graph):
    tx = empty_graph.begin()
    a = Node("Person", name="Alice")
    tx.create(a)
    b = Node("Person", name="Bob")
    tx.create(b)
    ab = Relationship(a, "KNOWS", b)
    tx.create(ab)
    empty_graph.commit(tx)
    return empty_graph


def test_dotify(test_dotify_graph):
    dotifier = Dotifier(test_dotify_graph)
    dotifier.dotify()
    assert dotifier.source()
