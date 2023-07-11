from src.preprocessing.Preprocessor import Preprocessor
from src.preprocessing.Pipeline import Pipeline
from py2neo import Graph, NodeMatcher, Node, Relationship
import pytest

class MockPreprocessorA(Preprocessor):
    def process_graph(self, graph: Graph) -> Graph:
        node = Node('MockLabel', name='node_a')
        graph.create(node)
        return graph


class MockPreprocessorB(Preprocessor):
    def process_graph(self, graph: Graph) -> Graph:
        matcher = NodeMatcher(graph)
        a = matcher.match('MockLabel').first()
        b = Node('MockLabel', name='node_b')
        ab = Relationship(a, 'KNOWS', b)
        graph.create(b)
        graph.create(ab)
        return graph


def test_preprocess(empty_graph):
    pipeline = Pipeline()
    processor_a = MockPreprocessorA('mock_a')
    processor_b = MockPreprocessorB('mock_b')
    pipeline.register(processor_a)
    pipeline.register(processor_b)
    graph = pipeline.trigger(empty_graph)

    matcher = NodeMatcher(graph)
    nodes = list(matcher.match('MockLabel'))

    assert len(nodes) == 2
    assert graph.relationships.match().first() is not None

def test_join():
    pipeline_a = Pipeline()
    processor_a1 = MockPreprocessorA('mock_a1')
    processor_a2 = MockPreprocessorA('mock_a2')
    pipeline_a.register(processor_a1)
    pipeline_a.register(processor_a2)

    pipeline_b = Pipeline()
    processor_b1 = MockPreprocessorB('mock_b1')
    processor_b2 = MockPreprocessorB('mock_b2')
    pipeline_b.register(processor_b1)
    pipeline_b.register(processor_b2)

    pipeline_a.join(pipeline_b)

    assert len(pipeline_a.processors) == 4
    assert pipeline_a.processors[0].name == 'mock_a1'
    assert pipeline_a.processors[-1].name == 'mock_b2'
