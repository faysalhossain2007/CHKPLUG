from src.preprocessing.Preprocessor import Preprocessor
from py2neo import Graph
import pytest

class MockPreprocessor(Preprocessor):
    def process_graph(self, graph: Graph) -> Graph:
        return graph

def test_preprocess():
    processor = MockPreprocessor('mock')
    processor.preprocess(None)
    processor.preprocess(None)

    assert processor.name == 'mock'
    assert len(processor.history) == 2
    assert processor.history[0].runtime() > 0



