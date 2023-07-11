from .Preprocessor import Preprocessor
from py2neo import Graph


class Pipeline:
    def trigger(self, graph: Graph) -> Graph:
        for processor in self._processors:
            graph = processor.preprocess(graph)
        return graph

    def join(self, pipeline):
        self._processors.extend(pipeline.processors)

    def register(self, *processors):
        self._processors.extend(processors)

    @property
    def processors(self):
        return self._processors

    def __init__(self):
        self._processors = []
