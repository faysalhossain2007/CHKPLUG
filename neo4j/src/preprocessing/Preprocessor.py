from .PreprocessorInvocationRecord import PreprocessorInvocationRecord
from py2neo import Graph

from abc import ABC, abstractmethod


class Preprocessor(ABC):

    @abstractmethod
    def process_graph(self, graph: Graph) -> Graph:
        pass

    def preprocess(self, graph: Graph) -> Graph:
        print(f'starting {self.name} processor')
        invocation_record = PreprocessorInvocationRecord()
        invocation_record.log_start()
        g = self.process_graph(graph)
        invocation_record.log_end()
        print(f'{self.name} has completed in {invocation_record.runtime()} milliseconds')
        self.history.append(invocation_record)
        return g

    def __init__(self, name):
        self.name = name
        self.history = []


