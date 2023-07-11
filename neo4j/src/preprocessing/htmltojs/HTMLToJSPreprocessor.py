from .DataDashStarPreprocessor import DataDashStarPreprocessor
from .SubmitEventNativePreprocessor import SubmitEventNativePreprocessor
from ..Pipeline import Pipeline
from ..Preprocessor import Preprocessor

from py2neo import Graph


class HTMLToJSPreprocessor(Preprocessor):

    def process_graph(self, graph: Graph) -> Graph:
        return self._pipeline.trigger(graph)

    @property
    def processors(self):
        return self._pipeline.processors

    def _register_processors(self):
        ddsp = DataDashStarPreprocessor('data-*processor')
        #senp = SubmitEventNativePreprocessor('submit_event_native_processor')
        #self._pipeline.register(ddsp, senp)
        self._pipeline.register(ddsp)

    def __init__(self, name):
        super().__init__(name)
        self._pipeline = Pipeline()
        self._register_processors()
