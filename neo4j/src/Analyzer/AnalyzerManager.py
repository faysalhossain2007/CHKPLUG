from typing import Dict,List,Type,Set

from .ComplianceFinding import ComplianceFinding
from .Analyzer import AbstractAnalyzer
from concurrent.futures import ThreadPoolExecutor

from .DeletionAnalyzer import *
from .AccessAnalyzer import *
from .ThirdPartyAnalyzer import *
from .EncryptionAnalyzer import *


class AnalyzerManager:

    detector_dict: Dict[str, AbstractAnalyzer] = {}

    def __init__(self):
        """Nexus for Analyzers. Manages running all of them at once as well as provides some useful interfaces for understanding the outputs.
        """
        print("### Instantiating Analyzers for GDPR laws")

        # Find all subclasses of the Abstract Analyzer, remove other Abstract subclasses.
        analyzer_types_unexplored: List[Type] = [
            analyzer for analyzer in AbstractAnalyzer.__subclasses__()
        ]
        analyzer_types: List[Type] = []
        # Recursively add in sub(sub)*classes
        while analyzer_types_unexplored:
            d = analyzer_types_unexplored.pop()
            analyzer_types_unexplored.extend(d.__subclasses__())
            analyzer_types.append(d)
        for d in analyzer_types:
            if d.__name__.startswith("Abstract"):
                analyzer_types.remove(d)

        # Now instantiate analyzers.
        self.analyzers: List[AbstractAnalyzer] = [analyzer() for analyzer in analyzer_types]
        print("### Finished instantiating Analyzers")

        self.allFindings: Set[ComplianceFinding] = set()
        self.__run()
    def __run(self):
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(detector.run) for detector in self.analyzers]
            for f in futures:
                self.allFindings.update(f.result())