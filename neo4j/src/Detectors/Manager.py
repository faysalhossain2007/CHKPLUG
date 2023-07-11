# GDPR Checker
# Patrick Thomas pwt5ca
# Created 200528

import os
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import *

import py2neo
import Results
from Settings import ENCRYPTION_PARALLEL, LRU_CACHE_SIZE

# from .ActivationDetectors import *
from .DatabaseDetectors import *
from .DeletionDetectors import *
from .Detectors import SCORE_BOUNDS, WARNING_STR, AbstractDetector
from .PhpDetectors import *
from .RemoteDetectors import *
from .SecurityDetectors import *
from .StorageDetectors import *
from .WP_UserDetector import *
from .UserInputDetector import *
# from .PersonalDataVariableDetector import ArrayElementDetector
from Functions import load_function_info
from Utls import progress_bar


def _detector_sort(x: AbstractDetector) -> str:
    name = type(x).__name__.lower()
    if name.startswith("generic"):
        return f"zzz{name}"
    elif (
        name.startswith("uninstall") or name.startswith("deletion") or name.startswith("activation")
    ):
        return f"zzzz{name}"
    return name


class DetectorManager:

    detector_dict: Dict[str, AbstractDetector] = {}

    def __init__(self, graph: py2neo.Graph, silent: bool = True):
        """Nexus for Security Detectors. Manages running all of them at once as well as provides some useful interfaces for understanding the outputs.

        Args:
            graph (py2neo.Graph): The graph to analyze.
            silent (bool, optional): Whether or not to printout some useful debug information. Defaults to True.
        """
        # if not AbstractDetector.SILENT_INITIALIZATION:
        # print("### Instantiating Detectors")
        self.graph = graph

        # Find all subclasses of the Abstract Detector, remove other Abstract subclasses.
        detector_types_unexplored: List[Type] = [
            detector for detector in AbstractDetector.__subclasses__()
        ]
        detector_types: List[Type] = []
        # Recursively add in sub(sub)*classes
        while detector_types_unexplored:
            d = detector_types_unexplored.pop()
            detector_types_unexplored.extend(d.__subclasses__())
            detector_types.append(d)
        for d in detector_types:
            if d.__name__.startswith("Abstract"):
                detector_types.remove(d)

        # Now instantiate detectors.
        self.detectors: List[AbstractDetector] = [detector(graph) for detector in sorted(detector_types, key=lambda x: x.__name__.lower())]  # type: ignore
        self.detectors.sort(key=_detector_sort)
        self.silent = silent
        # print("### Finished instantiating Detectors")
        # Make a dict with the detectors by name for easier lookup.
        DetectorManager.detector_dict = {type(d).__name__: d for d in self.detectors}

        self.allFindings: Set[AbstractDetector.Finding] = set()
        self.__finding_children_map: Dict[int, Set[Tuple[AbstractDetector.Finding, int]]] = dict()
        self.__parent_finding_map: Dict[int, Set[Tuple[AbstractDetector.Finding, int]]] = dict()

        self.__found: Set[AbstractDetector.Finding] = set()

        #include the steps to fill detector results here to encapsulate the manager module
        # print("### Loading WP function info")
        load_function_info()
        # print("### Finished loading WP function info")


    @staticmethod
    def get_detector(detector_name: str) -> Optional[AbstractDetector]:
        """Lookup an instantiated detector via name.

        Args:
            detector_name (str): Detector's name. This is the same as the class name of the detector.

        Returns:
            Optional[AbstractDetector]: Returns None if the detector couldn't be found. Otherwise returns a Detector.
        """
        return DetectorManager.detector_dict.get(detector_name, None)

    def print_detectors(self):
        """Print all the current detectors to the screen."""
        print("### Detectors:")
        print(
            f"{len(self.detectors)} detectors instantiated: {', '.join([type(detector).__name__ for detector in self.detectors])}"
        )

    def run(self):
        """Run all of the instantiated detectors at once."""

        if ENCRYPTION_PARALLEL:
            # Run detectors in parallel. TPE is used instead of multiprocessing. Use Pool since querying the
            # database is high IO/done in subprocesses (Neo4j itself).
            with ThreadPoolExecutor() as executor:
                [executor.submit(detector.run) for detector in self.detectors]
                [executor.submit(detector.post) for detector in self.detectors]
        else:
            for detector in progress_bar(self.detectors):
                detector.run()
            for detector in self.detectors:
                detector.post(self.detectors)

        self._rebuild_maps()
        if not self.silent:
            self.print_detectors()
            # self.print_results()

    def _rebuild_maps(self):
        # Save all non-generic findings.
        for detector in self.detectors:
            if not type(detector).__name__.startswith("Generic"):
                self.allFindings.update(detector.findings)

        # Filter out duplicated findings between generic and non-generic findings.
        for detector in self.detectors:
            for finding in detector.findings:
                if type(detector).__name__.startswith("Generic"):
                    overlap = [
                        other_finding
                        for other_finding in self.allFindings
                        if other_finding.node["id"] == finding.node["id"]
                    ]
                    if overlap:
                        for overlapping in overlap:
                            if overlapping.score.score_type == finding.score.score_type:
                                detector.findings.remove(finding)
                    else:
                        self.allFindings.add(finding)

        # Now build mappings.
        for finding in self.allFindings:
            finding_id = finding.node["id"]

            # Match all children of the finding and cache those.
            query = f"""
            MATCH p=(finding:AST{{id: {finding_id}}})-[:PARENT_OF*0..]->(child:AST)
            RETURN COLLECT(DISTINCT [child.id, LENGTH(p)])
            """
            results = self.graph.evaluate(query)
            if results:
                for r in results:
                    if not r:
                        continue
                    child_id, parent_child_distance = r
                    l = self.__finding_children_map.get(child_id, set())
                    l.add((finding, parent_child_distance))
                    self.__finding_children_map[child_id] = l

            # Match all parents of the finding and cache those.
            query = f"""
            MATCH p=(parent:AST)-[:PARENT_OF*]->(finding:AST{{id: {finding_id}}})
            RETURN COLLECT(DISTINCT [parent.id, LENGTH(p)])
            """
            results = self.graph.evaluate(query)
            if results:
                for r in results:
                    if not r:
                        continue
                    parent_id, parent_child_distance = r
                    l = self.__parent_finding_map.get(parent_id, set())
                    l.add((finding, parent_child_distance))
                    self.__parent_finding_map[parent_id] = l

    def print_results(self):
        """Print a general summary of the results to the screen."""
        # Tally and report number of passes and fails.
        all_tally = {
            **{key: 0 for key in SCORE_BOUNDS.values()},
            WARNING_STR: 0,
        }  # type: Dict[str, int]
        final_score = 0.0
        final_score_total = 0
        for detector in self.detectors:
            report = detector.report().strip()
            if report != "":
                print(report, "\n")
            tally = detector.tally()
            for key in tally.keys():
                if key not in all_tally.keys():
                    all_tally[key] = tally[key]
                else:
                    all_tally[key] += tally[key]
            score_correct, score_total = detector.score()
            final_score += score_correct
            final_score_total += score_total

    @lru_cache(LRU_CACHE_SIZE)
    def lookup_node_id(self, node_id: int) -> List[AbstractDetector.Finding]:
        """See if a node is associated with some finding. Useful for data flow tracking, as this
        function can be called on some node in a data flow to see if there is an associated finding
        with the node, allowing the data flow tracker to know if the current function/statement
        uses/needs security and whether or not if the function has security.

        Args:
            node_id (int): The node ID from the Neo4J graph.

        Returns:
            List[AbstractDetector.Finding]: Return an empty list if there are no findings that
            use this node. Otherwise return all related findings.
        """

        child_candidates = list(self.__finding_children_map.get(node_id, []))
        child_candidates.sort(key=lambda x: x[1])  # Sort by precedence, ascending
        if child_candidates:
            return [finding for finding, _ in child_candidates]

        parent_candidates = list(self.__parent_finding_map.get(node_id, []))
        parent_candidates.sort(key=lambda x: x[1])  # Sort by precedence, ascending
        if parent_candidates:
            return [parent_candidates[0][0]]

        return []

    def mark_as_found(self, finding: AbstractDetector.Finding):
        """During a traversal of a data flow, mark a node as read/found. Useful for determining if a data flow reaches some security function, helping us know if that node touches personal data or not.

        Args:
            finding (SecurityDetector.Finding): Finding, usually from SecurityDetectorManager.lookup_node_id().
        """
        self.__found.add(finding)


    def get_retrieval_node_ids(self) -> List[int]:
        """Return a list of nodes that are known to retrieve some information stored somewhere on the server.

        Returns:
            List[int]: List of node IDs.
        """
        return [f.node["id"] for f in self.allFindings if f.score.is_retrieval()]

    def get_storage_node_ids(self) -> List[int]:
        """Return a list of nodes that are known to store some information stored somewhere on the server.

        Returns:
            List[int]: List of node IDs.
        """
        return [f.node["id"] for f in self.allFindings if f.score.is_storage()]

    def get_database_node_ids(self) -> List[int]:
        """Return a list of nodes that are known to access databases.

        Returns:
            List[int]: List of node IDs.
        """
        return [f.node["id"] for f in self.allFindings if f.score.is_database()]

    def get_deleted_databases(self) -> List[str]:
        return [
            f.score.categories.get("code", "")
            for f in self.allFindings
            if f.score.is_deletion() and f.score.categories.get("table deletion", False)
        ]

    def write_findings_to_db(self):
        f: AbstractDetector.Finding
        for f in sorted(self.allFindings, key=lambda x: f"{x.parent_name} {x.file} {x.line}"):
            Results.write_plugin_detector_results(
                detector_name=f.parent_name,
                detector_type=f.score.score_type.value,
                file_name=f.file if f.file else "",
                line_number=f.line,
                node_ID=f.node["id"],
                description=f.recommendation,
                cryptography_method=f.score.encryption_method,
                api_endpoint=f.score.categories.get("url", None),
                personal_data=f.score.get_data_types_personal()
            )
