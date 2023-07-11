# GDPR Checker - SourcesSinks.py
# Patrick Thomas pwt5ca
# Created 210316

from typing import Any, List, Set, Tuple

from Detectors.Runtime import SECURITY_DETECTOR_MANAGER
from Errors import DetectorManagerUninitializedException, SourceDetectorException
from NeoGraph import getGraph
from SQLParser import SQLParentNodeOperations
from SourceDetector import SourceDetector


class SourceSinkManager:
    def __init__(self, include_sourcedetector: bool = True):
        if not SECURITY_DETECTOR_MANAGER:
            raise DetectorManagerUninitializedException()

        self.__sinks: Set[int] = set()
        self.__sources: Set[int] = set()
        #this var stores the nodes that are considered as sensitive
        self.__personal: Set[int] = set()

        # Get sources and sinks from the detector manager.
        for finding in SECURITY_DETECTOR_MANAGER.allFindings:
            if finding.score.is_source():
                self.__sources.add(finding.node["id"])
            elif finding.score.is_sink():
                # Assuming that this is also not a retrieval node.
                self.__sinks.add(finding.node["id"])

        # Now databases.
        for parent_id, ops in SQLParentNodeOperations.items():
            if "AST_SQL_SELECT" in ops:
                self.__sources.add(parent_id)
            if "AST_SQL_INSERT" in ops or "AST_SQL_UPDATE" in ops:
                self.__sinks.add(parent_id)

        # Now for SourceDetector if needed.
        if include_sourcedetector:
            all_sources = list(SourceDetector.sourceLocators.keys())
            all_sources.append("")  # Add action sources.
            for source in all_sources:
                try:
                    sources = SourceDetector.locateSource(source)
                    for datanode in sources:
                        self.__sources.add(datanode.id)
                except SourceDetectorException as e:
                    print(f"""Error getting sources for "{source}": {e}""")

    def get_sinks(self) -> Set[int]:
        """Get the set of sinks of the plugin.

        Returns:
            Set[int]: A set of all sinks.
        """
        return self.__sinks

    def get_sources(self) -> Set[int]:
        """Get a set of all sources of the plugin.

        Returns:
            Set[int]: A set of all sources.
        """
        return self.__sources

    def filter_datanodes(self, datanodes: list) -> Tuple[list, list]:
        """Filter a list of datanodes into a list of sources and a list of sinks.

        Args:
            datanodes (list): List of DataNode objects.

        Returns:
            Tuple[list, list]: (List of sources, list of sinks)
        """
        filtered_sources: List[Any] = [dn.id for dn in datanodes if dn.id in self.get_sources()]
        filtered_sinks: List[Any] = [dn.id for dn in datanodes if dn.id in self.get_sinks()]
        return (filtered_sources, filtered_sinks)

    def add_labels_to_database(self) -> Tuple[int, int]:
        """Add SINK and SOURCE labels to the database.

        Returns:
            Tuple[int, int]: Count of sources and sinks added, respectively.
        """

        graph = getGraph()
        query = f"""
        UNWIND [{', '.join([str(i) for i in self.__sources])}] as x
        MATCH (n:AST{{id:x}})
        SET n :SOURCE
        SET n.source_root = n.id
        // WITH n
        // OPTIONAL MATCH (n)-[:PARENT_OF*]->(m:AST)
        // SET m :SOURCE
        // SET m.source_root = n.id
        RETURN COUNT(n) // + COUNT(m)
        """
        result = graph.evaluate(query)
        source_count = int(result) if result else 0

        query = f"""
        UNWIND [{', '.join([str(i) for i in self.__sinks])}] as x
        MATCH (n:AST{{id:x}})
        SET n :SINK
        SET n.sink_root = n.id
        // WITH n
        // OPTIONAL MATCH (n)-[:PARENT_OF*]->(m:AST)
        // SET m :SINK
        // SET m.sink_root = n.id
        RETURN COUNT(n) // + COUNT(m)
        """
        result = graph.evaluate(query)
        sink_count = int(result) if result else 0

        return (int(source_count), int(sink_count))
