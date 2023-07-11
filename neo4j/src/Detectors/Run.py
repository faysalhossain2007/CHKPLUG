# GDPR Checker - Run.py
# Patrick Thomas pwt5ca
# Created 201208

from Args import handleArgs
from py2neo import Graph

from .Detectors import AbstractDetector
from .Manager import DetectorManager


def runEncryption(graph: Graph) -> DetectorManager:
    """Run the security detectors.

    run expects all of the nodes and edges for a program to already be loaded.
    """
    batchresults, _, plugin_name, plugin_dir = handleArgs()

    AbstractDetector.SILENT_INITIALIZATION = False
    manager = DetectorManager(graph, silent=False)

    manager.run()
    manager.write_findings_to_db()

    return manager
