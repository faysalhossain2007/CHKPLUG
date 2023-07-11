# GDPR Checker - Runtime.py
# Patrick Thomas pwt5ca
# Created 201208

from typing import Dict, Optional, Set, List

from NeoGraph import getGraph

from Detectors.Manager import DetectorManager
from Detectors.SecurityDetectors import AbstractDetector

from Args import DATABASE_DIR, DELETION_LOG_FILE, PLUGIN_NAME, PLUGIN_DIR

# Get output file locations from arguments -- very important for batch runs.
# if PLUGIN_NAME:
#     print(f"Plugin name: {PLUGIN_NAME}, https://wordpress.org/plugins/{PLUGIN_NAME}/")

# SECURITY_DETECTOR_MANAGER handles all encryption, hashing, and database usages.
SECURITY_DETECTOR_MANAGER: Optional[DetectorManager] = DetectorManager(getGraph())

# SECURITY_USES is a set of node IDs that are known to fall under some Security Detector Finding.
SECURITY_USES: Set[int] = set()

# SECURITY_MAP_USES_TO_FINDINGS is a map from node ID to a finding.
SECURITY_MAP_USES_TO_FINDINGS: Dict[int, AbstractDetector.Finding] = dict()
