from dataclasses import dataclass
from distutils.command import check
from functools import partial
from re import T
from typing import Dict, Iterable, List, Set, Tuple
from js2py import require

from numpy import isin

#from DataFlows import DataNode
from Detectors.Runtime import SECURITY_DETECTOR_MANAGER,PLUGIN_NAME
from Detectors.Scores import ScoreType
from Errors import DetectorManagerUninitializedException
from PersonalData import PersonalDataMatcher
from Results import write_path_analyzer_decision, write_path_analyzer_log_row
from NeoGraph import getGraph
from AdminAccessChecker import isNodeAdmin
from PathAnalyzerHelper import *
from ActionHook import checkWPDataDeletionHook,checkWPDataAccessHook,getInvokedFnID,getWPExportedData
from DataFlowTracking import allTraversalType,hasDataflowPath
import pandas as pd
from Detectors.Utils import get_node_filename
from DataFlows import DataFlowPath
from ControlFlowTracking import ControlFlowTracking
from NeoHelper import getNode,isUrlValid
from ValueResolver import evaluateExpression
import os

# from Settings import ROOT_DIR


WP_USER_STORAGE_FUNCTIONS = ['wp_set_password','wp_create_user','wpmu_create_user','wp_insert_user','wp_update_user','edit_user']

@dataclass
class PathAnalyzerLog:
    stage: str
    description: str
    level: int
    node_id: int

    def log_to_str(self) -> str:
        #print full path if it is tainted as PII and has sources
        # graph = getGraph()
        # query = f"""
        # MATCH (n:PERSONAL{{id:{self.node_id}}})
        # RETURN n.sources
        # """
        # result = graph.evaluate(query)
        # returned_str = f"""[{self.stage}.{self.node_id}.{self.level}] {self.description} \n"""
        returned_str = f"""[{self.stage}] {self.description} \n"""

        #Uncomment the below code block to print out data flow and control flow paths
        # if result:
        #     returned_str+=" Dataflow paths:\n"
        #     for source in result:
        #         if source!=self.node_id:
        #             query = f"""
        #             MATCH (n:PERSONAL{{id:{self.node_id}}}),(m{{id:{source}}}),
        #             p = shortestPath((m)-[{allTraversalType()}*]->(n))
        #             UNWIND nodes(p) AS ns
        #             RETURN ns
        #             """
        #             # print(query)
        #             pathResult = graph.run(cypher = query).data()
        #             if pathResult:
                        
        #                 nodeIDs = []
        #                 nodeTypes = []
        #                 files = []
        #                 linenos = []
        #                 for n in pathResult:
        #                     nodeID = n['ns']['id']
        #                     nodeType = n['ns']['type']
        #                     file = get_node_filename(graph,nodeID)
        #                     lineno = n['ns']["lineno"] if "lineno" in n['ns'] else 0

        #                     nodeIDs.append(nodeID)
        #                     nodeTypes.append(nodeType)
        #                     files.append(file)
        #                     linenos.append(lineno)
        #                 returned_str+="-"*5+f"Data Flow Path from {source} to {self.node_id}"+"-"*5+"\n"
        #                 temp_df = pd.DataFrame({'nodeID':nodeIDs,'nodeType':nodeTypes,'file':files,'lineno':linenos})
        #                 returned_str+=temp_df.to_string()
        #                 returned_str+="\n"

        #                 path = [n['ns']['id'] for n in pathResult]
        #                 path = DataFlowPath(pathList=path)
        #                 controlflowPaths = ControlFlowTracking.trackControlFlow(path)
        #                 returned_str+="-"*5+f"Control Flow Path from {source} to {self.node_id}"+"-"*5+"\n"
        #                 for p in controlflowPaths:
        #                     returned_str+=str(p)
        #                     returned_str+="\n"


        return returned_str

def find_api_calls() -> Set[str]:
    """Find all URLs that are called with remote requests.

    Returns:
            Set[str]: Set of URLs called.
    """
    urls: Set[str] = set()
    if SECURITY_DETECTOR_MANAGER:
        for finding in SECURITY_DETECTOR_MANAGER.allFindings:
            score = finding.score
            if score.score_type == ScoreType.API:
                url = score.categories.get("url", "")
                if url:
                    urls.add(url)
    return urls

class PathAnalyzer:
    """Analyze a list of data flow paths for GDPR violations.

    Raises:
        DetectorManagerUninitializedException: When the global security detector manager is not initialized.
    """

    DELETION_REQUIREMENT_MAP: Dict[int, str] = dict()
    DELETION_REQUIREMENT_UNNEEDED = 0
    DELETION_REQUIREMENT_WP = 1
    DELETION_REQUIREMENT_REQUIRED = 2
    DELETION_REQUIREMENT_REQUIRED_AND_IMPOSSIBLE = 3

    HAS_DELETION_MAP: Dict[int, str] = dict()
    HAS_DELETION_NONE = 0
    HAS_DELETION_NONE_BUT_NOT_REQUIRED = 1
    HAS_DELETION_ADMIN = 2
    HAS_DELETION_PUBLIC = 3

    REQUIRES_ACCESS_MAP: Dict[int, str] = dict()
    REQUIRES_ACCESS_UNNEEDED = 0
    REQUIRES_ACCESS_OPTIONAL = 1
    REQUIRES_ACCESS_REQUIRED = 2
    REQUIRES_ACCESS_REQUIRED_AND_IMPOSSIBLE = 3

    HAS_ACCESS_MAP: Dict[int, str] = dict()
    HAS_ACCESS_NONE = 0
    HAS_ACCESS_NONE_BUT_NOT_REQUIRED = 1
    HAS_ACCESS_ADMIN = 2
    HAS_ACCESS_PUBLIC = 3

    HAS_STORAGE_MAP: Dict[int, str] = dict()
    HAS_STORAGE_NONE = 0
    HAS_STORAGE_WP = 1
    HAS_STORAGE_CUSTOM = 2
    HAS_STORAGE_CUSTOM_UNSTRUCTURED = 3

    THIRD_PARTY_MAP: Dict[int, str] = dict()
    THIRD_PARTY_NONE = 0
    THIRD_PARTY_UNKNOWN = 1
    THIRD_PARTY_CONFIRMED = 2

    def __init__(self, topic: str = "") -> None:
        """Initialize the path analyzer and start analyzing the passed in path list.

        Args:
            path_list (List[List[DataNode]]): List of data flow paths to analyze.
        """
        
        self.log: List[PathAnalyzerLog] = list()
        self.violations: Dict[str, bool] = {}
        self.topic = topic
        self.findings = None
        self.need_access_fix = False
        self.need_deletion_fix = False
        self.need_policy_fix = False
        self.analyzePaths()
        
    def analyzePaths(self):
        self.log = list()
        
        self.need_policy_fix = not self.hasPrivacyPolicy()
        
        self.report_log("main", f"Found at least one personal data usage in the plugin. Analyzing the plugin.", 0, 0)
        hasRetrieval = self.hasPIIRetrieval()
        hasUserInput = self.hasUserInput()
        FALSE_POSITIVE_ALARM = False

        hasStorage = self.hasStorage()

        # requires_deletion = self.requiresDeletion()
        # requires_access = self.requiresAccess()
        #if there's storage of personal data, check for data access and data deletion methods
        if hasStorage[0]>0:
            # self.report_log(
            #     "main",
            #     f"Deletion is required of level {self.DELETION_REQUIREMENT_MAP[requires_deletion[0]]} for types {requires_deletion[1]}; looking for deletion interfaces.",
            #     0,
            #     0,
            # )
            self.findings = hasStorage[1]
            has_deletion_result = self.hasDeletion(hasStorage[1])
            self.violations["deletion"] = bool(has_deletion_result==0)

            has_access_result = self.hasAccess(hasStorage[1])
            self.violations["access"] = bool(has_access_result==0)
        

        #check for third party violations
        third_party = self.hasThirdParty()
        self.violations["third_party"] = third_party > 1

        #check for encryption violations.
        has_encryption = self.hasEncryption()
        self.violations["encryption"] = has_encryption>0

        # If a plugin requires consent, look for consent interfaces.
        #requires_consent = self.requiresConsent()
        # if requires_consent and requires_consent[0] > 0:
        #     has_consent_result = self.hasConsent()
        #     self.violations["consent"] = bool(has_consent_result[1])
            
        
        


        self.report_log(
            "main",
            f"Applicable GDPR requirements: {sorted(self.violations.keys()) if self.violations else None}",
            0,
            0,
        )
        for compliance_area, is_violation in self.violations.items():
            if is_violation and not (hasRetrieval or hasUserInput):
                FALSE_POSITIVE_ALARM = True
            self.report_log("main", f"Is {compliance_area} in violation? {is_violation}", 0, 0)
            write_path_analyzer_decision(self.topic, compliance_area, not is_violation)
        if FALSE_POSITIVE_ALARM:
            self.report_log("main", f"!ALARM!: this violation might be false positive. No retrieval or user input of PII is found (no valid source).", 0, 0)
        # else:
        #     self.report_log("main", f"Found no personal data in the plugin. No analysis needed.", 0, 0)
        self.report_log(
            "main",
            f"Complaint? {not self.violations or not any(self.violations.values())}",
            0,
            0,
        )
        return self.log, self.violations

    def hasThirdParty(self) -> Tuple[int, List[str]]:
        """
        Returns 0 - 2:

        - 0: No API calls that send personal data are found or known.
        - 1: At least one API call found but URL/endpoint is unknown. OR API call is known and URL is third-party, but plugin discloses third-party sharing in privacy policy.
        - 2: API call is known, and URL is third-party. No disclosure is found in privacy policy.
        """
        log = partial(self.report_log, "third_party")

        graph = getGraph()
        
        results = set()
        results.add(0)
        pii_types = set()
        ffs = [
            f
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if ScoreType.API == f.score.score_type
        ]
        
        policy_pii_categories = getThirdPartyDataTypeFromPolicy() if not self.need_policy_fix else None
        for f in ffs:
            personalTypes = getPersonalTypes(f.node['id'])
            if personalTypes:
                requirement = 0
                url = f.score.categories.get("url", [])
                isThirdParty = f.score.categories.get("is_third_party",True)
                sources = getSources(f.node['id'])
                for u in url:
                    pii_types.update(personalTypes)
                    if isThirdParty:

                        if not policy_pii_categories:
                            #if there's no privacy policy, then sending data to third party is a violation.
                            requirement = 2
                        else:
                            #check if there's some pii sent to third party that is not disclosed in privacy policy
                            has_disclosure_in_privacy_policy = True
                            for t in personalTypes:
                                if t not in policy_pii_categories:
                                    has_disclosure_in_privacy_policy = False
                                    break
                            if has_disclosure_in_privacy_policy:
                                requirement = 1
                            else:
                                #if there's some data sent to third party not disclosed in privacy policy, it's a violation.
                                requirement = 2
                            pass
                    else:
                        requirement = 1

                    results.add(requirement)
                    log(
                        f"""Third party at "{u}" used with data types {personalTypes}, found in file {f.file} at line {f.line} . Personal data flows from sources with nodeID {sources} """,
                        requirement,
                        f.node['id'],
                        types=personalTypes,
                    )
        #     #as of now, we still record the unknown API calls to evaluate whether it contains personal data
        #     else:
        #         requirement = 1
        #         results.add(requirement)
        #         log(
        #             f"""Third party at "{url}" used with unknown data types, found in file {f.file} at line {f.line}.""",
        #             requirement,
        #             f.node['id'],
        #             types=[],
        #         )

        self.report_log_requirement(
            "third_party",
            f"""Third party usage is {self.THIRD_PARTY_MAP[max(results)]} for data types {sorted(pii_types)}""",
        )
        return max(results)
    
    def hasEncryption(self):
        """
        Returns 0 - 2:

        - 0: Encryption is ideal or there's no need for encryption
        - 1: Encryption can be improved.
        - 2: Encryption is not safe.
        """
        log = partial(self.report_log, "encryption")

        results = set()
        results.add(0)
        
        #search for storage nodes and check encryption. Note that storage nodes contain database storage and api nodes.
        ffs = [
            f
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if f.score.is_storage()
        ]
       
        
        for f in ffs:
            personalTypes = getPersonalTypes(f.node['id'])
            if personalTypes:
                requirement = 0
                encryptionInfo = getEncryption(f.node['id'])
                encryptionScore = 0
                encryptionMethod = []

                
                
                if encryptionInfo:
                    encryptionScore = encryptionInfo[0]
                    encryptionMethod = encryptionInfo[1]
                #handle case in which the finding is an api call
                if f.score.score_type==ScoreType.API:
                    url = f.score.categories.get("url", [])
                    if url:
                        for u in url:
                            if (u.startswith("https://") or "https" in encryptionMethod) and encryptionScore==1:
                                requirement = 0
                                log(
                                    f"""API call that sends PII to "{u}" uses https. PII is securely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line} """,
                                    requirement,
                                    f.node['id'],
                                )
                            elif (u.startswith("https://") or "https" in encryptionMethod) and encryptionScore==0:
                                requirement = 1
                                log(
                                    f"""API call that sends PII to "{u}" uses https. PII is insecurely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                    requirement,
                                    f.node['id'],
                                )
                            elif u.startswith("http://") and encryptionScore==1:
                                requirement = 1
                                log(
                                    f"""API call that sends PII to "{u}" uses http. PII is securely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                    requirement,
                                    f.node['id'],
                                )
                            elif u.startswith("http://") and encryptionScore==0:
                                requirement = 2
                                log(
                                    f"""API call that sends PII to "{u}" uses http. PII is insecurely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                    requirement,
                                    f.node['id'],
                                )
                            elif encryptionScore==1:
                                requirement = 1
                                log(
                                    f"""API call that sends PII to "{u}" uses unknown protocol. PII is securely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                    requirement,
                                    f.node['id'],
                                )
                            elif isUrlValid(u):
                                requirement = 2
                                log(
                                    f"""API call that sends PII to "{u}" uses unknown protocol. PII is insecurely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                    requirement,
                                    f.node['id'],
                                )
                            else:
                                #adjusted the default score to compliant in case url cannot be statically determined (not enough evidence of incompliance).
                                requirement = 1
                                log(
                                    f"""API call that sends PII to unknown url "{u}" which cannot be resolved correctly. PII is insecurely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                    requirement,
                                    f.node['id'],
                                )
                        results.add(requirement)
                    else:
                        if "https" in encryptionMethod and encryptionScore==1:
                            requirement = 0
                            log(
                                f"""API call that sends PII to unknown url uses https. PII is securely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line} """,
                                requirement,
                                f.node['id'],
                            )
                        elif encryptionScore==1:
                            requirement = 1
                            log(
                                f"""API call that sends PII to unknown url. PII is securely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                requirement,
                                f.node['id'],
                            )
                        else:
                            #adjusted the default score to compliant in case url cannot be statically determined (not enough evidence of incompliance). 
                            requirement = 1
                            log(
                                f"""API call that sends PII to unknown url. PII is insecurely encrypted with {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                                requirement,
                                f.node['id'],
                            )

                        results.add(requirement)
                # No longer consider violations in storage, as the encryption can be globally set in a separate setting file.
                # else:
                #     if "password" in personalTypes and encryptionScore==0:
                #         requirement=2
                #         log(
                #             f"""Storage of data types {personalTypes} with insecure encryption methods: {encryptionMethod}. Includes unsafe storage of password. Found in file {f.file} at line {f.line}""",
                #             requirement,
                #             f.node['id'],
                #         )
                #     elif encryptionScore==0:
                #         requirement=1
                #         log(
                #             f"""Storage of data types {personalTypes} with insecure encryption methods: {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                #             requirement,
                #             f.node['id'],
                #         )
                #     else:
                #         requirement=0
                #         log(
                #             f"""Storage of data types {personalTypes} with secure encryption methods: {encryptionMethod}. Found in file {f.file} at line {f.line}""",
                #             requirement,
                #             f.node['id'],
                #         )
                #     results.add(requirement)
        return max(results)

    def hasDeletion(self, required_deletion_list) -> Tuple[int, List[str]]:
        """Determine if the plugin as a whole has the required deletion methods.

        Requirements are determined via requireDeletion.

        -   0: no deletion method and firmly required
        -   1: no deletiion method, but not required (Edit: Wordpress storage functions still need data deletion)
        -   2: has deletion method, but only available to admin
        -   3: has deletion method, available to public

        Args:
            path_list (List[List[DataNode]]): List of a list of DataNodes from data flow tracking.
            deletion_requirement (int): Level of deletion required via requireDeletion.
            required_data_list (List[str]): List of strings, where each is the name of a table or data type that needs to be deleted or deleted from.

        Returns:
            int: See description above.
        """
        log = partial(self.report_log, "Art.17, Right to erasure")
        access_level = {self.HAS_DELETION_NONE_BUT_NOT_REQUIRED}
        if not SECURITY_DETECTOR_MANAGER:
            raise DetectorManagerUninitializedException()


        wp_deletion_hook = checkWPDataDeletionHook()
        wp_deletion_invoked_fns = set()
        if wp_deletion_hook is not None:
            # if isinstance(wp_deletion_hook,int):
                
            #     file = get_node_filename(getGraph(), wp_deletion_hook)
            #     node = getNode(wp_deletion_hook)
            #     line = node["lineno"] if "lineno" in node else 0
            #     log(
            #         f"Data deletion is provided and interfaced to WP through 'wp_privacy_personal_data_erasers'. Deletion method found in file {file} at line {line}.",
            #         self.HAS_DELETION_ADMIN,
            #         wp_deletion_hook,
            #         types=[],
            #     )
            #     access_level.add(self.HAS_DELETION_ADMIN)
            # else:
            for i in wp_deletion_hook:
                wp_deletion_invoked_fns.update(getInvokedFnID(i,[]))
                file = get_node_filename(getGraph(), i)
                node = getNode(i)
                line = node["lineno"] if "lineno" in node else 0
                log(
                    f"Data deletion is provided and interfaced to WP through 'wp_privacy_personal_data_erasers'. Deletion method found in file {file} at line {line}.",
                    self.HAS_DELETION_ADMIN,
                    i,
                    types=[],
                )
                access_level.add(self.HAS_DELETION_ADMIN)
        else:
            self.need_deletion_fix = True
            #if the Wordpress deletion interface is not used, then it's a violation (we already checked that there's storage of PII)
            access_level.add(self.HAS_DELETION_NONE)
        
        for r in required_deletion_list:
            requirement = r[0]
            finding = r[1]
            personalTypes = getPersonalTypes(finding.node['id'])
            # Immediate violation if we determine that some data is not retrievable.
            # if requirement == self.HAS_STORAGE_CUSTOM_UNSTRUCTURED:
            #     print(
            #         "Data Deletion violation! The plugin has storage node that has no identifier and cannot be accessed!"
            #     )
            #     log(
            #         f"Complete data deletion is required for storage at node ID {finding.node['id']} , but is impossible due to custom storage of PII without identifiers. Found in file {finding.file} at line {finding.line}",
            #         self.HAS_DELETION_NONE,
            #         finding.node["id"],
            #         types=personalTypes,
            #     )
            #     access_level.add(self.HAS_DELETION_NONE)
            if requirement == self.HAS_STORAGE_CUSTOM:
                if finding.score.is_database():
                    table_name = finding.score.categories.get("table_name", None)
                    if table_name:
                        deletionFinding = findDeletionOfTable(table_name)
                        hasRecordDeletion = False
                        record_deletion_findings = deletionFinding[0]
                        hasTableDrop = False
                        table_drop_findings = deletionFinding[1]
                        for record_deletion in record_deletion_findings:
                            if not record_deletion.node.get('funcid',-1) in wp_deletion_invoked_fns:
                                continue
                            hasRecordDeletion = True
                            isAdmin = isNodeAdmin(record_deletion.node['id'])
                            if isAdmin:
                                access_level.add(self.HAS_DELETION_ADMIN)
                                log(
                                    f'Admin interface to delete record from table "{table_name}". Found in file {record_deletion.file} at line {record_deletion.line}',
                                    self.HAS_DELETION_ADMIN,
                                    finding.node["id"],
                                    types=personalTypes,
                                )
                            else:
                                access_level.add(self.HAS_DELETION_PUBLIC)
                                log(
                                    f'Public interface to delete record from table "{table_name}". Found in file {record_deletion.file} at line {record_deletion.line}',
                                    self.HAS_DELETION_PUBLIC,
                                    finding.node["id"],
                                    types=personalTypes,
                                )
                        if not hasRecordDeletion:
                            log(
                                f'No deletion method to delete record from table "{table_name}".',
                                self.HAS_DELETION_NONE_BUT_NOT_REQUIRED,
                                finding.node["id"],
                                types=personalTypes,
                            )
                        
                        for table_drop in table_drop_findings:
                            if not table_drop.node.get('funcid',-1) in wp_deletion_invoked_fns:
                                continue
                            hasTableDrop = True
                            isAdmin = isNodeAdmin(table_drop.node['id'])
                            if isAdmin:
                                access_level.add(self.HAS_DELETION_ADMIN)
                                log(
                                    f'Admin interface to drop table "{table_name}". Found in file {table_drop.file} at line {table_drop.line}',
                                    self.HAS_DELETION_ADMIN,
                                    finding.node["id"],
                                    types=personalTypes,
                                )
                            else:
                                access_level.add(self.HAS_DELETION_PUBLIC)
                                log(
                                    f'Public interface to drop table "{table_name}". Found in file {table_drop.file} at line {table_drop.line}',
                                    self.HAS_DELETION_PUBLIC,
                                    finding.node["id"],
                                    types=personalTypes,
                                )
                        if not hasTableDrop:
                            log(
                                f'No deletion method to drop table "{table_name}".',
                                self.HAS_DELETION_NONE_BUT_NOT_REQUIRED,
                                finding.node["id"],
                                types=personalTypes,
                            )
                        #only a violation if there's no option to either drop or delete from table
                        if not (hasRecordDeletion or hasTableDrop):
                            access_level.add(self.HAS_DELETION_NONE)
                            log(
                                f"Data deletion is required for custom database storage at node ID {finding.node['id']} , but no deletion method is found. Found in file {finding.file} at line {finding.line}",
                                self.HAS_DELETION_NONE,
                                finding.node["id"],
                                types=personalTypes,
                            )
                    else:
                        log(
                            f'Table name of database operation on PII cannot be analyzed correctly. Check operation to see if there is data deletion violation. Found in file {finding.file} at line {finding.line}.',
                            0,
                            finding.node["id"],
                            types=personalTypes,
                        )
                    

                
            elif requirement == self.HAS_STORAGE_WP:
                #for wordpress storage methods, find corresponding deletion method of the same key
                deletionFinding = findDeletionOfWPFn(finding)
                if not deletionFinding:
                    log(
                        f'Wordpress storage of PII through {finding.code} does not have corresponding deletion method. Storage method found in file {finding.file} at line {finding.line}.',
                            self.HAS_DELETION_NONE,
                            finding.node["id"],
                            types=personalTypes,
                    )
                    access_level.add(self.HAS_DELETION_NONE)
                else:
                    for f in deletionFinding:
                        #check if the deletion function is in the deletion function or in a function the deletion function calls (the deletion function is hooked to wordpress)
                        if not f.node.get('funcid',-1) in wp_deletion_invoked_fns:
                            continue
                        isAdmin = isNodeAdmin(f.node['id'])
                        access_level.add(self.HAS_DELETION_ADMIN if isAdmin else self.HAS_DELETION_PUBLIC)
                        log(
                            f'Wordpress storage of PII through {finding.code} has deletion method {f.code}. Storage method found in file {finding.file} at line {finding.line}. Deletion method found in file {f.file} at line {f.line}.',
                                self.HAS_DELETION_ADMIN if isAdmin else self.HAS_DELETION_PUBLIC,
                                finding.node["id"],
                                types=personalTypes,
                        )
                        #this case no longer affects compliance, as we only check deletion method interfaced to wordpress.
                        # else:
                        #     isAdmin = isNodeAdmin(f.node['id'])
                            
                        #     access_level.add(self.HAS_DELETION_ADMIN if isAdmin else self.HAS_DELETION_PUBLIC)
                        #     log(
                        #         f'Wordpress storage of PII through {finding.code} has deletion method {f.code}, but the deletion method is not interfaced to Wordpress\'s privacy tool. Storage method found in file {finding.file} at line {finding.line}. Deletion method found in file {f.file} at line {f.line}.',
                        #             self.HAS_DELETION_ADMIN if isAdmin else self.HAS_DELETION_PUBLIC,
                        #             finding.node["id"],
                        #             types=personalTypes,
                        #     )
        
        
            
            # Look for all paths with deletion calls on similar data types as that in the data_list.
            

            # for path_index, path in enumerate(self.path_list):
            #     for node in path:
            #         # Assert the format is as expected.
            #         assert isinstance(node, DataNode)

            #         findings = node.getAllFindings()
            #         for finding in findings:
            #             # Add more context to the violation.
            #             if finding.score.score_type == ScoreType.DELETION:
            #                 table_name = finding.score.categories.get("table_name", None)
            #                 operations: List[str] = finding.score.categories.get("operations", None)
            #                 # Operations contains with "AST_SQL_INSERT" or "AST_SQL_UPDATE", so if operations
            #                 # is not empty, then the DB operation is inserting or updating information.
            #                 if table_name and operations:
            #                     deleted_data_list_tables.append(table_name)
            #                     level: int = (
            #                         self.HAS_DELETION_ADMIN if node.admin else self.HAS_DELETION_PUBLIC
            #                     )
            #                     access_level.add(level)

            #                     log(
            #                         f"{'Admin' if node.admin else 'Public'} deletion interface available for SQL table \"{table_name}\".",
            #                         level,
            #                         node.id,
            #                         types=[table_name],
            #                     )

            # If there are more types left, look outside of the data flows.


            # deleted_data_list_functions: List[str] = []
            # #if len(types_remaining) > 0:
            # deletion_detector = SECURITY_DETECTOR_MANAGER.get_detector("DeletionDetector")
            # if deletion_detector:
            #     for finding in deletion_detector.findings:
            #         function_name = finding.get_call_name()
            #         is_wordpress: bool = finding.score.categories.get("wordpress", False)
            #         is_database: bool = finding.score.categories.get("database", False)
            #         is_drop: bool = finding.score.categories.get("drop", False)

            #         if is_wordpress:
            #             # Register a call to a WordPress deletion function (like delete_user_meta)
            #             # Get a list of applicable deletion methods for the PII type.
            #             data_types = finding.score.get_data_types_personal()
            #             data_key_names: List[str] = finding.score.categories.get("keys", [])

            #             if data_types or data_key_names:
            #                 # Only register the result if it adds to the analysis.
            #                 access_level.add(isNodeAdmin(finding.node['id']))
            #                 deleted_data_list_functions.extend(data_types)
            #                 deleted_data_list_functions.extend(data_key_names)
            #                 log(
            #                     f"Admin deletion interface for data types {data_types} "
            #                     f'available via call to "{function_name}".',
            #                     isNodeAdmin(finding.node['id']),
            #                     finding.node["id"],
            #                     types=data_types,
            #                 )
            #         elif is_database and is_drop:
            #             # Register a table's name as dropped.
            #             table_name = finding.score.categories.get("code", None)
            #             if table_name:
            #                 deleted_data_list_functions.append(table_name)
            #             access_level.add(isNodeAdmin(finding.node['id']))

            #             log(
            #                 f'Admin interface to drop table "{table_name}".',
            #                 isNodeAdmin(finding.node['id']),
            #                 finding.node["id"],
            #                 types=[table_name],
            #             )
            #         elif is_database and not is_drop:
            #             # Register a table as deleted from.
            #             table_name = finding.score.categories.get("code", None)
            #             if table_name:
            #                 deleted_data_list_functions.append(table_name)
            #             access_level.add(isNodeAdmin(finding.node['id']))

            #             log(
            #                 f'Admin interface to delete from table "{table_name}".',
            #                 isNodeAdmin(finding.node['id']),
            #                 finding.node["id"],
            #                 types=[table_name],
            #             )

        requirement = min(access_level)
        #satisfaction = max(access_level)
            # types_remaining = types_remaining.difference(deleted_data_list_functions)

        self.report_log_requirement(
            "Art.17, Right to erasure",
            f"""Deletion access is {self.HAS_DELETION_MAP[requirement]}""",
        )

        return requirement

    #deprecated
    def requiresAccess(self):
        """Returns if the plugin requires to satisfy GDPR data access requirement
        0: no need at all
        1: should need it, but is not strict violation to not satisfy it
        2: must need it
        3: access method needed but cannot be done. violation
        """
        has_user_input = self.hasUserInput()[0]
        storage = self.hasStorage()[0]
        if storage == self.HAS_STORAGE_CUSTOM_UNSTRUCTURED:
            return (self.REQUIRES_ACCESS_REQUIRED_AND_IMPOSSIBLE, [])
        elif has_user_input and (storage == self.HAS_STORAGE_CUSTOM):
            return (self.REQUIRES_ACCESS_REQUIRED, [])
        elif has_user_input and storage == self.HAS_STORAGE_WP:
            return (self.REQUIRES_ACCESS_OPTIONAL, [])
        elif storage == self.HAS_STORAGE_NONE:
            return (self.REQUIRES_ACCESS_UNNEEDED, [])
        elif not has_user_input and storage == self.HAS_STORAGE_CUSTOM:
            return (self.REQUIRES_ACCESS_REQUIRED, [])
        elif not has_user_input and storage == self.HAS_STORAGE_WP:
            return (self.REQUIRES_ACCESS_UNNEEDED, [])

    def hasAccess(self, required_access_list):
        """Returns if the plugin has data access method for certain personal data
        0: no access method
        1: has access method, but only available to admin
        2: has access method, available to public
        """
        log = partial(self.report_log, "Art.15, Right to access")
        access_level = {self.HAS_ACCESS_NONE_BUT_NOT_REQUIRED}
        if not SECURITY_DETECTOR_MANAGER:
            raise DetectorManagerUninitializedException()
        has_custom = False
        wp_access_hook = checkWPDataAccessHook()
        exportDataIDs = set()
        if wp_access_hook is not None:
            # if isinstance(wp_access_hook,int):
            #     file = get_node_filename(getGraph(), wp_access_hook)
            #     node = getNode(wp_access_hook)
            #     line = node["lineno"] if "lineno" in node else 0
            #     log(
            #         f"Data access is provided and interfaced to WP through 'wp_privacy_personal_data_exporters'. Deletion method found in file {file} at line {line}.",
            #         self.HAS_ACCESS_ADMIN,
            #         wp_access_hook,
            #         types=[],
            #     )
            #     access_level.add(self.HAS_DELETION_ADMIN)
            # else:
            for i in wp_access_hook:
                exportDataIDs.update(getWPExportedData(i))
                node = getNode(i)
                file = get_node_filename(getGraph(), i)
                line = node["lineno"] if "lineno" in node else 0
                log(
                    f"Data access is provided and interfaced to WP through 'wp_privacy_personal_data_exporters'. Deletion method found in file {file} at line {line}.",
                    self.HAS_ACCESS_ADMIN,
                    i,
                    types=[],
                )
                access_level.add(self.HAS_DELETION_ADMIN)


        # elif has_custom:
        #     self.need_access_fix = True
        #     log(
        #         f"Complete data access is required due to presence of custom storage, but no access method hooked to wordpress is found.",
        #         self.HAS_ACCESS_NONE,
        #         -1,
        #         types=[],
        #     )
        #     access_level.add(self.HAS_ACCESS_NONE)
        
        


        for r in required_access_list:
            requirement = r[0]
            finding = r[1]
            
            personalTypes = getPersonalTypes(finding.node['id'])
            # Immediate violation if we determine that some data is not retrievable.
            # if requirement == self.HAS_STORAGE_CUSTOM_UNSTRUCTURED:
                
            #     log(
            #         f"Complete data access is required for storage at node ID {finding.node['id']} , but is impossible due to custom storage of PII without identifiers. Found in file {finding.file} at line {finding.line}",
            #         self.HAS_DELETION_NONE,
            #         -1,
            #         types=personalTypes,
            #     )
            #     access_level.add(self.HAS_ACCESS_NONE)
            if requirement == self.HAS_STORAGE_CUSTOM:
                has_custom = True
                if finding.score.is_database():
                    #check if there's retrieval of the data and if it flows to the wp exporter sink
                    table_name = finding.score.categories.get("table_name", None)
                    if not table_name:
                        log(
                            f'Table name of database operation on PII cannot be analyzed correctly. Check operation to see if there is data deletion violation. Found in file {finding.file} at line {finding.line}.',
                            0,
                            finding.node["id"],
                            types=personalTypes,
                        )
                    retrievalFindings = findRetrievalOfTable(table_name)
                    if not retrievalFindings:
                        #if there is no retrieval of the stored data, then it's a violation (no data can be exported without being retrieved first)
                        access_level.add(self.HAS_ACCESS_NONE)
                        log(
                            f"Data access is required for custom storage at node ID {finding.node['id']}, but no access is found. Found in file {finding.file} at line {finding.line}",
                            self.HAS_ACCESS_NONE,
                            finding.node["id"],
                            types=personalTypes,
                        )
                        continue
                    hasFlowToExportedResult = None
                    for retrieval in retrievalFindings:
                        for exportData in exportDataIDs:
                            nodeID = retrieval.node['id']
                            if hasDataflowPath(nodeID,exportData):
                                hasFlowToExportedResult = retrieval
                                break
                        if hasFlowToExportedResult is not None:
                            break
                    if hasFlowToExportedResult is not None:
                        #this is the case if we can find a data retrieval that flows to the WP exporter interface (compliant)
                        access_level.add(self.HAS_ACCESS_ADMIN)
                        log(
                            f"Data access is required for custom storage at node ID {finding.node['id']}. Data is properly provided to WP exporter. Export data found in file {retrieval.file} at line {retrieval.line}",
                            self.HAS_ACCESS_ADMIN,
                            finding.node["id"],
                            types=personalTypes,
                        )
                    else:
                        #this is the case if we cannot find any retrieval of data that flows to the WP exporter interface, or if the plugin does not use the WP exporter interface.
                        access_level.add(self.HAS_ACCESS_NONE)
                        log(
                            f"Data access is required for custom storage at node ID {finding.node['id']}, but no access is found. Found in file {finding.file} at line {finding.line}",
                            self.HAS_ACCESS_NONE,
                            finding.node["id"],
                            types=personalTypes,
                        )

                
            elif requirement == self.HAS_STORAGE_WP:
                #for wordpress storage methods, the data access is not strictly required
                access_level.add(self.HAS_DELETION_NONE_BUT_NOT_REQUIRED)
                log(
                    f"Data access is not strictly required for wordpress storage at node ID {finding.node['id']}. Found in file {finding.file} at line {finding.line}",
                    self.HAS_ACCESS_NONE_BUT_NOT_REQUIRED,
                    finding.node["id"],
                    types=personalTypes,
                )
        
        if has_custom and not wp_access_hook:
            self.need_access_fix = True
            
        requirement = min(access_level)
        #satisfaction = max(access_level)
            # types_remaining = types_remaining.difference(deleted_data_list_functions)

        self.report_log_requirement(
            "Art.15, Right to access",
            f"""Data access is {self.HAS_ACCESS_MAP[requirement]}""",
        )

        return requirement

    def requiresConsent(self):
        """Returns if the plugin requires to satisfy GDPR consent requirement
        0: no need at all
        1: must need it
        """
        return self.hasUserInput()

    def hasConsent(self):
        """Returns if the plugin 1) has consent for each user input 2) uses the consent for such data
        0: does not collect consent or use consent
        1: collect consent but not use consent
        2: collect consent and use consent
        """
        return (-1, [])

    def hasPrivacyPolicy(self):
        """Returns if the plugin provides the privacy policy according to the Wordpress guideline: https://developer.wordpress.org/plugins/privacy/suggesting-text-for-the-site-privacy-policy/
        also collects privacy text
        """
        #first clean up the current policy text if there's any
        if os.path.exists(os.path.join(OUTPUT_PATH, f'html_policies')):
            os.remove(os.path.join(OUTPUT_PATH, f'html_policies'))
        if os.path.exists(os.path.join(OUTPUT_PATH2, f'plaintext_policies')):
            os.remove(os.path.join(OUTPUT_PATH2, f'plaintext_policies'))

        graph = getGraph()
        call_name = 'wp_add_privacy_policy_content'
        query = f"""
        MATCH (n:AST{{type:'AST_CALL'}})-[:PARENT_OF*..2]->(call_name:AST{{code:'{call_name}'}})
        MATCH (n)-[:PARENT_OF]->(:AST{{type:'AST_ARG_LIST'}})-[:PARENT_OF]->(privacy_text:AST{{childnum:1}})
        RETURN privacy_text.id
        """
        result = graph.evaluate(cypher=query)
        if result:
            #resolve the privacy text and save it to the output folder, in a txt file named <plugin name>_privacy_text.txt
            privacy_text = evaluateExpression(result)[0]
            privacy_text_file_dir = os.path.join(OUTPUT_PATH, f'html_policies')
            with open(privacy_text_file_dir, 'w') as txtfile:
                txtfile.write(privacy_text)
            return True
        return False

    def hasUserInput(self):
        """Returns if there are user inputs for personal data
        0: no input
        1: has input for personal data
        Also return data list
        """
        ffs = [
            f
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if f.score.is_input() and f.score.is_personal()
        ]
        if ffs:
            return (1,ffs)
        return (0,None)
    def hasPIIRetrieval(self):
        """Returns if there are retrieval of user data for personal data
        0: no data retrieval
        1: has data retrieval for personal data
        Also return data list
        """
        ffs = [
            f
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if f.score.is_retrieval() and f.score.is_personal()
        ]
        if ffs:
            return (1,ffs)
        return (0,None)
    def hasStorage(self) -> Tuple[int, List[str]]:
        """Returns 0-2
        0: no storage at all for personal data
        1: store in db through wp store
        2: store in db through other custom functions
        3: store in db with no data identifier
        Also return data list for storage

        Methodology:
        0: No storage at all. Trivial to find.
        1: Look for if the data is saved through the WordPressStorageDetector detector.
        2: Look for if the data is saved through any database query/statement. Could end
            up catching some queries that might go into 3, but assume that databases are
            used with a minimal amount of proficiency.
        3: Look for if data is saved through direct file writes/to logs. Could also fall into 2 though.
        """

        storage_levels: Set[int] = {self.HAS_STORAGE_NONE}
        storage_findings = []
        #need to remove findings that are part of deletion detector
        deletionID = [
            f.node["id"]
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if ScoreType.DELETION == f.score.score_type
        ]
        ffs = [
            f
            for f in SECURITY_DETECTOR_MANAGER.allFindings
            if f.score.is_storage() and not (ScoreType.API == f.score.score_type or f.node["id"] in deletionID)
        ]
        for finding in ffs:
            personalTypes = getPersonalTypes(finding.node['id'])
            if personalTypes:
                # TODO: Should transit be included?
                detector_name = type(finding.parent).__name__
                storage_requirement = self.HAS_STORAGE_NONE
                function_name = finding.get_call_name()
                node_id = finding.node["id"]
                
                # calls.append(finding.node["code"])
                if detector_name == "WordPressStorageDetector":
                    # Filter the data again for personal information-like types, like user.
                    # function_data_types = finding.score.get_data_types_personal()

                    #if the storage is operated on wp_user table, then there's no need for deletion
                    if function_name in WP_USER_STORAGE_FUNCTIONS:
                        storage_requirement = self.HAS_STORAGE_NONE
                        self.report_log(
                            "has_storage",
                            f"""WP User info of types ({personalTypes}) stored through WordPress function "{finding.code}", found in file {finding.file} at line {finding.line}.""",
                            self.HAS_STORAGE_NONE,
                            node_id,
                        )
                    else:
                        # Look for most well-defined case, WordPress storage usages.
                        storage_requirement = self.HAS_STORAGE_WP
                        self.report_log(
                            "has_storage",
                            f"""PII of types ({personalTypes}) stored through WordPress function "{finding.code}", found in file {finding.file} at line {finding.line}.""",
                            self.HAS_STORAGE_WP,
                            node_id,
                        )
                elif detector_name == "PHPStorageDetector":
                    # Now look for unstructured direct writes to files.
                    # Specifically, it includes keywords = ["fwrite", "file_put_contents"]
                    storage_requirement = self.HAS_STORAGE_CUSTOM_UNSTRUCTURED
                    self.report_log(
                        "has_storage",
                        f"""Unstructured data storage of PII types ({personalTypes}) to files through function "{function_name}", found in file {finding.file} at line {finding.line}.""",
                        self.HAS_STORAGE_CUSTOM_UNSTRUCTURED,
                        node_id,
                    )
                elif finding.score.is_database():
                    storage_requirement = self.HAS_STORAGE_CUSTOM
                    table_name = finding.score.categories.get("table_name", None)
                    self.report_log(
                        "has_storage",
                        f"""PII of types ({personalTypes}) stored through custom database storage into table "{table_name}" through "{function_name}", found in file {finding.file} at line {finding.line}.""",
                        self.HAS_STORAGE_CUSTOM,
                        node_id,
                    )
                else:
                    # Assume the rest are in 2, since this group encompasses all of the custom storage functions
                    # (database usages, etc.)
                    # Not WP or Generic Storage means that it includes all direct database queries (execute, query, etc.)
                    storage_requirement = self.HAS_STORAGE_CUSTOM
                    self.report_log(
                        "has_storage",
                        f"""PII of types ({personalTypes}) stored through custom means, like direct database access, through "{function_name}", found in file {finding.file} at line {finding.line}.""",
                        self.HAS_STORAGE_CUSTOM,
                        node_id,
                    )
                storage_levels.add(storage_requirement)
                storage_findings.append((storage_requirement,finding))
       

        requirement = max(storage_levels)

        self.report_log_requirement(
            "has_storage",
            f"""Storage check is {self.HAS_STORAGE_MAP[requirement]}""",
        )

        return (requirement, storage_findings)

    def report_log(
        self,
        stage: str,
        description: str,
        level: int,
        node_id: int,
        types: Iterable[str] = [],
        skip_duplications: bool = True,
    ):
        output = PathAnalyzerLog(stage, description, level, node_id)
        if not (skip_duplications and output in self.log):
            self.log.append(output)
            write_path_analyzer_log_row(
                self.topic, len(self.log), stage, node_id, level, description, types
            )

    def print_last_log_entry(self):
        if self.log:
            print(self.log[-1].log_to_str())

    def report_log_requirement(self, stage: str, description: str, skip_duplications: bool = True):
        self.report_log(stage, description, 0, 0, [], skip_duplications)

class FixReport:
    def __init__(self,finding) -> None:
        """Initialize the fix report and start generating ways to comply with GDPR by following Wordpress' guidelines
        """
        data_list,table_list = FixReport.getDataListAndTableList(finding)
        #wp_data_list: information of user data stored using wordpress functions. Passed in the format of: [(<data type>,<key>),...]
        self.wp_data_list = data_list
        #table_list: list of custom database tables where user data needs to be deleted.
        self.table_list = table_list

    def getDataListAndTableList(findings):
        """
        From the list of findings, get the list of wordpress data stored and database tables
        """
        table_list = set()
        data_list = set()
        for r in findings:
            requirement = r[0]
            finding = r[1]
            
            if requirement == PathAnalyzer.HAS_STORAGE_CUSTOM:
                if finding.score.is_database():
                    table_name = finding.score.categories.get("table_name", None)
                    if table_name:
                        table_list.add(table_name)
            elif requirement == PathAnalyzer.HAS_STORAGE_WP:
                keyValue = finding.keyValue
                # print(finding)
                # print(finding.function_annotation.data_type)
                if finding.function_annotation.data_type:
                    data_type = list(finding.function_annotation.data_type)[0] #get the first type of the data_type's frozen set.
                    data_list.add((data_type,keyValue))
        return list(data_list),list(table_list)

    def generateDeletionReport(self):
        """Generate a guide to comply with deletion law, along with auto-generated sample code.

        """

        handbook_url = "https://developer.wordpress.org/plugins/privacy/adding-the-personal-data-eraser-to-your-plugin/"

        filter = f"""
add_filter( 'wp_privacy_personal_data_erasers', '{PLUGIN_NAME}_register_privacy_erasers' );
        """

        register = f"""
/**
* Registers all data erasers.
*
* @param array $exporters
*
* @return mixed
*/
function {PLUGIN_NAME}_register_privacy_erasers( $erasers ) {{
    $erasers['my-plugin-slug'] = array(
        'eraser_friendly_name' => __( '<eraser name>', '{PLUGIN_NAME}' ),
        'callback'             => '{PLUGIN_NAME}_remove_data',
    );
    return $erasers;
}}
        """

        wp_data_list = self.wp_data_list
        wordpress_function_deletion_code = f"""
    //TODO: Delete the user data that was stored using Wordpress functions

    //Below is the sample code for deleting user meta and may need to be modified to suit the plugin.
    $user_id = get_user_by('email', $email_address)
    $key = 'email' //Sample user meta key
    if ( $customer->user_id > 0 ) {{
        //Delete user meta data by $key
        delete_user_meta( $user_id, $key );
    }}
        """ if wp_data_list else ''

        table_list = self.table_list

        database_deletion_code = f"""
    //TODO: Delete user data from custom database tables created by the plugin.

    //Below is the sample code for deleting data and may need to be modified to suit the plugin.
    global $wpdb;
    $user_data_table = '{table_list[0].replace('$','')}';
    $delete_data = $wpdb->query( "DELETE FROM {{$user_data_table}} WHERE user_email = {{$email_address}}" );
        """ if table_list else ''

        function = f"""
/**
* Removes all collected data of a user.
*
* @param string $email_address   email address to manipulate
* @param int    $page            pagination
*
* @return array
*/
function {PLUGIN_NAME}_remove_data( $email_address, $page = 1 ) {{
    
    $page = (int) $page;

{wordpress_function_deletion_code}

{database_deletion_code}

    // Tell core if we have more data to delete still
    $done = true;
    return array(
        'items_removed'  => $items_removed, // true if collected data of a user is being deleted
        'items_retained' => $items_retained, // true if certain data needs to be retained
        'messages'       => sprintf( __( 'Data of user with email %s successfully deleted.', '{PLUGIN_NAME}' ), $email_address ), // Put messages for data removal
        'done'           => $done, // true if all the removal processes are done (all data of the user is removed)
    );
}}
        """

        fix_report = f"""
This report suggests fixes to comply with the GDPR Art. 17, Right to erasure (https://gdpr-info.eu/art-17-gdpr/). The report
is based on guidelines provided by Wordpress. Refer to {handbook_url} for more details.

1) Implement a function that deletes all the user data collected in the plugin. Sample code:

{function}

2) Hook the deletion function to the Wordpress's Personal Data Removal tool

{register}
{filter}

        """

        return fix_report

    def generateAccessReport(self):
        """Generate a guide to comply with data access law, along with auto-generated sample code.

        """
        handbook_url = 'https://developer.wordpress.org/plugins/privacy/adding-the-personal-data-exporter-to-your-plugin/'

        filter = f"""
add_filter( 'wp_privacy_personal_data_exporters', '{PLUGIN_NAME}_register_user_data_exporter' );
        """

        register = f"""
/**
* Registers all data exporters.
*
* @param array $exporters
*
* @return mixed
*/
function {PLUGIN_NAME}_register_user_data_exporter( $exporters ) {{
    $exporters['my-plugin-slug'] = array(
    'exporter_friendly_name' => __( '<exporter name>', '{PLUGIN_NAME}' ),
    'callback'               => '{PLUGIN_NAME}_exporter',
    );
    return $exporters;
}}
        """

        wp_data_list = self.wp_data_list
        wordpress_function_access_code = f"""
    //TODO: Export user data that was stored using Wordpress functions. Refer to the sample code below to see how the retrieved data can be exported.
        """ if wp_data_list else ''

        table_list = self.table_list

        database_access_code = f"""
    //TODO: Export the user data from custom database tables created by the plugin. Refer to the sample code below to see how the retrieved data can be exported.
        """ if table_list else ''

        function = f"""
/**
* Export all collected data of a user.
*
* @param string $email_address   email address to manipulate
* @param int    $page            pagination
*
* @return array
*/
function {PLUGIN_NAME}_exporter( $email_address, $page = 1 ) {{
    
    $page = (int) $page;

{wordpress_function_access_code}

{database_access_code}

    //Below is example code adapated from the Wordpress's guidelines for exporting user data.

    $user = get_user_by( 'email', $email_address );
    $key = 'address' 
    $user_data = get_usermeta($user_id,$key) //example retrieval of user data

    // Most item IDs should look like postType-postID. If you don't have a post, comment or other ID to work with,
    // use a unique value to avoid having this item's export combined in the final report with other items
    // of the same id.
    $item_id = "comment-{{$comment->comment_ID}}";

    // Core group IDs include 'comments', 'posts', etc. But you can add your own group IDs as needed
    $group_id = 'comments';

    // Optional group label. Core provides these for core groups. If you define your own group, the first
    // exporter to include a label will be used as the group label in the final exported report.
    $group_label = __( 'Comments', '{PLUGIN_NAME}' );

    // Plugins can add as many items in the item data array as they want.
    $data = array(
        array(
            'name'  => __( '<name of user data>', '{PLUGIN_NAME}' ),
            'value' => $user_data,
        ),
    );

    $export_items[] = array(
        'group_id'    => $group_id,
        'group_label' => $group_label,
        'item_id'     => $item_id,
        'data'        => $data,
    );
    // Tell core if we have more comments to work on still.
    $done = true;
    return array(
        'data' => $export_items, //exported user data. refer to the code above for the format.
        'done' => $done, // true if all the export processes are done (all data of the user is exported)
    );
}}
        """

        fix_report = f"""
This report suggests fixes to comply with the GDPR Art. 15, Right of access (https://gdpr-info.eu/art-15-gdpr/). The report
is based on guidelines provided by Wordpress. Refer to {handbook_url} for more details.

1) Implement a function that exports all the user data collected in the plugin. Sample code:

{function}

2) Hook the export function to the Wordpress's Personal Data Exporter tool

{register}
{filter}

        """

        return fix_report

    def generatePrivacyPolicyReport(self):
        """Generate a guide to comply with privacy policy law, along with auto-generated sample code.

        """
        handbook_url = 'https://developer.wordpress.org/plugins/privacy/suggesting-text-for-the-site-privacy-policy/'

        function = f"""
/**
* Adds a privacy policy statement.
*/
function {PLUGIN_NAME}_add_privacy_policy_content() {{
    if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {{
        return;
    }}
    //TODO: modify the content below to include the privacy policy for the plugin.
    $content = '<p class="privacy-policy-tutorial">' . __( 'Some introductory content for the suggested text.', '{PLUGIN_NAME}' ) . '</p>'
            . '<strong class="privacy-policy-tutorial">' . __( 'Suggested Text:', '{PLUGIN_NAME}' ) . '</strong> '
            . sprintf(
                __( 'When you leave a comment on this site, we send your name, email address, IP address and comment text to example.com. Example.com does not retain your personal data. The example.com privacy policy is <a href="%1$s" target="_blank">here</a>.', '{PLUGIN_NAME}' ),
                'https://example.com/privacy-policy'
            );
    wp_add_privacy_policy_content( '{PLUGIN_NAME}', wp_kses_post( wpautop( $content, false ) ) );
}}
        """
        action = f"""
add_action( 'admin_init', '{PLUGIN_NAME}_add_privacy_policy_content' );
        """
        
        fix_report = f"""
This report suggests fixes to comply with the GDPR Art. 13 (https://gdpr-info.eu/art-13-gdpr/) through including a privacy notice. The report
is based on guidelines provided by Wordpress. Refer to {handbook_url} for more details.

1) Implement a function that includes the privacy policy for the plugin and provide it to wordpress through wp_add_privacy_policy_content(). Sample code:

{function}

2) Hook the privacy policy function to the Wordpress's admin initialization action.

{action}

        """
        return fix_report

        

# Build the maps for a more helpful output.
def __reverse_map_from_attrs(s):
    return {
        v: k[len(s) :]
        for k, v in PathAnalyzer.__dict__.items()
        if k.startswith(s) and isinstance(v, int)
    }


PathAnalyzer.DELETION_REQUIREMENT_MAP = __reverse_map_from_attrs("DELETION_REQUIREMENT_")
PathAnalyzer.HAS_DELETION_MAP = __reverse_map_from_attrs("HAS_DELETION_")
PathAnalyzer.HAS_ACCESS_MAP = __reverse_map_from_attrs("HAS_ACCESS_")
PathAnalyzer.REQUIRES_ACCESS_MAP = __reverse_map_from_attrs("REQUIRES_ACCESS_")
PathAnalyzer.HAS_STORAGE_MAP = __reverse_map_from_attrs("HAS_STORAGE_")
PathAnalyzer.THIRD_PARTY_MAP = __reverse_map_from_attrs("THIRD_PARTY_")
