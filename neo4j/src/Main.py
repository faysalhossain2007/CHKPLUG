from Detectors.Runtime import (
    DELETION_LOG_FILE,
    PLUGIN_NAME,
    SECURITY_DETECTOR_MANAGER,
    SECURITY_MAP_USES_TO_FINDINGS,
    SECURITY_USES,
)
from Preproccess import preprocess_graph
from Utls import header_print, progress_bar, subheader_print
import logging
from PathAnalyzer import PathAnalyzer, FixReport
from HookCollection import hookCollection
from NeoHelper import requiresAnalysis
# from NeoGraph import getGraph
# from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
#from DataFlows import DataFlowGraph,DataFlowPath, DataNode
# from NeoHelper import concatTree

# Log settings
neo4j_log = logging.getLogger("neo4j.bolt")
neo4j_log.setLevel(logging.WARNING)
logging.basicConfig(filename=DELETION_LOG_FILE, level=logging.INFO)

#dataflowGraph = DataFlowGraph()


def __run():
    print(f"Running Main.py on {PLUGIN_NAME}")
    """
	Preprocessing stage

	The following operations are done on the AST here:
	-	add parent to self edges
	-	convert detected SQL usages to SQL ASTs, and insert those ASTs back into the graph
	-	parse HTML and load the HTML ASTs as well
	"""
    header_print("Preprocessing stage")
    preprocess_graph()
    if not requiresAnalysis():
        print("="*15)
        print('Found no personal data in the plugin. No analysis needed.')
        return
    if not SECURITY_DETECTOR_MANAGER:
        return
    SECURITY_DETECTOR_MANAGER.write_findings_to_db()
    #collect hook info
    hookCollection()
    """
	Data flows stage

	Here, data flows thought to contain personal information are found and recorded.
	"""
    # Find data flows.
    # header_print("Data flows stage")
    # print("Finding data flows...")

    # # varNameTest = ['email', 'first.*name', 'last.*name', "username", "pass", "address", "street", "country", "state", "zipcode", "postcode", "city", "birth"]
    # # # trackTypeTest = [ 'request', 'AST_HTML_TEXT']
    # # trackTypeTest = ['request']
    # # trackDataFlow(varNameTest,trackTypeTest)

    # #Varname recorded in NeoHelper
    # #varNameTest = ['email', 'first.*name', 'last.*name', "user(.|)(name|)", "pass", "address", "street", "country", "state", "zipcode", "postcode", "city", "birth"]
    # trackTypeTest = ['request', 'woocommerce', 'wordpress', None]  # None is do_action and such
    # for t in trackTypeTest:
    # 	s = f"# Track type: {t if t else 'action'} #"
    # 	print(f"\n\n{'#' * len(s)}\n{s}\n{'#' * len(s)}\n")
    # 	trackDataFlow(t)

    #trackDataFlow(["request", "woocommerce", "wordpress", None])

    # Backtrack from sinks.
    # sinks: Set[int] = {
    #     f.node["id"] for f in SECURITY_DETECTOR_MANAGER.allFindings if f.score.is_sink()
    # }
    # real_sinks: Set[int] = set()

    # for s in progress_bar(sinks):
    #     query = f"""
    # 	MATCH (n:AST{{id:{s}}})
    # 	OPTIONAL MATCH (n)-[:PARENT_OF*0..]->(m:AST)<-[:PHP_REACHES]-(o:AST)
    # 	MATCH (o)-[:PHP_REACHES*0..]->(p:AST)
    # 	WHERE NOT EXISTS ((p)-[:PHP_REACHES]->()<-[:PARENT_OF*]-(n))
    # 		AND EXISTS ((n)-[:PARENT_OF*0..]->(p))
    # 	RETURN COLLECT(DISTINCT p.id)
    # 	"""
    #     result = getGraph().evaluate(query)
    #     if result:
    #         real_sinks.update(result)

    # for s in progress_bar(real_sinks):
    #     dn = DataNode(s, concatTree(s))
    #     reverseTrackDataFlowFromNode(dn)
    """
	Path analysis stage

	With the information from the past several stages, we now look for insecure usages and GDPR violations in these paths.
	"""
    header_print("Incompliance Finding")
    print()
    print("We found following evidences that your plugin is in violation of General Data Protection Regulation (GDPR).")
    
    # path_list_paths: Dict[str, List[DataFlowPath]] = dataflowGraph.getAllPaths()
    # sink_paths: Dict[str,List[DataFlowPath]] = dataflowGraph.getAllPathsToSink()
    #path_list_paths: Dict[str, List[DataFlowPath]] = ()
    # Manually grab paths?
    #query = """MATCH p=(source:SOURCE)-[:PHP_REACHES*]->(sink:SINK) RETURN [source.id, sink.id], [n IN NODES(p) | n.id]"""
    # path_list_paths["manual"] = []
    #results = getGraph().run(query)
    # if results:
    #     for r in results:
    #         if not r:
    #             continue
    #         source_sink, path_raw = r
    #         path = [int(i) for i in path_raw]
    #         for node in path:
    #             code = concatTree(node)
    #             dn = DataNode(node, code)
    #             dataflowGraph.insertNode(dn)
    #         path_list_paths["manual"].append(DataFlowPath(-1))
    #         path_list_paths["manual"][-1].path = path

    # path_analyzers: Dict[str, PathAnalyzer] = dict()

    # for pii_type, paths in path_list_paths.items():
    #     path_list: List[List[DataNode]] = [l.toDataNodeList() for l in paths]

    #     #commented out the code below as it took too long
    #     # print("Saving path information...")
    #     # conn = get_conn()
    #     # with conn:
    #     #     for p in progress_bar(paths):
    #     #         p.addToPathsDatabase()
    #     #     conn.commit()
    #     # conn.close()

    #     subheader_print(f'Analyze paths for personal data type: "{pii_type}"')
    #     # for l in paths:
    #     # 	l.printPathInfo()
    #     pa = PathAnalyzer(path_list, topic=pii_type)
    #     path_analyzers[pii_type] = pa
    pa = PathAnalyzer()
    # subheader_print(f"Path Analyzer Result")
    for l in pa.log:
        print(l.log_to_str())
    if not pa.findings:
        print('No findings')
        return
    if pa.need_access_fix or pa.need_deletion_fix or pa.need_policy_fix:
        header_print("Q&A")
        access_requirement_text = ""
        deletion_requirement_text = ""
        privacy_policy_requirement_text = ""
        if pa.need_access_fix:
            access_requirement_text = """
[Art.15, Right to access] If a plugin stores personal data in a custom database they create or manage, it needs to provide methods for users to export the data upon request. Note that Wordpress provides an exporter tool that handles Wordpress's native tables (e.g., user_meta), but it is still suggested to provide ways to export data stored through Wordpress's native storage functions (e.g., update_user_meta). \n\n
            """
        if pa.need_deletion_fix:
            deletion_requirement_text = """
[Art.17, Right to erasure] If a plugin stores personal data in a custom database they create or manage, or through Wordpress's native storage functions (e.g., update_user_meta), it needs to provide methods for users to erase the data upon request. Note that deleting data for all users upon uninstallation does not satisfy the requirement. \n\n
            """
        if pa.need_policy_fix:
            privacy_policy_requirement_text = """
[Art. 13, Information to be provided where personal data are collected from the data subject] If a plugin collects or handles personal data, it needs to provide privacy policy texts that explain what personal data is being collected and for what purpose. The texts are meant to be added to the privacy policy of the websites that deploy the plugin. \n\n
            """
            
        q1text = f"""
1. Why is my plugin in violation against GDPR?

GDPR (https://gdpr-info.eu/) aims to give citizens in the European Union (EU) control over their personal data. If a website collects or store user data, it is required to provide users functionalities to control their data, such as ones to erase or export their data. While a plugin do not directly interact with users, it may provide functionalities that collect or store personal data, which would make websites that deploy the plugin in violation against GDPR if the plugin does not provide corresponding functionalities to allow users control their personal data. Therefore, plugin developers are responsible to provide functions to manage the personal data they handle in accordance with GDPR. We list requirements by specific GDPR articles relevant to your plugin below.

{privacy_policy_requirement_text}{access_requirement_text}{deletion_requirement_text}
        """
        print(q1text)

        q2text = f"""
2. What are the consequences of violating GDPR?



        """
        # print(q2text)

        q3text = f"""
2. How do I make my plugin compliant?

Please refer to the fix report below to see how you can make your plugin comply with GDPR.

        """
        print(q3text)
        fr = FixReport(pa.findings)
        header_print("Fix Report")
        if pa.need_access_fix:
            subheader_print(f"Data Access Fix Report")
            print(fr.generateAccessReport())
        if pa.need_deletion_fix:
            subheader_print(f"Data Deletion Fix Report")
            print(fr.generateDeletionReport())
        if pa.need_policy_fix:
            subheader_print(f"Privacy Policy Fix Report")
            print(fr.generatePrivacyPolicyReport())
        disclaimer = f"""
Disclaimer: The sample code provided above is only for reference and does not guarantee GDPR compliance. The recommended list of data to delete/export may not be comprehensive. 
        """
        print()
        print(disclaimer)
    print("Done.")


if __name__ == "__main__":
    __run()
