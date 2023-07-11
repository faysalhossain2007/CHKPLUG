#This file is for fast testing used when implementing functions

import unittest
# from AdminAccessChecker import *
# from PersonalData import PersonalDataMatcher
from NeoGraph import getGraph
# from Detectors.FunctionFinding import FunctionFinding
# from Detectors.Runtime import SECURITY_DETECTOR_MANAGER,DATABASE_DIR, PLUGIN_NAME
# from Detectors.Scores import ScoreType
# from Functions import load_function_info
# import csv
# import os
# from Settings import SRC_DIR
# from DataFlowTracking import getMaxTraversalLength,allTraversalType
# from Preproccess import Test_taint_personal_data
# from Preproccess import TestDetector,eliminateUselessNodes
from PathAnalyzer import PathAnalyzer
# from PersonalData import PersonalDataMatcher
# import re
# ALL_PATH = os.path.join(SRC_DIR, "function_information", "wp_functions_jerry.csv")
# ALL_PATH2 = os.path.join(SRC_DIR, "function_information", "wp_function_key_param.csv")
# from ActionHook import *
# from ValueResolver import evaluateExpression

class TestPreprocess(unittest.TestCase):
    def setUp(self):
        # Called before every test case.
        pass

    def tearDown(self):
        # Called after every test case.
        pass
    # def testDFNewString(self):
    #     print(allTraversalType())
    #     print(getMaxTraversalLength())
    # def testLogDataflowPath(self):
    #     testPA = PathAnalyzer()
    #     graph = getGraph()
    #     query = f"""
    #     MATCH (n:PERSONAL)
    #     RETURN n LIMIT 3
    #     """
    #     result = graph.run(cypher = query).data()
    #     if result:
    #         for r in result:
    #             testPA.report_log(
    #                 "test",
    #                 f"Test logging for node {r['n']['id']} with sources: {r['n']['sources']}",
    #                 0,
    #                 r['n']['id'],
    #             )
    #             for l in testPA.log:
    #                 print(l.log_to_str())
    def testWPDB_prepare(self):
        from ValueResolver import evaluateExpressionSQL,evaluateExpression
        # print(evaluateExpressionSQL(11378)[0])
        # print(evaluateExpression(11366)[0])
        from SQLParser import SQLToAST1
        # SQLToAST1(11373)
        # print("here")
        # test = [12067, 18151, 12713, 11815, 25006, 23418, 22277, 28167, 27811, 27979]
        # for i in test:
        #     print("="*20)
        #     SQLToAST1(i)
        
            
    def testTemp(self):
        # from ValueResolver import evaluateExpression
        # print(evaluateExpression(12152))
        # from Preproccess import TestHTMLToPHP
        # TestHTMLToPHP()
        from NodeEdgeManager import importToNeo4j
        importToNeo4j(True)
        pass
        # from NodeEdgeManager import setUp,commit
        # #setUp()
        # from Preproccess import TestHTMLAST,TestDetector
        # from HTMLParser2 import parseHTML
        # setUp()
        # #parseHTML("/Users/zihaosu/Documents/GDPR-CCPA-violation-checker/navex_docker/exampleApps/gdprplugin/public/class-gdpr-public.php",0)
        # TestHTMLAST()
        # #connect_html_php_ast()
        # commit()
        # from NeoHelper import getStatementSQLInfo
        # from SQLParser import getSQLParentNodes
        # SQLParentNodes = getSQLParentNodes()
        # print("here0")
        # for sql_node in SQLParentNodes:
        #     sql_info = getStatementSQLInfo(sql_node)
        #     if not sql_info:
        #         print("here")
        #         continue
        #     print("here 2")
        #     print(sql_info.operations)
        #     if {'AST_SQL_CREATE','AST_SQL_SELECT','AST_SQL_UPDATE','AST_SQL_DELETE','AST_SQL_DROP','AST_SQL_INSERT'}.intersection(sql_info.operations):
        #         print("here 3")
        # from NeoHelper import getStatementSQLInfo
        # temp = getStatementSQLInfo(712)
        # print(temp)
        # print(evaluateExpression(6549)[0])
        # from Results import register_plugin
        # register_plugin(DATABASE_DIR, PLUGIN_NAME)
        # from Args import getPluginLink
        #from HTMLParser import test
        #test()
        # print(getPluginLink())
        # # from DataFlowTracking import allTraversalTypeAPOC
        # from NodeEdgeManager import commit,setUp
        # setUp()
        # from Preproccess import Test_ensure_hierarchical_edges,TestPreprocessGraph
        # setUp()
        # Test_ensure_hierarchical_edges()
        
        # Test_ensure_hierarchical_edges()
        # commit()
        # # print(allTraversalTypeAPOC())
        
        # TestDetector()
        # #print(getSpecificFnSensitivity('wp-events-manager','WPEMS_Frontend_Assets','register_scripts'))
        # SECURITY_DETECTOR_MANAGER.run()
        # SECURITY_DETECTOR_MANAGER.write_findings_to_db()
        # SECURITY_DETECTOR_MANAGER.print_results()
        # from HookCollection import hookCollection
        # hookCollection()
        # from PathAnalyzer import PathAnalyzer
        # pa = PathAnalyzer()
        # for l in pa.log:
        #     print(l.log_to_str())

        # print("Done.")
        # from NeoHelper import addParentSelfEdges
        # print(addParentSelfEdges())
        # from Preproccess import Test_class_constant_hierarchy
        # Test_class_constant_hierarchy()
        pass
        # Test_taint_personal_data()
        # ffs = [
        #     f
        #     for f in SECURITY_DETECTOR_MANAGER.allFindings
        #     if ScoreType.API == f.score.score_type
        # ]

        # for f in ffs:
        #     print(f.score.categories.get("url",None))
            # print("Arg values")
            # print(f.arg_values)
            # print("Args:")
            # for arg_num, arg_var_name in f.arg_map.items():
            #     print(f.arg_values)
            #     print(f.data_types)
                # # arg_num: the argument's order, also corresponds to an argument's childnum in Neo4j
                # # arg_var_name: the argument's var name in Wordpress -- probably useful in determining if it is a key (arg_var_name == "$key")
                # print(f"""\t{arg_num}: {arg_var_name} {f.arg_info[arg_num]}""")
                # # There is also a lot of auxillary information stored about each arg that was scraped from
                # # WP's website; This info generally mirrors
                # # https://github.com/faysalhossain2007/GDPR-CCPA-violation-checker/blob/d91ed605b2e59bdb64f4e6cda7d251f4a50a12de/neo4j/src/Detectors/wordpress_functions.json#L22123-L22123
                # # but it is in a different form (split into f.arg_map and f.arg_info).
                # print(f"""\t\ttype: {f.arg_info[arg_num].get("type")}""")
                # print(f"""\t\tdescription: {f.arg_info[arg_num].get("description")}""")
            # print()
    # def testProc(self):
    #     rows = []
    #     with open(ALL_PATH, "r", newline="") as f:
    #         reader = csv.reader(f)
    #         header = False
    #         for row in reader:
    #             # Skip the header.
    #             if not header:
    #                 header = True
    #                 continue

    #             (
    #                 func_name,
    #                 sensitivity_str,
    #                 setter_retriever,
    #                 data_type,
    #                 url,
    #                 data_type_std,
    #             ) = row
    #             if sensitivity_str in ['dynamic','sensitive'] or setter_retriever=='set':
    #                 rows.append([func_name,url,0])
    #     with open(ALL_PATH2,mode='a') as plugin_hook_info_file:
    #         plugin_hook_info_writer = csv.writer(plugin_hook_info_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            
    #         for row in rows:
    #             plugin_hook_info_writer.writerow(row)



        # for f in ffs:
        #     print(f)
        #     print(f.code) # This is just concatTree called on the root call node.
        #     print("Args:")
        #     for arg_num, arg_var_name in f.arg_map.items():
        #         # arg_num: the argument's order, also corresponds to an argument's childnum in Neo4j
        #         # arg_var_name: the argument's var name in Wordpress -- probably useful in determining if it is a key (arg_var_name == "$key")
        #         print(f"""\t{arg_num}: {arg_var_name} {f.arg_info[arg_num]}""")
        #         # There is also a lot of auxillary information stored about each arg that was scraped from
        #         # WP's website; This info generally mirrors
        #         # https://github.com/faysalhossain2007/GDPR-CCPA-violation-checker/blob/d91ed605b2e59bdb64f4e6cda7d251f4a50a12de/neo4j/src/Detectors/wordpress_functions.json#L22123-L22123
        #         # but it is in a different form (split into f.arg_map and f.arg_info).
        #         print(f"""\t\ttype: {f.arg_info[arg_num].get("type")}""")
        #         print(f"""\t\tdescription: {f.arg_info[arg_num].get("description")}""")
        #     print()

        # graph = getGraph()
        # query = f"""
        # MATCH (n)
        # RETURN n.id LIMIT 200
        # """
        # result = graph.run(cypher = query).data()
        # for rst in result:
        #     ID = rst['n.id']
        #     PersonalDataMatcher.isNodePersonal(ID)


def __run():
    unittest.main()


if __name__ == "__main__":
    __run()
