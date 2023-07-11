# GDPR Checker - PathAnalyzerHelper.py
# Zihao Su zs3pv
# Created 210930

#this file is intended to store helper functions that analyze dataflow paths.

from NeoHelper import ASTMethodGetParameterList
from NeoGraph import getGraph
from Detectors.Runtime import PLUGIN_NAME,SECURITY_DETECTOR_MANAGER
from Detectors.Scores import ScoreType
from typing import List
import pandas as pd
from Settings import *

from Detectors.FunctionFinding import FunctionFinding
from PersonalData import PersonalDataMatcher
import subprocess
import shutil

#output_path for html privacy text
HTML_TO_PLAIN_TEXT_DIR = os.path.join(ROOT_DIR, "PrivacyPolicyAnalysis","HtmlToPlaintext-master")
OUTPUT_PATH = os.path.join(HTML_TO_PLAIN_TEXT_DIR,"ext")

#output path for plain text privacy text after preprocessing html privacy text
POLICY_LINT_DIR = os.path.join(ROOT_DIR, "PrivacyPolicyAnalysis","PrivacyPolicyAnalysis-master")
OUTPUT_PATH2 = os.path.join(POLICY_LINT_DIR,"ext")

def getTableCreationFindings():
    """Finds all table creation findings
    Returns: a list of findings that are table creation
    """
    if not SECURITY_DETECTOR_MANAGER:
        return []
    ffs = [
        f
        for f in SECURITY_DETECTOR_MANAGER.allFindings
        if f.score.score_type == ScoreType.DATABASE
    ]
    findings = []
    for f in ffs:
        operations: List[str] = f.score.categories.get("operations", None)
        if operations and "AST_SQL_CREATE" in operations:
            findings.append(f)
    return findings

def getTableDeletionFindings():
    """Finds all table creation findings
    Returns: a list of findings that are table creation
    """
    if not SECURITY_DETECTOR_MANAGER:
        return []
    ffs = [
        f
        for f in SECURITY_DETECTOR_MANAGER.allFindings
        if f.score.score_type == ScoreType.DATABASE
    ]
    findings = []
    for f in ffs:
        operations: List[str] = f.score.categories.get("operations", None)
        if operations and (("AST_SQL_DELETE" in operations) or ("AST_SQL_DROP" in operations)):
            findings.append(f)
    return findings

def getPersonalDataStorageFindings():
    """Finds all sensitive storage findings
    Returns: a list of tuples in the form of (finding, personalTypes), where finding is a Detector finding and personalTypes a list of personal data types.
    """
    #returns a list of tuples
    if not SECURITY_DETECTOR_MANAGER:
        return []
    ffs = [
        f
        for f in SECURITY_DETECTOR_MANAGER.allFindings
        if f.score.is_storage()
    ]
    sensitive_storage_findings = []
    for f in ffs:

        #PS: can further reduce false positive by filtering out calls that have personal data flowing to the key instead of the data.
        personalTypes = getPersonalTypes(f.node['id'])
        if personalTypes:
            sensitive_storage_findings.append((f,personalTypes))
    return sensitive_storage_findings


def analyzeFunctionSensitivity(nodeID):
    """
    input:
        nodeID: function declaration's node id
    output:
        a list of sensitivity score, corresponding to each of the parameters in order (e.g., [1,2,0,1] if there are four parameters)
    """
    sensitivityScores = []
    param = ASTMethodGetParameterList(nodeID)
    if param:
        paramName, paramList = param
        for params in paramList:
            sensitivityScores.append(traceFunctionParamSensitivity(params))
    return sensitivityScores
def traceFunctionParamSensitivity(nodeID):
    graph = getGraph()
    query = f"""
    
    """
    return 0

def getPersonalTypes(nodeID):
    graph = getGraph()
    query = f"""
    MATCH (n:PERSONAL{{id:{nodeID}}})
    RETURN n.personal_types
    """
    isPersonal = graph.evaluate(cypher = query)
    if isPersonal:
        return list(isPersonal)
    return None

def getSources(nodeID):
    graph = getGraph()
    query = f"""
    MATCH (n:PERSONAL{{id:{nodeID}}})
    RETURN n.sources
    """
    sources = graph.evaluate(cypher = query)
    if sources:
        return list(sources)
    return None

def getEncryption(nodeID):
    """Returns encryption score and encryption method of a node, if applicable
    """
    graph = getGraph()
    query = f"""
    MATCH (n:SECURE{{id:{nodeID}}})
    RETURN n
    """
    sources = graph.evaluate(cypher = query)
    if sources:
        return [sources["encryption_score"],sources["encryption_method"]]
    return None

def findRetrievalOfTable(tableName:str):
    """
    Find data access of a database table
    """
    if not SECURITY_DETECTOR_MANAGER:
        return (None,None)
    ffs = [
        f
        for f in SECURITY_DETECTOR_MANAGER.allFindings
        if f.score.is_database() and f.score.categories.get("table_name", None)==tableName and f.score.categories.get("operations",None)=='select'
    ]
    return ffs


def findDeletionOfTable(tableName:str):
    """
    Find data deletion of a database table
    """
    if not SECURITY_DETECTOR_MANAGER:
        return (None,None)
    deletion_detector = SECURITY_DETECTOR_MANAGER.get_detector("DeletionDetector")
    hasDeletionOfRecord = []
    hasDropOfTable = []
    if deletion_detector:
        for finding in deletion_detector.findings:
            
            is_database: bool = finding.score.categories.get("database", False)
            is_drop: bool = finding.score.categories.get("drop", False)

            
            if is_database and is_drop:
                # Register a table's name as dropped.
                table_name = finding.score.categories.get("table_name", None)
                if table_name:
                    if table_name.lower() == tableName.lower():
                        hasDropOfTable.append(finding)
            elif is_database and not is_drop:
                # Register a table as deleted from.
                table_name = finding.score.categories.get("table_name", None)
                if table_name:
                    if table_name.lower() == tableName.lower():
                        hasDeletionOfRecord.append(finding)
                
    return (hasDeletionOfRecord,hasDropOfTable)

def findDeletionOfWPFn(finding:FunctionFinding):
    #finding corresponding deletion funciton for a given finding of a Wordpress storage method.
    deletionFindings = []
    if finding:
        deletion_detector = SECURITY_DETECTOR_MANAGER.get_detector("DeletionDetector")
        keyValue = finding.keyValue
        data_type = finding.function_annotation.data_type
        #try to find another call with the same data type and same keyValue (if present)
        for f in deletion_detector.findings:
            temp_func_annotation = getattr(f,'function_annotation',None)
            if temp_func_annotation:
                temp_data_type = f.function_annotation.data_type
                if finding.keyValue:
                    temp_keyValue = getattr(f,'keyValue',None)
                    if data_type==temp_data_type and temp_keyValue and temp_keyValue==keyValue:
                        deletionFindings.append(f)
                else:
                    if data_type==temp_data_type:
                        deletionFindings.append(f)
                
    return deletionFindings

def getDataCategoryForPolicyLint(data_type:str):
    """Map policy lint data categories to our data types. Policy lint data categories found in PrivacyPolicyAnalysis/PrivacyPolicyAnalysis-master/DockerImage/code/Consistency.py
    """
    if data_type == 'geographical location':
        return list(DATA_TYPE_ADDRESS)
    elif data_type == 'email address':
        return list(DATA_TYPE_EMAIL)
    elif data_type == 'person name':
        return list(DATA_TYPE_FIRST_NAME).extend(list(DATA_TYPE_LAST_NAME))
    elif data_type == 'phone number':
        return list(DATA_TYPE_PHONE)
    elif data_type == 'mac address':
        return list(DATA_TYPE_IP)
    elif data_type in ['device information','device identifier','router name','advertising identifier']:
        return list(DATA_TYPE_USER_META)
    elif data_type == 'identifier':
        return list(DATA_TYPE_USER).extend(list(DATA_TYPE_USER_META))
    else:
        return PersonalDataMatcher.determine_category(data_type)

def getThirdPartyDataTypeFromPolicy():
    print("=preprocessing privacy policy text...")
    status = preprocess_html_policy_text()
    if status in [1,2]:
        print("=preprocessing privacy policy text FAILED")
        #return if there's error
        return None
    print("=preprocessing privacy policy text DONE")
    print("=analyzing privacy policy text")
    result = analyze_privacy_policy()
    status = result[0]
    df = result[1]
    if status in [1,2]:
        #return if there's error
        print("=analyzing privacy policy text FAILED")
        return None
    print("=analyzing privacy policy text DONE")
    
    #get all data types ('policyData') that has "collect" for 'policyAction' column. Currently do not differentiate policy entity.
    if len(df)==0:
        return None
    df = df[df['policyAction']=='collect']['policyData']
    if len(df)==0:
        return None
    dataTypes = []
    for i in df:
        dataTypes.extend(getDataCategoryForPolicyLint(i))
    return dataTypes

def unlock_file(path):
    sudo_password = os.environ['SUDO_PASSWORD']
    print("SUDO PASSWORD", sudo_password)
    if len(sudo_password) > 0:
        cmd = 'echo '+ sudo_password +' | sudo -S chmod 777 -R ' + path
    else:
        print('No SUDO password provided. so trying to change the file permission of '+  str(path) + 'without sudo permission')
        cmd = 'echo ' + ' sudo -S chmod 777 -R ' + path
    print("Command to execute: ", cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    p.communicate()
    print("Removing all locks in ", path)

def preprocess_html_policy_text():
    if not os.path.exists(os.path.join(OUTPUT_PATH, f'html_policies')):
        return 1
    os.chdir(HTML_TO_PLAIN_TEXT_DIR)
    p = subprocess.Popen("./build.sh", stdout=subprocess.PIPE, shell=True)
    # print("start")
    p.communicate()
    print("Finished building docker")
    p = subprocess.Popen("./run.sh", stdout=subprocess.PIPE, shell=True)
    p.communicate()
    print("Finished running docker")

    preprocessed_file_path = os.path.join(OUTPUT_PATH,'plaintext_policies','html_policies.txt')
    file_exists = os.path.exists(preprocessed_file_path)

    # print(file_exists)

    if not file_exists:
        return 2

    unlock_file(OUTPUT_PATH)

    #move the preprocessed file to the folder for analyzing privacy policy
    os.rename(preprocessed_file_path,os.path.join(OUTPUT_PATH2,'plaintext_policies'))
    # os.remove(preprocessed_file_path)
    return 0

def analyze_privacy_policy():
    if not os.path.exists(os.path.join(OUTPUT_PATH2, f'plaintext_policies')):
        return (1,None)
    #clean up

    # sudo_password = os.environ['SUDO_PASSWORD']
    # # if len(sudo_password) == 0:
    # #     return
    #
    # # print("SUDO PASSWORD", sudo_password)
    # cmd = 'echo '+ str(sudo_password) +' | sudo -S chmod 777 -R ' + OUTPUT_PATH2
    # # print("Command to execute: ", cmd)
    # p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    # p.communicate()
    # print("Removing all locks in ", OUTPUT_PATH2)

    unlock_file(OUTPUT_PATH2)

    path_to_combined_table = os.path.join(OUTPUT_PATH2,'combined_tables')
    if os.path.exists(path_to_combined_table):
        shutil.rmtree(path_to_combined_table)
    path_to_dataset = os.path.join(OUTPUT_PATH2,'datasets')
    if os.path.exists(path_to_dataset):
        shutil.rmtree(path_to_dataset)
    path_to_input = os.path.join(OUTPUT_PATH2,'input')
    if os.path.exists(path_to_input):
        shutil.rmtree(path_to_input)
    path_to_output = os.path.join(OUTPUT_PATH2,'output')
    if os.path.exists(path_to_output):
        shutil.rmtree(path_to_output)
    analysis_result_path = os.path.join(OUTPUT_PATH2,'policylint_results.csv')
    if os.path.exists(analysis_result_path):
        os.remove(analysis_result_path)
    
    os.chdir(POLICY_LINT_DIR)
    p = subprocess.Popen("./build.sh", stdout=subprocess.PIPE, shell=True)
    p.communicate()
    print("Finished building docker")
    p = subprocess.Popen("./run.sh", stdout=subprocess.PIPE, shell=True)
    p.communicate()
    print("Finished running docker")

    if not os.path.exists(analysis_result_path):
        return (2,None)
    
    df = pd.read_csv(analysis_result_path)

    #clean up
    os.remove(os.path.join(OUTPUT_PATH2, f'plaintext_policies'))

    return (0,df)




# def readWPFunctionCompliance():
#     __HOOK_INFO = pd.read_csv(HOOK_INFO_STORE_PATH)

    