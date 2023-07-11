import json
from ValueResolver import evaluateExpression
from os.path import dirname, join, realpath
from typing import Set
from NeoGraph import getGraph
from ClassStructure import determineObjectType, getClassHierarchy
from PathAnalyzerHelper import analyzeFunctionSensitivity
import pandas as pd
from Settings import HOOK_INFO_STORE_PATH, FN_SENSITIVITY_INFO_PATH
from NeoHelper import concatTree
from Detectors.Runtime import PLUGIN_NAME
import re

global __HOOK_INFO
__HOOK_INFO = None

global __FN_SENSITIVITY
__FN_SENSITIVITY = None


def getHookInfo():
    global __HOOK_INFO
    if __HOOK_INFO is not None:
        return __HOOK_INFO
    else:
        __HOOK_INFO = ActionHook.locateAddActionAndFilter2()
        # __HOOK_INFO = pd.read_csv(HOOK_INFO_STORE_PATH)
        return __HOOK_INFO


def getHookedFn(hook_type, hook_name):
    hookedFnID = []
    hook_info = getHookInfo()
    # print(hook_info)
    for hi in hook_info:
        if hi['hook_type'] == hook_type and hi['hook_name'] == hook_name:
            # print(hi)
            hookedFnID.append(hi['hooked_fn_id'])
    return hookedFnID

def getHookedFnToWPAJAX():
    #returns list of tuples, with hooked fn id and hooknames
    hookedFnID = []
    hook_info = getHookInfo()
    # print(hook_info)
    for hi in hook_info:
        if hi['hook_type'] == 'add_action' and "wp_ajax_nopriv_" in hi['hook_name']:
            # print(hi)
            hookedFnID.append((hi['hooked_fn_id'],hi['hook_name'].replace("wp_ajax_nopriv_","")))
        elif hi['hook_type'] == 'add_action' and "wp_ajax_" in hi['hook_name']:
            hookedFnID.append((hi['hooked_fn_id'],hi['hook_name'].replace("wp_ajax_","")))
    return hookedFnID

def checkWPDataDeletionHook():
    #gets the fn id of hooked function to wordpress' data deletion filter
    hook_type = "add_filter"
    hook_name = 'wp_privacy_personal_data_erasers'
    hooked_fn = getHookedFn(hook_type, hook_name)
    delete_fn = set()
    #the hooked_fn is not the export fn, but the fn that registers the export function. Traverse the export fn to get the export fns.
    for fn in hooked_fn:
        graph = getGraph()
        query = f"""
        MATCH (fn:AST{{childnum:0}})<-[:PARENT_OF]-(array_elem:AST{{funcid:{fn},type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(:AST{{childnum:1,code:'callback'}})
        RETURN fn
        """
        result = graph.run(cypher=query).data()
        if not result:
            continue
        for i in result:
            arg = i['fn']
            fnid = ActionHook.getCallback(arg)
            delete_fn.update(fnid)
    return list(delete_fn)

def getInvokedFnID(base_function_id,current_set):
    """from a given function, trace invoked functions recursively. Helper function for data deletion check.
    """
    all_invoked_id = set()
    all_invoked_id.add(base_function_id)
    all_invoked_id.update(current_set)

    graph = getGraph()
    query = f"""
    MATCH (n:AST{{funcid:{base_function_id}}})-[:CALLS]->(m:AST)
    RETURN DISTINCT m.id
    """
    result = graph.run(cypher=query).data()
    if not result:
        return list(all_invoked_id)
    for r in result:
        id = r['m.id']
        if not (id in all_invoked_id or id in current_set):
            all_invoked_id.update(getInvokedFnID(id,all_invoked_id.copy()))
    return list(all_invoked_id)

def getWPExportedData(funcid):
    """
    Given an export function, get the export data's var (according to format in WP's documentation: https://developer.wordpress.org/plugins/privacy/adding-the-personal-data-exporter-to-your-plugin/)
    """
    exportedDataIDs = []
    graph = getGraph()
    query = f"""
    MATCH (n:AST{{funcid:{funcid},type:'AST_RETURN'}})-[:PARENT_OF]->(:AST{{type:'AST_ARRAY'}})-[:PARENT_OF]->(:AST{{childnum:0}})-[:PARENT_OF]->(data:AST{{childnum:0}})
    RETURN data.id
    """
    result = graph.run(cypher=query).data()
    if not result:
        return exportedDataIDs
    exportedDataIDs = [i['data.id'] for i in result]
    return exportedDataIDs

def checkWPDataAccessHook():
    #gets the fn id of hooked function to wordpress' data export filter
    hook_type = "add_filter"
    hook_name = 'wp_privacy_personal_data_exporters'
    hooked_fn = getHookedFn(hook_type, hook_name)

    access_fns = set()
    #the hooked_fn is not the export fn, but the fn that registers the export function. Traverse the export fn to get the export fns.
    for fn in hooked_fn:
        graph = getGraph()
        query = f"""
        MATCH (fn:AST{{childnum:0}})<-[:PARENT_OF]-(array_elem:AST{{funcid:{fn},type:'AST_ARRAY_ELEM'}})-[:PARENT_OF]->(:AST{{childnum:1,code:'callback'}})
        RETURN fn
        """
        result = graph.run(cypher=query).data()
        if not result:
            continue
        for i in result:
            arg = i['fn']
            fnid = ActionHook.getCallback(arg)
            access_fns.update(fnid)
    return list(access_fns)


class ActionHook:
    f = None
    with open(join(dirname(realpath(__file__)), "actionHooks.json"), "r") as f:
        ActionHooks = json.load(f)
    del f
    AdminClasses: Set[str] = set()
    NonAdminClasses: Set[str] = set()
    Undetermined: Set[str] = set()

    @staticmethod
    def locateAddActionAndFilter2():
        #this function is the new version of locateAddActionAndFilter(). It outputs data and discards sensitivity score.
        #Gets hook_type, hook_name, hookedfunctionID

        callNames = []
        hooks = []
        hooked_fn_id = []

        graph = getGraph()
        query = f"""
        MATCH (argList:AST)<-[:PARENT_OF]-(addAction:AST)-[:PARENT_OF]->(astName:AST)-[:PARENT_OF]->(callname:AST)
        WHERE addAction.type = 'AST_CALL' AND astName.type = 'AST_NAME' AND (callname.code = 'add_action' OR callname.code = 'add_filter') AND argList.type = 'AST_ARG_LIST'
        WITH argList,callname,addAction
        MATCH (arg:AST)<-[:PARENT_OF]-(argList:AST)-[:PARENT_OF]->(arg2:AST)
        WHERE arg.childnum = 1 AND arg2.childnum = 0
        RETURN addAction.id AS callID, arg, arg2, callname.code
        """
        result = graph.run(cypher=query).data()
        if result:
            for i in result:

                # Use this later to store the callback function information
                arg = i["arg"]
                hook = i["arg2"]
                callname = i["callname.code"]
                #if the hook is a string, use the string to store the hook name
                if hook['type'] == 'string':
                    hook = hook['code']
                #else, try to resolve the concatenated value of the hook
                else:
                    evaluatedHook = evaluateExpression(hook['id'])[0]
                    if evaluatedHook:
                        #use * to denote that this name is not literal.
                        hook = evaluateExpression(hook['id'])[0] + "*"
                    else:
                        hook = concatTree(hook['id']) + "*"
                # print(callname)
                # print(hook)
                #get the call back function's id from the callback function argument.
                hooked_fn_id_temp = ActionHook.getCallback(arg)
                # if hook == 'wp_privacy_personal_data_exporters':
                #     print(hooked_fn_id_temp)
                for methodID in hooked_fn_id_temp:
                    callNames.append(callname)
                    hooks.append(hook)
                    hooked_fn_id.append(methodID)
        
        hookInfo = [{
            "hook_type": ht,
            "hook_name": hn,
            "hooked_fn_id": hfid
        } for ht, hn, hfid in zip(callNames, hooks, hooked_fn_id)]
        # print(hookInfo)
        return hookInfo

    @staticmethod
    def getCallback(arg):
        """
        Returns the hooked function ids (several if there are functions with the same name. there should only be one, but allow several for overapproximation purposes) from the callback function declaration (e.g., array( $this, 'eraser_personal_data' ) )
        If the function id can't be found, return []
        """
        graph = getGraph()
        classHierarchy = getClassHierarchy()
        funcids = []
        if arg["type"] == "AST_ARRAY":
            # case when the function info is stored in an array. example: add_action( 'plugins_loaded', array( $this, 'loaded' ) );

            # get the function name parameter and the object information
            # assume the object information is stored in a variable initialized earlier
            query1 = f"""
            MATCH (funcName:AST{{type:'string'}})<-[:PARENT_OF]-(ele2:AST{{childnum:1}})<-[:PARENT_OF]-(arg:AST{{id:{arg['id']}}})-[:PARENT_OF]->(ele:AST{{childnum:0}})-[:PARENT_OF]->(var:AST{{childnum:0}})
            RETURN funcName.code,var
            """
            result1 = graph.run(cypher=query1).data()
            if result1:
                objectType = None
                #this is to handle case where the class is directly stored as the string of the class name
                if result1[0]['var']['type'] == 'string':
                    objectType = result1[0]['var']['code']
                else:
                    objectType = determineObjectType(result1[0]['var'])
                funcName = result1[0]["funcName.code"]
                methodIDs = classHierarchy.lookUpFunction(objectType, funcName)
                if len(methodIDs) > 0:
                    for methodID in methodIDs:
                        funcids.append(methodID)
                else:
                    #overapproximate by matching all functions with the function name in case the object type can't be determined.
                    query1 = f"""
                    MATCH (func:AST)
                    WHERE (func.type = 'AST_METHOD' OR func.type= 'AST_FUNC_DECL') AND func.name = '{funcName}'
                    RETURN func.id
                    """
                    result1 = graph.run(cypher=query1).data()
                    if result1:
                        for resultTemp in result1:
                            funcNodeID = resultTemp["func.id"]
                            funcids.append(funcNodeID)

        elif arg["type"] == "string":
            #case when the second parameter is a string of the function name. example: add_action( 'publish_post', 'wpdocs_email_friends' );

            funcName = arg['code']
            query1 = f"""
            MATCH (func:AST)
            WHERE (func.type = 'AST_METHOD' OR func.type= 'AST_FUNC_DECL') AND func.name = '{arg['code']}'
            RETURN func.id
            """
            result1 = graph.run(cypher=query1).data()
            if result1:
                for resultTemp in result1:
                    funcNodeID = resultTemp["func.id"]
                    funcids.append(funcNodeID)
        return funcids


    @staticmethod
    def locateAddActionAndFilter(plugin_name):
        #plugin_name, hook_type, hook_name, hookedfunction, callback_function_sensitivity_score
        hookInfo = []
        fnSensitivityInfo = []
        graph = getGraph()
        classHierarchy = getClassHierarchy()
        query = f"""
        MATCH (argList:AST)<-[:PARENT_OF]-(addAction:AST)-[:PARENT_OF]->(astName:AST)-[:PARENT_OF]->(callname:AST)
        WHERE addAction.type = 'AST_CALL' AND astName.type = 'AST_NAME' AND (callname.code = 'add_action' OR callname.code = 'add_filter') AND argList.type = 'AST_ARG_LIST'
        WITH argList,callname,addAction
        MATCH (arg:AST)<-[:PARENT_OF]-(argList:AST)-[:PARENT_OF]->(arg2:AST)
        WHERE arg.childnum = 1 AND arg2.childnum = 0
        RETURN addAction.id AS callID, arg, arg2, callname.code
        """
        result = graph.run(cypher=query).data()
        if result:
            for i in result:

                # Use this later to store the callback function information
                arg = i["arg"]
                hook = i["arg2"]
                callname = i["callname.code"]
                #if the hook is a string, use the string to store the hook name
                if hook['type'] == 'string':
                    hook = hook['code']
                #else, try to resolve the concatenated value of the hook
                else:
                    evaluatedHook = evaluateExpression(hook['id'])[0]
                    if evaluatedHook:
                        #use * to denote that this name is not literal.
                        hook = evaluateExpression(hook['id'])[0] + "*"
                    else:
                        hook = concatTree(hook['id']) + "*"

                if arg["type"] == "AST_ARRAY":
                    # case when the function info is stored in an array. example: add_action( 'plugins_loaded', array( $this, 'loaded' ) );

                    # get the function name parameter and the object information
                    # assume the object information is stored in a variable initialized earlier
                    query1 = f"""
                    MATCH (funcName:AST{{type:'string'}})<-[:PARENT_OF]-(ele2:AST{{childnum:1}})<-[:PARENT_OF]-(arg:AST{{id:{arg['id']}}})-[:PARENT_OF]->(ele:AST{{childnum:0}})-[:PARENT_OF]->(var:AST{{childnum:0}})
                    RETURN funcName.code,var
                    """
                    result1 = graph.run(cypher=query1).data()
                    if result1:
                        objectType = None
                        #this is to handle case where the class is directly stored as the string of the class name
                        if result1[0]['var']['type'] == 'string':
                            objectType = result1[0]['var']['code']
                        else:
                            objectType = determineObjectType(result1[0]['var'])
                        funcName = result1[0]["funcName.code"]
                        methodIDs = classHierarchy.lookUpFunction(objectType, funcName)
                        if len(methodIDs) > 0:
                            for methodID in methodIDs:
                                sensitivityScore = analyzeFunctionSensitivity(methodID)
                                hookInfo.append([plugin_name, callname, hook, objectType, funcName])
                                for paramIndex in range(len(sensitivityScore)):
                                    fnSensitivityInfo.append(
                                        [plugin_name, objectType, funcName, paramIndex, sensitivityScore[paramIndex]])
                        else:
                            hookInfo.append([plugin_name, callname, hook, "unknown", funcName])

                elif arg["type"] == "string":
                    #case when the second parameter is a string of the function name. example: add_action( 'publish_post', 'wpdocs_email_friends' );

                    funcName = arg['code']
                    query1 = f"""
                    MATCH (func:AST)
                    WHERE (func.type = 'AST_METHOD' OR func.type= 'AST_FUNC_DECL') AND func.name = '{arg['code']}'
                    RETURN func.id
                    """
                    result1 = graph.run(cypher=query1).data()
                    if result1:
                        for resultTemp in result1:
                            funcNodeID = resultTemp["func.id"]
                            sensitivityScore = analyzeFunctionSensitivity(funcNodeID)
                            hookInfo.append([plugin_name, callname, hook, "none", funcName])
                            for paramIndex in range(len(sensitivityScore)):
                                fnSensitivityInfo.append(
                                    [plugin_name, "none", funcName, paramIndex, sensitivityScore[paramIndex]])
                    #if function cannot be found, set the sensitivity score to be -1
                    else:
                        hookInfo.append([plugin_name, callname, hook, "unknown", funcName])

        return (hookInfo, fnSensitivityInfo)

    @staticmethod
    def calculateDependency(allHooks):
        dependency = set()
        for i in allHooks:
            if ActionHook.isWCHook(i):
                dependency.add("Woocommerce")
            if ActionHook.isBPHook(i):
                dependency.add("Buddypress")
        return list(dependency)

    @staticmethod
    def isWCHook(hook):
        return (hook in ActionHook.ActionHooks["Woocommerce"]["public"] | hook in
                ActionHook.ActionHooks["WooCommerce"]["admin"])

    @staticmethod
    def isBPHook(hook):
        return (hook in ActionHook.ActionHooks["Buddypress"]["public"] | hook in
                ActionHook.ActionHooks["Buddypress"]["admin"])

    @staticmethod
    def isWPHook(hook):
        return (hook in ActionHook.ActionHooks["Wordpress"]["public"] | hook in
                ActionHook.ActionHooks["Wordpress"]["admin"])

    """Determine if an action/filter hook is accessed by public or admin only
    """

    @staticmethod
    def isAdmin(hook, className=None):
        admin = False
        unknown = True
        for i in ActionHook.ActionHooks.values():
            if hook in i["admin"] and hook not in i["public"]:
                admin = True
                unknown = False
            elif hook in i["public"]:
                unknown = False
        if className:
            if unknown:
                ActionHook.Undetermined.add(className)
            elif admin:
                ActionHook.AdminClasses.add(className)
            elif not admin:
                ActionHook.NonAdminClasses.add(className)
        return admin

    @staticmethod
    def isAdminClass(className):
        if className in ActionHook.AdminClasses:
            return True
        return False
