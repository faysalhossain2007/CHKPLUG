# GDPR Checker - HookCollection.py
# Zihao Su zs3pv
# Created 210930

#logic: run preprocess, analyze paths assuming the parameters contain personal info.
#from Preproccess import preprocess_graph
import csv
from Detectors.Runtime import PLUGIN_NAME
from ActionHook import ActionHook
from Settings import HOOK_INFO_STORE_PATH,FN_SENSITIVITY_INFO_PATH
global hookInfo,fnSensitivityInfo
hookInfo = []
fnSensitivityInfo = []

def hookCollection():
    #clear hookInfo in case it's not empty
    global hookInfo,fnSensitivityInfo
    hookInfo = []
    fnSensitivityInfo = []
    #preprocess_graph()
    print("Finding all hooks in the current plugin...")
    locateHooks()
    print("Storing all hook information in the current plugin...")
    storeHookInformation()
def locateHooks():
    plugin_name = PLUGIN_NAME
    global hookInfo,fnSensitivityInfo
    hookInfo, fnSensitivityInfo = ActionHook.locateAddActionAndFilter(plugin_name)
def storeHookInformation():
    global hookInfo,fnSensitivityInfo
    try:
        #check if the hook info file exists
        with open(HOOK_INFO_STORE_PATH) as test:
            pass
        #if so, add the results from the current plugin
        with open(HOOK_INFO_STORE_PATH,mode='a') as plugin_hook_info_file:
            plugin_hook_info_writer = csv.writer(plugin_hook_info_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            
            for row in hookInfo:
                plugin_hook_info_writer.writerow(row)
    
    #if the file does not exist, initialize the file with headers 
    except:
        with open(HOOK_INFO_STORE_PATH, mode='w') as plugin_hook_info_file:
            plugin_hook_info_writer = csv.writer(plugin_hook_info_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            plugin_hook_info_writer.writerow(['plugin_name','hook_type','hook_name','hooked_fn_class','hooked_fn'])
            for row in hookInfo:
                plugin_hook_info_writer.writerow(row)
    try:
        #check if the hook info file exists
        with open(FN_SENSITIVITY_INFO_PATH) as test:
            pass
        #if so, add the results from the current plugin
        with open(FN_SENSITIVITY_INFO_PATH,mode='a') as plugin_fn_info_file:
            plugin_fn_info_writer = csv.writer(plugin_fn_info_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for row in fnSensitivityInfo:
                plugin_fn_info_writer.writerow(row)
    
    #if the file does not exist, initialize the file with headers 
    except:
        with open(FN_SENSITIVITY_INFO_PATH, mode='w') as plugin_fn_info_file:
            plugin_fn_info_writer = csv.writer(plugin_fn_info_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            plugin_fn_info_writer.writerow(['plugin_name','hooked_fn_class','hooked_fn','param_number','sensitivity_score'])
            for row in fnSensitivityInfo:
                plugin_fn_info_writer.writerow(row)
if __name__ == "__main__":
    hookCollection()
#database format: 
#plugin_name, hook_type, hook_name, hookedfunction, callback_function_sensitivity_score


#hook analysis

#logic 1: 

#special gdpr logic: look for add_filter for specific gdpr hooks, check sensitivity score.
#data access: check all data source going to the returned value.
