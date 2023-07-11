# GDPR Checker - Args.py
# Patrick Thomas pwt5ca
# Created 201217


import argparse
import os
import sys
from typing import Tuple
from NeoGraph import getGraph
from Settings import ROOT_DIR, SRC_DIR
import json


def getPluginName():
    """Get the plugin name through grabbing the name of the top level directory name
    
    """
    graph = getGraph()
    query = f"""
    MATCH (n:Filesystem{{id:0}})
    RETURN n.name
    """
    result = graph.run(cypher = query).data()
    if result:
        return result[0]['n.name']
    else:
        return 'unknown'
def handleArgs() -> Tuple[str, str, str, str]:
    plugin_name = getPluginName()
    plugin_path = "/var/www/html/"
    results_database = os.path.join(ROOT_DIR, "results", "results.sqlite")
    data_flow_log = os.path.join(ROOT_DIR, "results", "DataFlowTracking.log")
    
    # Preemptively exit if we detect that a test harness is being ran.
    if any(["Test.py" in s for s in sys.argv]) or any(["unittest" in s for s in sys.argv]):
        print("Skipping argument handling and assuming defaults...")
        return (results_database, data_flow_log, plugin_name, plugin_path)

    try:
        parser = argparse.ArgumentParser(
            description="Analyze WordPress plugin for GDPR infractions.",
        )
        parser.add_argument(
            "-b",
            "--database",
            type=str,
            help="Database to store all of the results.",
            default=results_database,
        )
        parser.add_argument(
            "-l",
            "--dataflowlog",
            type=str,
            help="Log file for path finding.",
            default=data_flow_log,
        )
        parser.add_argument(
            "-p",
            "--pluginname",
            type=str,
            help="The name of the plugin being analyzed.",
            default=plugin_name,
        )
        parser.add_argument(
            "-d",
            "--pluginpath",
            type=str,
            help="The path to the directory that contains the plugin.",
            default=plugin_path,
        )

        args = parser.parse_args()
        if args.database:
            results_database = args.database
        if args.dataflowlog:
            data_flow_log = args.dataflowlog
        if args.pluginname:
            plugin_name = args.pluginname
        if args.pluginpath:
            plugin_path = args.pluginpath
    except Exception as e:
        print(e)
        print("Invalid arguments... continuing with default argument values.")
        pass

    return (results_database, data_flow_log, plugin_name, plugin_path)
DATABASE_DIR, DELETION_LOG_FILE, PLUGIN_NAME, PLUGIN_DIR = handleArgs()

PLUGIN_LINK = None
PLUGIN_LINK_DATA_DIR = SRC_DIR+'/plugin_link_data.json'

def getPluginLink():
    global PLUGIN_LINK
    if PLUGIN_LINK:
        return PLUGIN_LINK
    else:
        plugin_link_data = None
        f = None
        with open(PLUGIN_LINK_DATA_DIR, "r") as f:
            plugin_link_data = json.load(f)
        del f
        plugin_link = 'http://placeHolderForPluginWebsite.com'
        for p in plugin_link_data:
            if PLUGIN_NAME==p['LOCAL_NAME']:
                plugin_link = p['AUTHOR_URL']
                break
        PLUGIN_LINK=plugin_link
        return PLUGIN_LINK
        
