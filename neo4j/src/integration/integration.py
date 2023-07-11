import argparse
import logging
import os
import subprocess
import sys
from typing import Dict, List, Set

from pathlib import Path
from Naked.toolshed.shell import muterun_js

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from Settings import ROOT_DIR
from Utls import create_dir, readCSVbyTab, writeCSVbyTab

global PLUGIN_DIR
global INTEGRATION_DIR
global JS_DIR_NODES
global PHP_DIR_NODES
global HTML_DIR_NODES
global OUTPUT_DIR
global JSJOERN_DIR
global ESPRIMA_JS
global PHP2AST_CONVERTER
PLUGIN_DIR = os.path.join(
    ROOT_DIR,
    "jsjoern-uva/exampleApps/woo-empatkali-checkout-gateway/woo-empatkali-checkout-gateway/",
)
INTEGRATION_DIR = os.path.join(ROOT_DIR, "neo4j/src/integration/")
JS_DIR_NODES = os.path.join(INTEGRATION_DIR, "results-js/")
PHP_DIR_NODES = os.path.join(INTEGRATION_DIR, "results-php/")
HTML_DIR_NODES = os.path.join(INTEGRATION_DIR, "results-html/")
OUTPUT_DIR = os.path.join(INTEGRATION_DIR, "output/")
JSJOERN_DIR = os.path.join(ROOT_DIR, "jsjoern-uva")
ESPRIMA_JS = os.path.join(JSJOERN_DIR, "esprima-joern/main.js")
PHP2AST_CONVERTER = os.path.join(JSJOERN_DIR, "phpast2cpg")

_NODES_HEADER = "id:int	labels:label	type	flags:string_array	lineno:int	code	childnum:int	funcid:int	classname	namespace	endlineno:int	name	doccomment".split(
    "\t")
_EDGES_HEADER = "start	end	type".split("\t")
_CPG_EDGES_HEADER = "start	end	type	var	taint_src	taint_dst	flowLabel".split("\t")


class Node:
    __next_id: int = 0

    def __init__(self, csv_data: List[str]) -> None:
        super().__init__()

        self.csv_data = csv_data
        self.old_id = int(self.csv_data[0])
        self.new_id = Node.__next_id
        Node.__next_id += 1

    def __repr__(self) -> str:
        return f"Node[{self.old_id}:{self.new_id}]"

    def convert(self) -> List[str]:
        return list([str(self.new_id), *self.csv_data[1:]])


class Edge:
    __next_id: int = 0

    def __init__(self, start_node: Node, end_node: Node, csv_data: List[str]) -> None:
        super().__init__()
        self.start = start_node
        self.end = end_node
        self.csv_data = csv_data
        self.index = Edge.__next_id
        Edge.__next_id += 1

    def __repr__(self) -> str:
        return f"Edge[{self.start}->{self.end}]"

    def convert(self) -> List[str]:
        return list([str(self.start.new_id), str(self.end.new_id), *self.csv_data[2:]])


def get_maximum_id(data_list: List[List[str]]):
    l = [int(r[0]) for r in data_list]
    return max(l)


def longest_common_prefix(str_set: Set[str], i: int = 0) -> str:
    if len(str_set) == 0 or i < 0:
        return ""
    first = str_set.copy().pop()
    prefix = first[:i]
    matching = {s for s in str_set if s.startswith(prefix)}
    if len(matching) == len(str_set) and i + 1 <= len(first):
        return longest_common_prefix(str_set, i=i + 1)
    else:
        return first[:i - 1]


def relative_paths(files):
    """Map a collection of paths to relative paths of the common prefix."""
    # common = Path(os.path.commonprefix(files))
    if len(files) < 1:
        return []
    common = Path(os.path.commonpath(files))
    return [str(Path(f).relative_to(common)) for f in files]


def merge_php_js_joern():
    create_dir(OUTPUT_DIR)

    nodes_js = os.path.join(JS_DIR_NODES, "nodes.csv")
    edges_js = os.path.join(JS_DIR_NODES, "rels.csv")
    cpg_edges_js = os.path.join(JS_DIR_NODES, "cpg_edges.csv")

    nodes_php = os.path.join(PHP_DIR_NODES, "nodes.csv")
    edges_php = os.path.join(PHP_DIR_NODES, "edges.csv")
    cpg_edges_php = os.path.join(PHP_DIR_NODES, "cpg_edges.csv")

    # nodes_html = os.path.join(HTML_DIR_NODES, "nodes.csv")
    # edges_html = os.path.join(HTML_DIR_NODES, "edges.csv")

    nodes_agg = os.path.join(OUTPUT_DIR, "nodes.csv")
    edges_agg = os.path.join(OUTPUT_DIR, "edges.csv")
    cpg_edges_agg = os.path.join(OUTPUT_DIR, "cpg_edges.csv")

    data_tuples = [
        (readCSVbyTab(nodes_php), readCSVbyTab(edges_php), readCSVbyTab(cpg_edges_php)),
        (readCSVbyTab(nodes_js), readCSVbyTab(edges_js), readCSVbyTab(cpg_edges_js)),
    # (readCSVbyTab(nodes_html), readCSVbyTab(edges_html), []),
    ]

    data_node_dicts: List[Dict[int, Node]] = [dict() for t in data_tuples]
    data_edge_dicts: List[Dict[int, Edge]] = [dict() for t in data_tuples]
    data_cpg_dicts: List[Dict[int, Edge]] = [dict() for t in data_tuples]

    for i, t in enumerate(data_tuples):
        node_rows, edges_rows, cpg_rows = t
        logging.info(f"Data set {i}: {len(node_rows)} nodes, {len(edges_rows)} edges, {len(cpg_rows)} CPG edges")
        for r in node_rows:
            data_node_dicts[i][int(r[0])] = Node(r)
        for r in edges_rows:
            start_id = int(r[0])
            end_id = int(r[1])
            start_node = data_node_dicts[i].get(start_id, None)
            end_node = data_node_dicts[i].get(end_id, None)
            if not start_node:
                logging.warning(f"Missing start node for edge (ID {start_id}); skipping {r}")
            elif not end_node:
                logging.warning(f"Missing end node for edge (ID {end_id}); skipping {r}")
            else:
                e = Edge(start_node, end_node, r)
                data_edge_dicts[i][e.index] = e
        for r in cpg_rows:
            start_id = int(r[0])
            end_id = int(r[1])
            start_node = data_node_dicts[i].get(start_id, None)
            end_node = data_node_dicts[i].get(end_id, None)
            if not start_node:
                logging.warning(f"Missing start node for edge (ID {start_id}); skipping {r}")
            elif not end_node:
                logging.warning(f"Missing end node for edge (ID {end_id}); skipping {r}")
            else:
                e = Edge(start_node, end_node, r)
                data_cpg_dicts[i][e.index] = e

        # Remove common filename prefixes for file name comparison.
        filenames: Set[str] = set()
        for n in data_node_dicts[i].values():
            if "/" in n.csv_data[11]:
                filenames.add(n.csv_data[11])

        rel_paths = relative_paths(list(filenames))
        filenames_cut = {f: r for f, r in zip(filenames, rel_paths)}
        for n in data_node_dicts[i].values():
            if "/" in n.csv_data[11]:
                n.csv_data[11] = filenames_cut[n.csv_data[11]]

    node_csv_rows: List[List[str]] = [_NODES_HEADER]
    edge_csv_rows: List[List[str]] = [_EDGES_HEADER]
    cpg_csv_rows: List[List[str]] = [_CPG_EDGES_HEADER]
    for i in range(len(data_node_dicts)):
        nodes = data_node_dicts[i].values()
        edges = data_edge_dicts[i].values()
        cpgs = data_cpg_dicts[i].values()
        node_csv_rows.extend([v.convert() for v in nodes])
        edge_csv_rows.extend([v.convert() for v in edges])
        cpg_csv_rows.extend([v.convert() for v in cpgs])

    logging.info(
        f"Final data set: {len(node_csv_rows)} nodes, {len(edge_csv_rows)} edges, {len(cpg_csv_rows)} CPG edges")

    writeCSVbyTab(nodes_agg, node_csv_rows, "w")
    writeCSVbyTab(edges_agg, edge_csv_rows, "w")
    writeCSVbyTab(cpg_edges_agg, cpg_csv_rows, "w")


# to generate nodes, edges and cpg_edges file
def execute_js_joern(plugin_file_dir):
    js_output_nodes = os.path.join(JS_DIR_NODES, "nodes.csv")
    js_output_rels = os.path.join(JS_DIR_NODES, "rels.csv")
    js_cpg_edges_fileloc = os.path.join(JS_DIR_NODES, "cpg_edges.csv")

    # Generate JS notes and edges
    logging.info("Running Esprima...")
    response = muterun_js(ESPRIMA_JS, arguments=f"{plugin_file_dir} -o {JS_DIR_NODES}")
    logging.info(f"Esprima exited with code {response.exitcode}")
    if response.exitcode != 0:
        logging.error(f"Running Esprima failed with exit code {response.exitcode}")
        logging.error(f"Esprima stdout:")
        print(response.stdout.decode())
        logging.error(f"Esprima stderr:")
        print(response.stderr.decode())
        sys.exit(response.exitcode)

    # CD into output directory then generate JS CPG.
    logging.info("Running PHP2AST_CONVERTER...")
    old_dir = os.getcwd()
    os.chdir(JS_DIR_NODES)
    result = subprocess.run((PHP2AST_CONVERTER, js_output_nodes, js_output_rels), capture_output=True)
    os.chdir(old_dir)
    if result.returncode != 0:
        logging.error(f"Running PHP2AST_CONVERTER failed with exit code {response.exitcode}:")
        logging.error(f"PHP2AST_CONVERTER stdout:")
        print(result.stdout)
        logging.error(f"PHP2AST_CONVERTER stderr:")
        print(result.stderr)
        sys.exit(result.returncode)
    logging.info(f"PHP2AST_CONVERTER exited with code {result.returncode}")



def start_integration(plugin_file_dir):
    execute_js_joern(plugin_file_dir)
    merge_php_js_joern()


def run():
    plugin_file_dir = PLUGIN_DIR
    # plugin_file_dir = ROOT_DIR + "navex_docker/exampleApps/gdprplugin"

    logging.info("Integration.py")
    logging.debug(f"PLUGIN_DIR {PLUGIN_DIR}")
    logging.debug(f"JS_DIR_NODES {JS_DIR_NODES}")
    logging.debug(f"PHP_DIR_NODES {PHP_DIR_NODES}")
    logging.debug(f"HTML_DIR_NODES {HTML_DIR_NODES}")
    logging.debug(f"OUTPUT_DIR {OUTPUT_DIR}")
    logging.debug(f"JSJOERN_DIR {JSJOERN_DIR}")
    logging.debug(f"ESPRIMA_JS {ESPRIMA_JS}")
    logging.debug(f"PHP2AST_CONVERTER {PHP2AST_CONVERTER}")

    start_integration(plugin_file_dir)


if __name__ == "__main__":
    # Parse some arguments for batch runs.
    parser = argparse.ArgumentParser(description="Merge JS and PHP ASTs.")
    parser.add_argument("-s", "--source", help="PHP plugin location.", type=str)
    parser.add_argument("-j", "--js", help="JS AST directory location.", type=str)
    parser.add_argument("-p", "--php", help="PHP AST directory location.", type=str)
    parser.add_argument("-m", "--html", help="HTML AST directory location.", type=str)
    parser.add_argument("-o", "--output", help="Output directory.", type=str)
    parser.add_argument("-u", "--jsjoern", help="JS Joern directory.", type=str)

    args = parser.parse_args()

    if args.source:
        PLUGIN_DIR = args.source
    if args.js:
        JS_DIR_NODES = args.js
    if args.php:
        PHP_DIR_NODES = args.php
    if args.html:
        HTML_DIR_NODES = args.html
    if args.output:
        OUTPUT_DIR = args.output
    if args.jsjoern:
        JSJOERN_DIR = args.jsjoern
        ESPRIMA_JS = os.path.join(JSJOERN_DIR, "esprima-joern/main.js")
        PHP2AST_CONVERTER = os.path.join(JSJOERN_DIR, "phpast2cpg")

    # # Parse HTML
    # htmlParsePluginFiles(pluginDIR=PLUGIN_DIR, output_directory=HTML_DIR_NODES)

    logging.basicConfig(
        format="[INTEGRATION]%(asctime)s %(levelname)s:%(message)s",
        level=logging.INFO,
        force=True,
    )

    run()

    logging.info("Done.")
