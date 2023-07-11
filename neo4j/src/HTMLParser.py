import argparse
import logging
import os
import re
from html.parser import HTMLParser
from traceback import print_exc
from typing import Dict, Iterable, List, Optional, Tuple

from PhpSourceUtils import PHPCutter
from Settings import (
    AST_HTML_ATTRIBUTE_TAG,
    AST_HTML_ATTRIBUTES_TAG,
    AST_HTML_CHAR_REF_TAG,
    AST_HTML_COMMENT_TAG,
    AST_HTML_ELEMENT_TAG,
    AST_HTML_ENTITY_REF_TAG,
    AST_HTML_KEY_TAG,
    AST_HTML_PHP_TAG,
    AST_HTML_PI_TAG,
    AST_HTML_TEXT_TAG,
    AST_HTML_VALUE_TAG,
    EDGES_HEADER,
    NODES_HEADER,
    ROOT_DIR,
)
from Utls import create_dir, getAllFilepathsWithEXT, read_file, writeCSVbyTab

# logging.basicConfig(
#     format="[HTML PARSE]%(asctime)s %(levelname)s:%(message)s", level=logging.INFO, force=True
# )

__GEN_DOTFILES = True
_UNCLOSED_TAGS = {"meta", "input", "br"}


class HTMLNode:
    __next_id = 0
    __file_id = -1

    def __init__(
        self,
        code: str = "",
        childnum: int = 0,
        name: str = "",
        parent_id: int = -1,
        type: str = "",
        lineno: int = -1,
    ):
        self.id = HTMLNode.__next_id
        HTMLNode.__next_id += 1

        self.labels: str = "AST_HTML"
        self.type: str = type
        self.flags: Optional[List[str]] = None  # no data
        self.lineno: Optional[int] = lineno
        self.code: str = code
        self.childnum: int = childnum
        self.funcid: Optional[int] = None  # no data
        self.name: Optional[str] = name
        self.classname: Optional[str] = None  # no data
        self.namespace: Optional[str] = None  # no data
        self.endlineno: Optional[int] = None  # no data
        self.doccomment: Optional[str] = None  # no data

        # Assign the file ID if needed.
        if parent_id == -1 and HTMLNode.__file_id >= 0:
            self.parentID = HTMLNode.__file_id
        else:
            self.parentID = parent_id

    def __repr__(self) -> str:
        return f"HTMLNode[{self.id}{', ' + self.code if self.code else ''},{self.type}]"

    def __hash__(self):
        return hash(tuple(self.csv_row()))

    def __str__(self):
        if len(self.code) < 20:
            return "\n".join(
                [f"{self.childnum}:{self.type}", self.code.replace('"', '\\"').strip()]
            )
        else:
            return "\n".join(
                [
                    f"{self.childnum}:{self.type}",
                    self.code.replace('"', '\\"').strip()[:17] + "...",
                ]
            )

    def csv_row(self) -> List[str]:
        t = (
            self.id,
            self.labels,
            self.type,
            self.flags,
            self.lineno,
            self.code,
            self.childnum,
            self.funcid,
            self.classname,
            self.namespace,
            self.endlineno,
            self.name,
            self.doccomment,
        )
        l = [str(v) for v in t]
        return l

    @staticmethod
    def set_next_id(next_id: int):
        """Set the starting ID of all new HTMLNodes.

        Args:
            next_id (int): Starting node ID. This is automatically incremented.
        """
        HTMLNode.__next_id = next_id

    @staticmethod
    def set_file_id(file_id: int):
        """Set the global parent file ID. All new HTML AST roots will point to the specified ID as the file parent.

        Args:
            file_id (int): File ID to point to. Should be an Filesystem node in Neo4j.
        """
        HTMLNode.__file_id = file_id


class PhpHtmlParser(HTMLParser):
    def __init__(self, filename: str, php_mapping: Dict[str, str] = {}) -> None:
        super().__init__()
        self.nodes: List[HTMLNode] = list()
        self.scopes: List[HTMLNode] = list()
        self.childnums: List[int] = [0]
        self.filename = filename

        self.php_mapping = php_mapping

        self.__root = HTMLNode(
            code="", childnum=0, name=self.filename, parent_id=-1, type="AST_HTML_ROOT"
        )
        self.add_node(self.__root)
        self.enter_scope(self.__root)
        self.new_nodes: List[HTMLNode] = []

        self.__sent_root = False

    def feed(self, s: str):
        old_nodes = set(self.nodes)
        super().feed(s)
        self.new_nodes = list(set(self.nodes).difference(old_nodes))

        if not self.__sent_root:
            self.new_nodes.insert(0, self.__root)
            self.__sent_root = True

        # Sort so nodes are created in the order they were instantiated.
        self.new_nodes.sort(key=lambda x: x.id)

    def to_dot_file(self) -> str:
        """Create a DOT file representation of the nodes for debugging and demonstration.

        Returns:
            str: DOT file representation for direct writing to graphviz.
        """
        labels = "\n\t".join([f"""{n.id} [label="{str(n)}"];""" for n in self.nodes])
        node_info = "\n\t".join(
            [f"""{n.parentID} -> {n.id};""" for n in self.nodes if n.parentID >= 0]
        )
        cleaned_name = re.sub(r"\W+", "_", self.filename)
        contents = f"""
digraph html_nodes_{cleaned_name} {{
\t// Labels
\t{labels}

\t// Edges
\t{node_info}
}}
"""
        return contents

    def add_node(self, node: HTMLNode, skip_php_expansion: bool = False, lineno: int = -1):
        """Internally register a new node in the AST.

        Args:
            node (HTMLNode): The node to add to the internal register.
        """
        node.childnum = self.childnums[-1]
        node.name = self.filename
        node.parentID = node.parentID if len(self.scopes) == 0 else self.scopes[-1].id
        node.lineno = lineno if lineno > 0 else self.getpos()[0]

        self.nodes.append(node)
        self.childnums[-1] += 1

        # Try to expand PHP references here.
        if not skip_php_expansion and node.code.strip():
            self.enter_scope(node)
            for k in self.php_mapping.keys():
                if k in node.code:
                    logging.debug(f"Substituting PHP back in: {k}")
                    # Save some information about how many lines are between the line root and the PHP code.
                    offset = node.code.find(k)
                    line_offset = node.code[:offset].count("\n")
                    node.code = node.code.replace(k, self.php_mapping[k])

                    php_node = HTMLNode(
                        code=PHPCutter.trim_php(self.php_mapping[k]),
                        type=AST_HTML_PHP_TAG,
                    )
                    self.add_node(
                        php_node,
                        skip_php_expansion=True,
                        lineno=self.getpos()[0] + line_offset,
                    )
            self.exit_scope()

    def enter_scope(self, node: HTMLNode):
        """Enter a scope for keeping track of parents.

        Args:
            node (HTMLNode): Scope parent.
        """
        self.scopes.append(node)
        self.childnums.append(0)
        s = self.scopes[-1].code.split("\n")[-1].strip()
        logging.debug(f"Entering scope {s[:min(20, len(s))]}")

    def exit_scope(self):
        """Exit the current scope."""
        if len(self.scopes) == 0:
            logging.warning("Cannot exit scope: scope stack is empty!")
            return
        s = self.scopes[-1].code.split("\n")[-1]
        logging.debug(f"Exiting scope {s[:min(20, len(s))]}")
        self.scopes.pop()
        self.childnums.pop()

    def get_nodes(self) -> List[HTMLNode]:
        """Get a list of nodes representing all nodes thus so far.

        Returns:
            List[HTMLNode]: List of HTMLNodes, should consist of entire graph.
        """
        return self.nodes

    def handle_charref(self, name):
        logging.debug(f"handle_charref name={name}")
        n = HTMLNode(code=name, type=AST_HTML_CHAR_REF_TAG)
        self.add_node(n)

    def handle_comment(self, data):
        logging.debug(f"handle_comment data={data}")
        n = HTMLNode(code=data, type=AST_HTML_COMMENT_TAG)
        self.add_node(n)

    def handle_data(self, data):
        # Skip data that is just whitespace
        if data.strip() == "":
            return
        logging.debug(f"handle_data data={data.strip()}")

        # Append code to previous data node if possible.
        if self.nodes[-1].type == AST_HTML_TEXT_TAG:
            self.nodes[-1].code += str(data)
        else:
            n = HTMLNode(code=data, type=AST_HTML_TEXT_TAG)
            self.add_node(n)

    def handle_decl(self, decl):
        logging.debug(f"handle_decl decl={decl}")
        n = HTMLNode(
            code=decl,
            type="AST_HTML_DECL",
        )
        self.add_node(n)

    def handle_endtag(self, tag):
        logging.debug(f"handle_endtag tag={tag}")
        self.exit_scope()

    def handle_entityref(self, name):
        logging.debug(f"handle_entityref name={name}")
        n = HTMLNode(code=name, type=AST_HTML_ENTITY_REF_TAG)
        self.add_node(n)

    def handle_pi(self, data):
        logging.debug(f"handle_pi data={data}")
        data = data.strip()
        n = HTMLNode(code=data, type=AST_HTML_PI_TAG)
        self.add_node(n)

    def handle_startendtag(self, tag, attrs):
        element_node = HTMLNode(code=tag, type=AST_HTML_ELEMENT_TAG)
        self.add_node(element_node)
        self.enter_scope(element_node)
        if len(attrs) > 0:
            attrs_node = HTMLNode(code="", type=AST_HTML_ATTRIBUTES_TAG)
            self.add_node(attrs_node)
            self.enter_scope(attrs_node)
            for key, value in attrs:
                attr_node = HTMLNode(code="", type=AST_HTML_ATTRIBUTE_TAG)
                self.add_node(attr_node)
                self.enter_scope(attr_node)
                key_node = HTMLNode(code=key, type=AST_HTML_KEY_TAG)
                self.add_node(key_node)
                if value:
                    value_node = HTMLNode(code=value, type=AST_HTML_VALUE_TAG)
                    self.add_node(value_node)
                self.exit_scope()  # Attr node scope
            self.exit_scope()  # Attrs node scope
        self.exit_scope()  # Element node scope
        logging.debug(f"handle_startendtag tag={tag} attrs={attrs}")

    def handle_starttag(self, tag, attrs):
        element_node = HTMLNode(code=tag, type=AST_HTML_ELEMENT_TAG)
        self.add_node(element_node)
        self.enter_scope(element_node)
        if len(attrs) > 0:
            attrs_node = HTMLNode(code="", type=AST_HTML_ATTRIBUTES_TAG)
            self.add_node(attrs_node)
            self.enter_scope(attrs_node)
            for key, value in attrs:
                attr_node = HTMLNode(code="", type=AST_HTML_ATTRIBUTE_TAG)
                self.add_node(attr_node)
                self.enter_scope(attr_node)
                key_node = HTMLNode(code=key, type=AST_HTML_KEY_TAG)
                self.add_node(key_node)
                if value:
                    value_node = HTMLNode(code=value, type=AST_HTML_VALUE_TAG)
                    self.add_node(value_node)
                self.exit_scope()  # Attr node scope
            self.exit_scope()  # Attrs node scope
        # Meta tags may not be correctly parsed?
        if tag in _UNCLOSED_TAGS:
            self.exit_scope()
        logging.debug(f"handle_starttag tag={tag} attrs={attrs}")

    def handle_php(self, data):
        logging.debug(f"handle_php data={data}")
        data = data.strip()
        n = HTMLNode(code=data, type=AST_HTML_PHP_TAG)
        self.add_node(n)

    def unknown_decl(self, data: str) -> None:
        logging.warning(f"unknown decl encountered: {data}")


def format_html_code(html_code):
    code = re.sub(r"\s+", " ", html_code).strip()
    return code


def startFileParsing(codeList: Iterable[Tuple[str, str]], output_directory: str) -> List[HTMLNode]:
    nodes: List[HTMLNode] = []

    # Try to create dot files; if fail, then disable for the rest of the run.
    global __GEN_DOTFILES
    if __GEN_DOTFILES:
        try:
            with open("dot/graph.gv", "w") as f:
                pass
        except:
            __GEN_DOTFILES = False

    for code, filename in codeList:
        # Cut the PHP out temporarily.
        stripped, mapping = PHPCutter(code).cut_php()

        # Parse the HTML/PHP into nodes/tokens
        p = PhpHtmlParser(filename, mapping)
        p.feed(stripped)
        p.close()

        # Save the parsed nodes.
        nodes.extend(p.get_nodes())

        # Create dot files for visualization if enabled.
        if __GEN_DOTFILES:
            with open("dot/graph.gv", "a") as f:
                print(p.to_dot_file(), file=f)

    return nodes


def writeEdgesInCSV(nodes, output_directory=None):
    create_dir(output_directory)
    data = [
        EDGES_HEADER,
        *[[int(node.parentID), int(node.id), "PARENT_OF"] for node in nodes if node.parentID >= 0],
    ]
    writeCSVbyTab(os.path.join(output_directory, "edges.csv"), data, "w")


def writeNodesInCSV(nodes: List[HTMLNode], output_directory=None):
    create_dir(output_directory)

    data: List[List[str]] = [NODES_HEADER, *[n.csv_row() for n in nodes]]
    writeCSVbyTab(os.path.join(output_directory, "nodes.csv"), data, "w")


def test():
    html_code = """
<form class="gdpr-request-form gdpr-add-to-deletion-requests" method="post">
    <?php wp_nonce_field('gdpr-add-to-requests', 'gdpr_request_nonce'); ?>
    <input type="hidden" name="action" value="gdpr_send_request_email" />
    <input type="hidden" name="type" value="delete" />
    <?php if (!is_user_logged_in()) : ?>
        <input type="email" name="user_email" placeholder="<?php esc_attr_e('email@domain.com', 'gdpr'); ?>" required />
    <?php endif ?>
    <?php GDPR_Public::add_recaptcha(); ?>
    <?php $submit_button_text = ($args['submit_button_text'] ?: esc_attr__('Close my account', 'gdpr')); ?>
    <input type="submit" value="<?php echo esc_attr($submit_button_text); ?>" />
</form>
"""
    stripped, mapping = PHPCutter(html_code).cut_php()
    p = PhpHtmlParser("test.php", mapping)
    p.feed(stripped)
    p.close()

    from pprint import pprint

    pprint(p.get_nodes())
    print(stripped)
    #pprint(stripped)
    pprint(mapping)


def htmlParsePluginFiles(pluginDIR: str, output_directory: str):
    paths, total_files = getAllFilepathsWithEXT(pluginDIR, ".php")
    logging.info(f"Found {total_files} files ending with .php")

    code_file_tuples: List[Tuple[str, str]] = list()
    for file in paths:
        try:
            logging.debug(f"Parsing File {file}")
            code_file_tuples.append((read_file(file), file))
        except:
            logging.error(f"Error parsing file {file}")
            print_exc()

    nodes = startFileParsing(code_file_tuples, output_directory)

    # create nodes.csv
    writeNodesInCSV(nodes, output_directory)
    # create edges.csv
    writeEdgesInCSV(nodes, output_directory)

    logging.info(f"Created {len(nodes)} nodes")
    for node in nodes:
        c = node.code[: min(len(node.code), 20)]
        logging.debug(f"id={node.id} c={c} node.names={node.name}")


if __name__ == "__main__":
    # Parse some arguments for batch runs.
    parser = argparse.ArgumentParser(description="Merge JS and PHP ASTs.")
    parser.add_argument("-s", "--source", help="Plugin location.", type=str)
    parser.add_argument("-o", "--output", help="Output directory.", type=str)

    args = parser.parse_args()

    plugin_dir = os.path.join(
        ROOT_DIR,
        "jsjoern-uva/exampleApps/woo-empatkali-checkout-gateway/woo-empatkali-checkout-gateway/",
    )
    output_dir = os.path.join(ROOT_DIR, "neo4j/src/integration/results-html/")

    if args.source:
        plugin_dir = args.source
    if args.output:
        output_dir = args.output

    logging.info("HTMLParser.py")
    logging.debug(f"plugin_dir={plugin_dir}")
    logging.debug(f"output_dir={output_dir}")

    # run()
    # test()
    htmlParsePluginFiles(plugin_dir, output_directory=output_dir)

    logging.info("Done")
