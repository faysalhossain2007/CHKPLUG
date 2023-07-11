import collections
import json
import os
from typing import Any, OrderedDict

NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")

NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "1")
NEO4J_BOLT_PORT = "7687"
NEO4J_HTTP_PORT = "7474"
NEO4J_HOST = "localhost"
NEO4J_BOLT_CONNECTION_STRING = f"bolt://{NEO4J_HOST}:{NEO4J_BOLT_PORT}"

# ROOT_DIR_FAYSAL = "/home/faysal/code/jhu/gdpr/GDPR-CCPA-violation-checker/"
# ROOT_DIR_JERRY = "/Users/jerrysu/Documents/GDPR-CCPA-violation-checker/"
# ROOT_DIR_PATRICK = "/home/thomas/Documents/research/GDPR-CCPA-violation-checker/"
# ROOT_DIR = ROOT_DIR_FAYSAL  # you need to change it
ROOT_DIR = (
    os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")) + "/"
)

SRC_DIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__)))

# Nodes/edges import headers.
EDGES_HEADER = ["start", "end", "type"]
NODES_HEADER = [
    "id:int",
    "labels:label",
    "type",
    "flags:string_array",
    "lineno:int",
    "code",
    "childnum:int",
    "funcid:int",
    "classname",
    "namespace",
    "endlineno:int",
    "name",
    "doccomment",
]
HOOK_INFO_STORE_PATH = 'PluginHookInfo.csv'
FN_SENSITIVITY_INFO_PATH = 'PluginFunctionSensitivity.csv'

MINIMUM_ROW_NUMBER = 10000

NAVEX_DOCKER_DIR = ROOT_DIR + "navex_docker/"
RESULT_DIR = NAVEX_DOCKER_DIR + "result/results/"
NODES_CSV_FILE_LOC = RESULT_DIR + "nodes.csv"
NODES_CSV_MODIFIED_FILE_LOC = RESULT_DIR + "nodes_w.csv"
EDGES_CSV_FILE_LOC = RESULT_DIR + "edges.csv"
EDGES_CSV_MODIFIED_FILE_LOC = RESULT_DIR + "edges_w.csv"
CPG_EDGES_CSV_FILE_LOC = RESULT_DIR + "cpg_edges.csv"
CPG_EDGES_CSV_MODIFIED_FILE_LOC = RESULT_DIR + "cpg_edges_w.csv"

NEO4J_FILE_PREFIX = "file:/"

EXAMPLE_APPS_DIR = NAVEX_DOCKER_DIR + "exampleApps/"
GDPR_PLUGIN_DIR = EXAMPLE_APPS_DIR + "gdprplugin/"
JS_FILE_GDPR_ADMIN = GDPR_PLUGIN_DIR + "src/js/admin/gdpr-admin.js"

COLUMN_INDEX_START = "start"
COLUMN_INDEX_END = "end"
COLUMN_INDEX_TYPE = "type"
COLUMN_INDEX_VAR = "var"
COLUMN_INDEX_TAINTSRC = "taint_src"
COLUMN_INDEX_TAINTDST = "taint_dst"
COLUMN_INDEX_FLOWLABEL = "flowLabel"


COLUMN_INDEX_ID = "id:int"
COLUMN_INDEX_LABELS = "labels:label"
COLUMN_INDEX_TYPE = "type"
COLUMN_INDEX_FLAGS = "flags:string_array"
COLUMN_INDEX_LINE = "lineno:int"
COLUMN_INDEX_CODE = "code"
COLUMN_INDEX_CHILDNUM = "childnum:int"
COLUMN_INDEX_FUNCID = "funcid:int"
COLUMN_INDEX_CLASSNAME = "classname"
COLUMN_INDEX_NAMESPACE = "namespace"
COLUMN_INDEX_ENDLINE = "endlineno:int"
COLUMN_INDEX_NAME = "name"
COLUMN_INDEX_DOCCOMMENT = "doccomment"


TAG_NODE = "node"
TAG_EDGES = "edges"
TAG_CPG_EDGES = "cpg_edges"


TAG_POST = "post"
TAG_GET = "get"
TAG_PUT = "put"
TAG_INPUT = "input"
TAG_TD = "td"
TAG_VARIABLE = "variable"
TAG_UI_ELEMENT = "ui-element"
TAG_ID = "id"

TAG_SUCCESS = 1
TAG_FAILED = 0

AST_JS = "AST_JS_"

TAG_AST_ARRAY_ELEM = "AST_ARRAY_ELEM"
TAG_AST_CALL = "AST_CALL"
TAG_AST_ARRAY = "AST_ARRAY"
TAG_AST_METHOD_CALL = "AST_METHOD_CALL"
TAG_AST_ASSIGN = "AST_ASSIGN"
TAG_AST_VAR = "AST_VAR"


AST_HTML = "AST_HTML_"
AST_HTML_KEY_TAG = AST_HTML + "KEY"
AST_HTML_VALUE_TAG = AST_HTML + "VALUE"
AST_HTML_ELEMENT_TAG = AST_HTML + "ELEMENT"
AST_HTML_TEXT_TAG = AST_HTML + "TEXT"
AST_HTML_ATTRIBUTES_TAG = AST_HTML + "ATTRIBUTES"
AST_HTML_ATTRIBUTE_TAG = AST_HTML + "ATTRIBUTE"
AST_HTML_PI_TAG = AST_HTML + "PI"
AST_HTML_ENTITY_REF_TAG = AST_HTML + "ENTITY_REF"
AST_HTML_COMMENT_TAG = AST_HTML + "COMMENT"
AST_HTML_CHAR_REF_TAG = AST_HTML + "CHAR_REF"
AST_HTML_PHP_TAG = AST_HTML + "PHP"

MSG_NODE_NOT_FOUND = "NODE NOT FOUND"

TAG_PHP_EXT = ".php"

ENCRYPTION_PARALLEL = True  # Should encryption detectors be ran in parallel.

f = None
__function_info_path = os.path.join(SRC_DIR, "Detectors", "wordpress_functions.json")
with open(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), __function_info_path), "r"
) as f:
    s = f.read()
    ALL_WORDPRESS_FUNCTIONS: OrderedDict[str, Any] = json.JSONDecoder(
        object_pairs_hook=collections.OrderedDict
    ).decode(s)
del f, s

ALL_WORDPRESS_FUNCTION_RETURN_TYPES = {
    k: v.get("returns", {}).get("types", []) for k, v in ALL_WORDPRESS_FUNCTIONS.items()
}

DATA_TYPE_ATTACHMENT = frozenset({"attachment", "attachment_meta"})
DATA_TYPE_ATTACHMENT_META = frozenset({"attachment_meta"})
DATA_TYPE_BLOG = frozenset({"blog", "blog_option", "option"})
DATA_TYPE_BLOG_OPTION = frozenset({"option", "blog_option"})
DATA_TYPE_CATEGORY = frozenset({"category"})
DATA_TYPE_COMMENT = frozenset({"comment", "comment_meta"})
DATA_TYPE_COMMENT_META = frozenset({"comment_meta"})
DATA_TYPE_META = frozenset({"meta"})  # Defined by first argument to add_metadata
DATA_TYPE_OPTION = frozenset({"option"})
DATA_TYPE_POST = frozenset({"post", "post_meta", "wp_post"})
DATA_TYPE_POST_META = frozenset({"post_meta"})
DATA_TYPE_SITE = frozenset({"site", "site_meta", "site_transient"})
DATA_TYPE_SITE_META = frozenset({"site_meta"})
DATA_TYPE_SITE_TRANSIENT = frozenset({"site"})
DATA_TYPE_TERM = frozenset({"term"})
DATA_TYPE_USER = frozenset({"user", "user_meta"})
DATA_TYPE_USER_META = frozenset({"user_meta"})
DATA_TYPE_FILE = frozenset({"file"})  # For raw file writes.
DATA_TYPE_DATABASE = frozenset({"database"})  # For database queries.
DATA_TYPE_REMOTE = frozenset({"remote"})  # For APIs and remote operations.

DATA_TYPE_EMAIL = frozenset({'email'})
DATA_TYPE_ADDRESS = frozenset({'address'})
DATA_TYPE_IP = frozenset({'ip'})
DATA_TYPE_FIRST_NAME = frozenset({"first_name"})
DATA_TYPE_LAST_NAME = frozenset({"last_name"})
DATA_TYPE_PASSWORD = frozenset({"password"})
DATA_TYPE_COUNTRY = frozenset({"country"})
DATA_TYPE_STATE = frozenset({"state"})
DATA_TYPE_ZIPCODE = frozenset({"zipcode"})
DATA_TYPE_POSTCODE = frozenset({"postcode"})
DATA_TYPE_CITY = frozenset({"city"})
DATA_TYPE_BIRTHDAY = frozenset({"birth"})
DATA_TYPE_PHONE = frozenset({'phone'})





EVALUATE_EXPRESSION_IGNORED = "AST_EMPTY"

LRU_CACHE_SIZE = None
MAX_NODE_CODE_LENGTH = 300  # Maximum length for a Neo4j node's code field -- limited by index

USEFUL_NODES = {
    "AST_VAR",
    "AST_CONST",
    "string",
    "integer",
    "AST_CALL",
    "AST_STATIC_CALL",
    "AST_METHOD_CALL",
    "AST_ARRAY",
    "AST_PROP",
    "AST_DIM",
    "AST_RETURN",
    "AST_NEW",
    "AST_ENCAPS_LIST",
    "BINARY_CONCAT",
    "AST_MAGIC_CONST",
    "AST_LIST",
    "AST_ECHO",
    "AST_CLASS_CONST",
    "AST_CLOSURE_VAR"

}
