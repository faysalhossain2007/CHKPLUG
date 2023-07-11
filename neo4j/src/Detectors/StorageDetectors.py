# GDPR Checker - StorageDetectors.py
# Patrick Thomas pwt5ca
# Created 200615

from datetime import date
from typing import List

import py2neo
from Functions import FUNCTION_SENSITIVITY
from Settings import (
    ALL_WORDPRESS_FUNCTION_RETURN_TYPES,
    DATA_TYPE_ATTACHMENT,
    DATA_TYPE_BLOG,
    DATA_TYPE_FILE,
    DATA_TYPE_POST,
    DATA_TYPE_USER,
)

from .Detectors import AbstractDetector
from .FunctionFinding import FunctionFinding
from .Scores import ScoreType


class PHPStorageDetector(AbstractDetector):

    keywords = ["fwrite", "file_put_contents", "fputs", "fputcsv", "touch"]

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for various PHP functions that explicitly write to a file.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 5, 26))
        self.finding_type = ScoreType.STORAGE

    def __find(self):
        regex = f"(?i)({'|'.join(self.keywords)})"

        for finding in FunctionFinding.findings_from_function_name(
            self.graph, regex, self.finding_type, self
        ):
            finding.score.types = DATA_TYPE_FILE
            self.add_finding(finding)

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")


class PHPRetrievalDetector(AbstractDetector):

    keywords = [
        "fgetc",
        "fgetcsv",
        "fgets",
        "fgetss",
        "file_get_contents",
        "file",
        # "fopen",
        "fread",
        "fscanf",
        "readfile",
    ]

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for various PHP functions that explicitly read from a file.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 5, 26))
        self.finding_type = ScoreType.RETRIEVAL

    def __find(self):
        regex = f"(?i)({'|'.join(self.keywords)})"

        for finding in FunctionFinding.findings_from_function_name(
            self.graph, regex, self.finding_type, self
        ):
            finding.score.types = DATA_TYPE_FILE
            self.add_finding(finding)

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")


class WordPressStorageDetector(AbstractDetector):
    # Source: https://code.tutsplus.com/tutorials/wordpress-for-web-app-development-saving-data--wp-34268
    # See: https://codex.wordpress.org/Function_Reference

    all_keywords: List[str] = []

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for various WordPress functions that explicitly write to a file.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 5, 25))
        self.finding_type = ScoreType.STORAGE

    def __find(self, search_str: str):
        for finding in FunctionFinding.findings_from_function_name(
            self.graph, search_str, self.finding_type, self
        ):
            self.add_finding(finding)

    def _run(self):
        # self.__find("add_metadata", 4, DATA_TYPE_META)
        # self.__find("(add|update)_post_meta", 2, DATA_TYPE_POST_META)
        # self.__find("wp_(new|update|insert)_comment", 0, DATA_TYPE_COMMENT)
        # self.__find("wp_(insert|update)_post", 0, DATA_TYPE_POST)
        # self.__find("(add|update)_user_meta", 2, DATA_TYPE_USER_META)
        print(f"### Start running {self.__class__.__name__}")
        
        self.all_keywords = [
            k for k, v in FUNCTION_SENSITIVITY.items() if v.is_sensitive() and v.is_setter == True
        ]
        self.regex = f'({"|".join(self.all_keywords)})'
        self.__find(self.regex)
        print(f"### Finish running {self.__class__.__name__}")


class WordPressRetrievalDetector(AbstractDetector):
    # See: https://codex.wordpress.org/Function_Reference

    """Data types not checked:

    - Categories
    - Tags
    - Taxonomy
    - Feed functions
    """

    keywords_posts = [
        "get_adjacent_post",
        "get_boundary_post",
        "get_children",
        "get_extended",
        "get_next_post",
        "get_post_ancestors",
        "get_post_custom_keys",
        "get_post_custom_values",
        "get_post_custom",
        "get_post_field",
        "get_post",
        "get_posts",
        "get_the_author_posts",
        "get_the_author",
        "get_the_content",
        "get_the_content",
        "get_the_ID",
        "get_the_title",
        "the_content",
        "the_content",
        "the_ID",
        "the_post",
        "the_title_attribute",
        "the_title",
        *[str(k) for k, v in ALL_WORDPRESS_FUNCTION_RETURN_TYPES.items() if "WP_Post" in v],
    ]

    keywords_pages = [
        "get_all_page_ids",
        "get_ancestors",
        "get_page_by_path",
        "get_page_by_title",
        "get_page_children",
        "get_page",
        "get_pages",
        "wp_list_pages",
    ]

    keywords_attachments = [
        "get_attached_file",
        "wp_get_attachment_image_src",
        "wp_get_attachment_image",
        "wp_get_attachment_metadata",
        "wp_get_attachment_thumb_file",
        "wp_get_attachment_thumb_url",
        "wp_get_attachment_url",
    ]

    keywords_users = [
        "get_user_by",
        "get_userdata",
        "get_users",
        "wp_get_current_user",
        "get_user_meta",
        *[str(k) for k, v in ALL_WORDPRESS_FUNCTION_RETURN_TYPES.items() if "WP_User" in v],
    ]

    keywords_other = [
        "get_option",
        "get_user_option",
        "get_site_option",
        "get_transient",
        # "absint",  # Debug
        # "add_allowed_options",  # Debug
    ]

    # all_keywords = sorted(
    #     list(
    #         {
    #             *keywords_attachments,
    #             *keywords_other,
    #             *keywords_pages,
    #             *keywords_posts,
    #             *keywords_users,
    #         }
    #     )
    # )

    all_keywords: List[str] = []

    regex: str = ""

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for various WordPress functions that explicitly write to a file.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2021, 5, 25))
        self.finding_type = ScoreType.RETRIEVAL

    def __determine_source(self, s: str) -> List[str]:
        output: List[str] = []
        if s in self.keywords_attachments:
            output.extend(DATA_TYPE_ATTACHMENT)
        # elif s in self.keywords_other:
        #     output.extend(DATA_TYPE_ATTACHMENT)
        elif s in self.keywords_posts:
            output.extend(DATA_TYPE_POST)
        elif s in self.keywords_pages:
            output.extend(DATA_TYPE_BLOG)
        elif s in self.keywords_users:
            output.extend(DATA_TYPE_USER)

        # Return all sources that are true
        return output

    def __find(self):
        for finding in FunctionFinding.findings_from_function_name(
            self.graph, self.regex, self.finding_type, self
        ):
            self.add_finding(finding)

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.all_keywords = [
            k for k, v in FUNCTION_SENSITIVITY.items() if v.is_sensitive() and v.is_setter == False
        ]
        self.regex = f'({"|".join(self.all_keywords)})'
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")
