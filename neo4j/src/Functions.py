import csv
import os
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, Set

from Settings import (
    DATA_TYPE_ATTACHMENT,
    DATA_TYPE_ATTACHMENT_META,
    DATA_TYPE_BLOG,
    DATA_TYPE_BLOG_OPTION,
    DATA_TYPE_CATEGORY,
    DATA_TYPE_COMMENT,
    DATA_TYPE_COMMENT_META,
    DATA_TYPE_META,
    DATA_TYPE_OPTION,
    DATA_TYPE_POST,
    DATA_TYPE_POST_META,
    DATA_TYPE_SITE,
    DATA_TYPE_SITE_META,
    DATA_TYPE_SITE_TRANSIENT,
    DATA_TYPE_TERM,
    DATA_TYPE_USER,
    DATA_TYPE_USER_META,
    SRC_DIR,
    DATA_TYPE_CITY,
    DATA_TYPE_ADDRESS,
    DATA_TYPE_BIRTHDAY,
    DATA_TYPE_COUNTRY,
    DATA_TYPE_EMAIL,
    DATA_TYPE_FIRST_NAME,
    DATA_TYPE_IP,
    DATA_TYPE_LAST_NAME,
    DATA_TYPE_PASSWORD,
    DATA_TYPE_POSTCODE,
    DATA_TYPE_STATE,
    DATA_TYPE_ZIPCODE,
)

CONFLICTED_PATH = os.path.join(
    SRC_DIR, "function_information", "wp_functions_conflict_resolution.csv"
)
ALL_PATH = os.path.join(SRC_DIR, "function_information", "wp_functions_jerry.csv")

FUNCTION_PARAM_INFO_PATH = os.path.join(SRC_DIR, "function_information", "wp_function_key_param.csv")


class Sensitivity(Enum):
    NONSENSITIVE = auto()
    SENSITIVE = auto()
    DYNAMIC = auto()

    @staticmethod
    def from_str(s):
        if s == "sensitive":
            return Sensitivity.SENSITIVE
        elif s == "dynamic":
            return Sensitivity.DYNAMIC
        else:
            return Sensitivity.NONSENSITIVE


@dataclass
class FunctionInfo:
    sensitivity: Sensitivity
    is_setter: Optional[bool]
    data_type: Set[str]
    #this denotes which parameter is used as key to store/retrieve data. If it is unknown, the default value is -1
    key_param: int
    #this denotes which parameter is used to store data. If it is unknown, the default value is -1
    data_param: int
    def is_sensitive(self):
        return self.sensitivity != Sensitivity.NONSENSITIVE


global FUNCTION_SENSITIVITY
FUNCTION_SENSITIVITY: Dict[str, FunctionInfo] = dict()


def load_function_info():
    # First load all of the first-pass manual analysis results.
    with open(ALL_PATH, "r", newline="") as f:
        reader = csv.reader(f)
        header = False
        for row in reader:
            # Skip the header.
            if not header:
                header = True
                continue

            (
                func_name,
                sensitivity_str,
                setter_retriever,
                data_type,
                _,
                data_type_std,
            ) = row

            data_type_set: Set[str] = set()
            if data_type_std == "attachment":
                data_type_set = DATA_TYPE_ATTACHMENT
            elif data_type_std == "attachment_meta":
                data_type_set = DATA_TYPE_ATTACHMENT_META
            elif data_type_std == "blog":
                data_type_set = DATA_TYPE_BLOG
            elif data_type_std == "blog_option":
                data_type_set = DATA_TYPE_BLOG_OPTION
            elif data_type_std == "category":
                data_type_set = DATA_TYPE_CATEGORY
            elif data_type_std == "comment":
                data_type_set = DATA_TYPE_COMMENT
            elif data_type_std == "comment_meta":
                data_type_set = DATA_TYPE_COMMENT_META
            elif data_type_std == "meta":
                data_type_set = DATA_TYPE_META
            elif data_type_std == "option":
                data_type_set = DATA_TYPE_OPTION
            elif data_type_std == "post":
                data_type_set = DATA_TYPE_POST
            elif data_type_std == "post_meta":
                data_type_set = DATA_TYPE_POST_META
            elif data_type_std == "site":
                data_type_set = DATA_TYPE_SITE
            elif data_type_std == "site_meta":
                data_type_set = DATA_TYPE_SITE_META
            elif data_type_std == "site_transient":
                data_type_set = DATA_TYPE_SITE_TRANSIENT
            elif data_type_std == "term":
                data_type_set = DATA_TYPE_TERM
            elif data_type_std == "user":
                data_type_set = DATA_TYPE_USER
            elif data_type_std == "user_meta":
                data_type_set = DATA_TYPE_USER_META
            elif data_type_std == "email":
                data_type_set = DATA_TYPE_EMAIL
            elif data_type_std == "ip":
                data_type_set = DATA_TYPE_IP
            elif data_type_std == "first_name":
                data_type_set = DATA_TYPE_FIRST_NAME
            elif data_type_std == "last_name":
                data_type_set = DATA_TYPE_LAST_NAME
            elif data_type_std == "user_meta":
                data_type_set = DATA_TYPE_USER_META
            FUNCTION_SENSITIVITY[func_name.strip()] = FunctionInfo(
                Sensitivity.from_str(sensitivity_str.strip()),
                "set" in setter_retriever.strip().lower(),
                data_type_set,
                -1,
                -1
            )

    # Override any previous analysis with the conflict resolution CSV if needed.
    with open(CONFLICTED_PATH, "r", newline="") as f:
        reader = csv.reader(f)
        header = False
        for row in reader:
            # Skip the header.
            if not header:
                header = True
                continue

            func_name, _, _, _, sensitivity_str = row
            FUNCTION_SENSITIVITY[func_name].sensitivity = Sensitivity.from_str(sensitivity_str)
    with open(FUNCTION_PARAM_INFO_PATH, "r", newline="") as f:
        reader = csv.reader(f)
        header = False
        for row in reader:
            # Skip the header.
            if not header:
                header = True
                continue

            (
                func_name,
                key_param,
                data_param,
            ) = row
            FUNCTION_SENSITIVITY[func_name].data_param = int(data_param)
            FUNCTION_SENSITIVITY[func_name].key_param = int(key_param)
