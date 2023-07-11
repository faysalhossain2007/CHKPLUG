# GDPR Checker
# Patrick Thomas pwt5ca
# Created 210109

from enum import Enum
from hashlib import md5
from typing import *

_PHP_START_TAG = "<?php"
_PHP_START_TAG_SHORTCUT = "<?"
_PHP_END_TAG = "?>"


class StartScopeEnum(Enum):
    SINGLE_QUOTE = "'"
    DOUBLE_QUOTE = '"'
    COMMENT = "//"
    MULTILINE_COMMENT = "/*"


class EndScopeEnum(Enum):
    SINGLE_QUOTE = "'"
    DOUBLE_QUOTE = '"'
    COMMENT = "\n"
    MULTILINE_COMMENT = "*/"


class PHPCutter:
    def __init__(self, src: str):
        self._src = src
        self._mapping: Dict[str, str] = dict()

    def cut_php(self):
        return self.walk()

    def walk(self) -> Tuple[str, Dict[str, str]]:
        i = 0

        scopes: List[StartScopeEnum] = []
        ranges: List[int] = []
        in_php: bool = False

        while i < len(self._src):
            if not in_php:
                if self._src[i:].startswith(_PHP_START_TAG):
                    in_php = True
                    ranges.append(i)
                    i += len(_PHP_START_TAG)
                elif self._src[i:].startswith(_PHP_START_TAG_SHORTCUT):
                    in_php = True
                    ranges.append(i)
                    i += len(_PHP_START_TAG_SHORTCUT)
                else:
                    i += 1
            else:
                # Check if we should exit PHP mode.
                if self._src[i:].startswith(_PHP_END_TAG) and not scopes:
                    in_php = False
                    i += len(_PHP_END_TAG)
                    ranges.append(i)
                    continue

                done = False
                # Check if we should leave the current scope.
                for end_e in EndScopeEnum:
                    if self._src[i:].startswith(end_e.value) and scopes:
                        if not scopes[-1].name == end_e.name:
                            break
                        scopes.pop()
                        i += len(end_e.value)
                        done = True
                        break
                if done:
                    continue
                # Check if we should be entering a scope.
                for start_e in StartScopeEnum:
                    if self._src[i:].startswith(start_e.value):
                        if scopes:
                            break
                        scopes.append(start_e)
                        i += len(start_e.value)
                        done = True
                        break
                if done:
                    continue
                i += 1

        if in_php:
            ranges.append(i)

        ranges.insert(0, 0)
        ranges.append(len(self._src))
        sub_strs = []
        cut_php = {}

        for i in range(len(ranges) - 1):
            start = ranges[i]
            end = ranges[i + 1]
            s = self._src[start:end]
            if i % 2 == 0:
                # In HTML
                sub_strs.append(s)
            else:
                # In PHP
                h = md5(s.encode()).hexdigest() + (s.count("\n") * "\n")
                sub_strs.append(h)
                cut_php[h] = s

        self._mapping = cut_php
        return "".join(sub_strs), cut_php

    @staticmethod
    def trim_php(php_code: str) -> str:
        php_code = php_code.strip()

        if php_code.startswith("<?php"):
            php_code = php_code[5:]
        elif php_code.startswith("<?"):
            php_code = php_code[2:]

        if php_code.endswith("?>"):
            php_code = php_code[:-2]

        return php_code.strip()


if __name__ == "__main__":
    code = ""
    with open(
        "/home/thomas/Documents/research/GDPR-CCPA-violation-checker/navex_docker/exampleApps/htmlParseTest/generic_1.php",
        "r",
    ) as f:
        code = f.read()
    p = PHPCutter(code)
    processed_php, mapping = p.cut_php()
    print("\n\n### BEFORE")
    print(code)
    print("\n\n### AFTER")
    print(processed_php)
