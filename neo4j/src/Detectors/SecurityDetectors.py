# GDPR Checker - SecurityDetectors.py
# Patrick Thomas pwt5ca
# Created 200615

from NeoHelper import getNode
from datetime import date

import py2neo

from .Detectors import IGNORE_MD5, IGNORE_SHA1, AbstractDetector
from .FunctionFinding import FunctionFinding
from .Scores import Score, ScoreType


class PHPIncludedDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Initialize the detector that looks for security functions that come bundled with PHP.

        Example usage:
        ```py
        detector = PHPIncludedDetector(graph)
        detector.run()
        report = detector.report().strip()
        if report != "":
            print(report)
        ```

        Args:
            graph (py2neo.Graph): Graph containing AST to be analyzed.
        """
        super().__init__(graph, date(2021, 5, 25))
        self.finding_type = ScoreType.CRYPTOGRAPHY

    def __find_crypt(self):
        query = """
        match (m)-[:PARENT_OF*..2]->(n) 
        where m.type =~ "AST_CALL" and n.code =~ "crypt"
        RETURN COLLECT(DISTINCT n.id)
        """
        crypt = self.graph.evaluate(query)

        for node_id in crypt:
            if not node_id:
                continue
            # Get the number of arguments to the crypt call.
            query = f"""
            match (a)<-[:PARENT_OF*]-(b)-[:PARENT_OF*]->(c) 
            where b.type =~ "AST_CALL" 
                and c.id = {node_id}
                and a.type =~ "AST_ARG_LIST"
            match (a)-[:PARENT_OF]->(d)
            return count(d)
            """
            results = self.graph.run(query).data()
            count = results[0]["count(d)"]
            score = None
            reason = None
            if count == 1:
                # No salt provided.
                score = Score.encrypt_score(False, False, "crypt")
                reason = "No salt provided."
            elif count == 2:
                # Used with salt, but usage still not recommended.
                score = Score.encrypt_score(False, False, "crypt")
                reason = "Salt provided, however password_hash is recommended over crypt (https://www.php.net/crypt)."
            else:
                score = Score.error_score()
                reason = "More/less arguments for crypt encountered than expected."
            self.new_finding(node_dict=getNode(node_id), score=score, reason=reason)

    def __find_simple(self, name: str):
        query = f"""
        match (m)-[:PARENT_OF*..2]->(n) 
        where m.type =~ "AST_CALL" and n.code =~ "{name}" 
        RETURN COLLECT(DISTINCT n.id)
        """
        query_results = self.graph.evaluate(query)

        for node_id in query_results:
            query = f"""
            match (a)<-[:PARENT_OF*]-(b)-[:PARENT_OF*]->(c) 
            where b.type =~ "AST_CALL" and c.id = {node_id} and a.type =~ "AST_ARG_LIST"
            match (a)-[:PARENT_OF*]->(d) where d.type =~ "string"
            return d as n
            """
            params = self.graph.run(query)
            param_strs = set(param_node["n"]["code"] for param_node in params)
            param_f = ", ".join(param_strs)
            self.new_finding(
                node_dict=getNode(node_id),
                score=Score.encrypt_score(
                    is_state_of_the_art=False,
                    is_maintained=True,
                    encryption_method=name,
                ),
                reason=f"{name.upper()} called with parameters [{param_f}]. Ignore if [{param_f}] does not contain personal information.",
            )

    def __find_md5(self):
        self.__find_simple("md5")

    def __find_sha1(self):
        self.__find_simple("sha1")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_crypt()
        if not IGNORE_MD5:
            self.__find_md5()
        if not IGNORE_SHA1:
            self.__find_sha1()
        print(f"### Finish running {self.__class__.__name__}")


class PasswordHashingDetector(AbstractDetector):
    # Algorithms that can be detected and are supported by password_hash
    supported_algorithms = {
        "PASSWORD_DEFAULT",
        "PASSWORD_BCRYPT",
        "PASSWORD_ARGON2I",
        "PASSWORD_ARGON2ID",
    }

    def __init__(self, graph: py2neo.Graph):
        """
        Detect usages of the PHP Password Hashing library, which provides wrappers around `crypt`.

        This only detects usages of `password_hash()`, and can handle the following algorithms:

        -   `PASSWORD_DEFAULT`
        -   `PASSWORD_BCRYPT`
        -   `PASSWORD_ARGON2I`
        -   `PASSWORD_ARGON2ID`

        It is currently assumed that all of the algorithms are currently secure (as of June 2020).

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2020, 7, 6))
        self.finding_type = ScoreType.CRYPTOGRAPHY

    def __find_password_hash(self):
        for keyword in ["password_hash", "password_verify"]:
            query = f"""
            match (m)-[:PARENT_OF*..2]->(n) 
            where m.type =~ "AST_CALL" and n.code =~ "{keyword}" 
            RETURN COLLECT(DISTINCT n.id)
            """
            query_results = self.graph.evaluate(query)

            for node_id in query_results:
                query = f"""
                match (a)<-[:PARENT_OF*]-(b)-[:PARENT_OF*]->(c) 
                where b.type =~ "AST_CALL" and c.id = {node_id} and a.type =~ "AST_ARG_LIST"
                match (a)-[:PARENT_OF*]->(d) where d.type =~ "string"
                return d as n
                """
                params = self.graph.run(query)
                param_strs = set(param_node["n"]["code"] for param_node in params)
                used_alg = ""
                for alg in self.supported_algorithms:
                    if alg in param_strs:
                        used_alg = alg
                        break
                if used_alg == "PASSWORD_DEFAULT":
                    used_alg += " (which uses PASSWORD_BCRYPT)"  # as of June 2020
                self.new_finding(
                    node_dict=getNode(node_id),
                    score=Score.encrypt_score(True, True, used_alg),
                    reason=f"{keyword} called with hash algorithm {used_alg}.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_password_hash()
        print(f"### Finish running {self.__class__.__name__}")


class OpenSSLDetector(AbstractDetector):
    """Detect OpenSSL usages, specifically of the functions `openssl_encrypt()`, `openssl_decrypt()`, and `openssl_digest()`.

    PHP documentation: <https://www.php.net/manual/en/book.openssl.php>
    """

    encrypt_decrypt_re = "openssl_(de|en)crypt"
    hash_re = "openssl_digest"

    approved_mds = set(AbstractDetector.settings["openssl"]["approved_hashes"])
    approved_ciphers = set(AbstractDetector.settings["openssl"]["approved_ciphers"])
    all_mds = set(AbstractDetector.settings["openssl"]["all_hashes"])
    all_ciphers = set(AbstractDetector.settings["openssl"]["all_ciphers"])

    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 6))
        self.finding_type = ScoreType.CRYPTOGRAPHY

    def __find_openssl_encrypt(self):
        param_nodes = self._find_with_arg(self.encrypt_decrypt_re, 1)
        for node, params in param_nodes.items():
            param_set = set(param["code"].lower() for param in params)
            intersect_approved = param_set.intersection(self.approved_ciphers)
            intersect_all = param_set.intersection(self.all_ciphers)
            if len(intersect_approved) >= 1:
                alg = intersect_approved.pop()
                self.new_finding(
                    node_dict=node,
                    score=Score.encrypt_score(True, True, alg),
                    reason=f"{node['code']} called with approved encryption algorithm {alg}.",
                )
            elif len(intersect_all) >= 1:
                alg = intersect_approved.pop()
                self.new_finding(
                    node_dict=node,
                    score=Score.encrypt_score(True, True, alg),
                    reason=f"{node['code']} called with unapproved encryption algorithm {alg}. Ignore if this is not encrypting personal information",
                )
            else:
                self.new_finding(
                    node_dict=node,
                    score=Score.error_score(),
                    reason=f"{node['code']} called with unknown encryption algorithm.",
                )

    def __find_openssl_digest(self):
        param_nodes = self._find_with_arg(self.hash_re, 1)
        for node, params in param_nodes.items():
            param_set = set(param["code"].lower() for param in params)
            intersect_approved = param_set.intersection(self.approved_mds)
            intersect_all = param_set.intersection(self.all_mds)
            if len(intersect_approved) >= 1:
                alg = intersect_approved.pop()
                self.new_finding(
                    node_dict=node,
                    score=Score.encrypt_score(True, True, alg),
                    reason=f"{node['code']} called with approved hash algorithm {alg}.",
                )
            elif len(intersect_all) >= 1:
                alg = intersect_all.pop()
                self.new_finding(
                    node_dict=node,
                    score=Score.encrypt_score(False, True, alg),
                    reason=f"{node['code']} called with unapproved hash algorithm {alg}. Ignore if this is not encrypting personal information",
                )
            else:
                self.new_finding(
                    node_dict=node,
                    score=Score.error_score(),
                    reason=f"{node['code']} called with unknown hash algorithm.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_openssl_encrypt()
        self.__find_openssl_digest()
        print(f"### Finish running {self.__class__.__name__}")


class HashDetector(AbstractDetector):
    """Detect usages of PHP's HASH Message Digest Framework

    PHP documentation: https://www.php.net/manual/en/book.hash.php

    Safe/approved hashes are configured in `SecurityFunctions.json`. Primarily looks for `hash()`
    and `hash_hmac()`.
    """

    all_mds = AbstractDetector.settings["php_hash"]["all_hashes"]
    approved_mds = AbstractDetector.settings["php_hash"]["approved_hashes"]

    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 6))
        self.finding_type = ScoreType.CRYPTOGRAPHY

    def __find_hash(self):
        param_nodes = self._find_with_arg("hash(_hmac|)", 0)
        for node, params in param_nodes.items():
            param_set = set(param["code"].lower() for param in params)
            intersect_approved = param_set.intersection(self.approved_mds)
            intersect_all = param_set.intersection(self.all_mds)
            if len(intersect_approved) >= 1:
                alg = intersect_approved.pop()
                self.new_finding(
                    node_dict=node,
                    score=Score.encrypt_score(True, True, alg),
                    reason=f"{node['code']} called with approved hash algorithm {alg}.",
                )
            elif len(intersect_all) >= 1:
                alg = intersect_all.pop()
                self.new_finding(
                    node_dict=node,
                    score=Score.encrypt_score(False, True, alg),
                    reason=f"{node['code']} called with unapproved hash algorithm {alg}. Ignore if this is not encrypting personal information",
                )
            else:
                self.new_finding(
                    node_dict=node,
                    score=Score.error_score(),
                    reason=f"{node['code']} called with unknown hash algorithm.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_hash()
        print(f"### Finish running {self.__class__.__name__}")


class DefuseDetector(AbstractDetector):
    """Detect usages of Defuse security: <https://github.com/defuse/php-encryption>

    At time of writing, **Defuse uses aes-256-ctr** as the default encryption algorithm, which is
    considered secure to several public standards:
    <https://github.com/defuse/php-encryption/blob/6de6e861fe48f8555a1fdd45a3de90df4e400067/src/Core.php#L14>
    """

    # Toggle whether or not Defuse is considered to be secure.
    DEFUSE_IS_SECURE = True

    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 6))
        self.finding_type = ScoreType.CRYPTOGRAPHY

        self.__files_of_interest = []

        for filename, uses in AbstractDetector._uses_map.items():
            for use in uses:
                if "Defuse" in use:
                    self.__files_of_interest.append(filename)
                    break

    def __find_encrypt(self):
        """Find usages of either Crypto::encrypt or Crypto::decrypt.

        This function assumes that either all usages of encrypt or decrypt are secure or insecure,
        as defined by the class attribute DEFUSE_IS_SECURE.
        """
        for f in self.__files_of_interest:
            query = f"""
            match (top) where top.name = "{f}" and top.type = "AST_TOPLEVEL"
            match (top)-[:PARENT_OF*]->(call)-[:PARENT_OF]->(encrypt) where encrypt.code =~ "(de|en)crypt"
            match (call)-[:PARENT_OF]->(children)
            return call, collect(children)
            """
            results = self.graph.run(query)
            for r in results:
                if not r:
                    continue
                call, children = r
                ast_name = [child for child in children if child["childnum"] == 0][0]
                ast_func_name = [child for child in children if child["childnum"] == 1][0]
                if ast_name["type"] == "AST_NAME":
                    name = self.graph.evaluate(
                        f"match (n)-[:PARENT_OF]->(m) where n.id = {ast_name['id']} return m.code"
                    )
                    if name != "Crypto":
                        continue
                    elif len(children) != 3:
                        self.new_finding(
                            call,
                            Score.error_score(),
                            f"Defuse Crypto::{ast_func_name['code']} has an invalid signature -- syntax error?",
                        )
                    else:
                        self.new_finding(
                            call,
                            Score.encrypt_score(
                                DefuseDetector.DEFUSE_IS_SECURE, True, "aes-256-ctr"
                            ),
                            f"Defuse Crypto::{ast_func_name['code']} is {'' if DefuseDetector.DEFUSE_IS_SECURE else 'in'}secure.",
                        )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_encrypt()
        print(f"### Finish running {self.__class__.__name__}")


class PHPSecLibDetector(AbstractDetector):
    """Detect usages of PHPSecLib security: <http://phpseclib.sourceforge.net/index.html>"""

    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 7))
        self.finding_type = ScoreType.CRYPTOGRAPHY

        self.__files_of_interest = []

        for filename, uses in AbstractDetector._uses_map.items():
            for use in uses:
                if "vendor" not in filename and "phpseclib" in use:
                    self.__files_of_interest.append(filename)
                    break

    def __find_rsa(self):
        for f in self.__files_of_interest:
            query = f"""
            match (top) where top.name = "{f}" and top.type = "AST_TOPLEVEL"
            match (top)-[:PARENT_OF*]->(call)-[:PARENT_OF]->(encrypt) where call.type =~ ".*CALL" and encrypt.code =~ "(de|en)crypt"
            match (call)-[:PARENT_OF]->(children)
            return call, collect(children)
            """
            results = self.graph.run(query)
            for r in results:
                if not r:
                    continue
                call_node, children = r
                ast_name = [c for c in children if c["childnum"] == 0][0]
                ast_method_name = [c for c in children if c["childnum"] == 1][0]
                # ast_arg_list = [c for c in children if c["childnum"] == 2][0]
                class_name = self._find_object_class(ast_name["id"])
                if class_name == "RSA":  # Strong guess
                    self.new_finding(
                        call_node,
                        Score.encrypt_score(True, True, ast_method_name["code"]),
                        f"PHPSecLib RSA::{ast_method_name['code']} is secure.",
                    )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_rsa()
        print(f"### Finish running {self.__class__.__name__}")


class GenericEncryptionDetector(AbstractDetector):

    keywords = [
        "(?i).*crypt.*",
        "(?i).*hash.*",
        "(?i).*mask.*",
        "(?i).*anony.*",
        # '(?i).*aes.*',
        # '(?i).*des.*',
        # '(?i).*md5.*',
        # '(?i).*(sha)(\d)+.*',
    ]

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for all otherwise undetected cryptography and hashing usages.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2020, 8, 4))
        self.finding_type = ScoreType.CRYPTOGRAPHY

    def __find(self):
        regex = f"(({'|'.join(self.keywords)}))"

        finding: AbstractDetector.Finding
        for finding in FunctionFinding.findings_from_function_name(
            self.graph, regex, self.finding_type, self
        ):
            finding.score.categories["generic"] = True
            self.add_finding(finding)

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")

class WordpressHashingFnDetector(AbstractDetector):

    keywords = [
        "wp_hash_password",
        "wp_create_user",
        "wp_set_password",
        "wp_update_user",
        "wpmu_create_user"
    ]

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for all otherwise undetected cryptography and hashing usages.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2022, 3, 3))
        self.finding_type = ScoreType.CRYPTOGRAPHY

    def __find(self):
        regex = f"(({'|'.join(self.keywords)}))"

        finding: AbstractDetector.Finding
        for finding in FunctionFinding.findings_from_function_name(
            self.graph, regex, self.finding_type, self
        ):
            finding.score.encryption_method = "hash"
            self.add_finding(finding)
        

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        print(f"### Finish running {self.__class__.__name__}")