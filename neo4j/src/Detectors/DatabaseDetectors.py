# GDPR Checker - DatabaseDetectors.py
# Patrick Thomas pwt5ca
# Created 200615

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from enum import IntEnum, auto
from typing import List,Set,Tuple
from DataFlowTracking import getMaxTraversalLength,allTraversalType

import py2neo
from NeoGraph import getGraph
from NeoHelper import getNode,getStatementSQLInfo
from SQLParser import getSQLParentNodes
from .Detectors import GENERIC_MAX_LEN, AbstractDetector
from .Scores import (
    Score,
    ScoreType,
    dbase_database_score,
    dbplus_database_score,
    filepro_database_score,
    firebird_database_score,
    frontbase_database_score,
    ibm_db2_database_score,
    informix_database_score,
    ingres_database_score,
    maxdb_database_score,
    mongo_database_score,
    mongodb_database_score,
    msql_database_score,
    mysql_database_score,
    mysqli_database_score,
    oci8_database_score,
    paradox_database_score,
    pdo_4d_database_score,
    pdo_cubrid_database_score,
    pdo_dblib_database_score,
    pdo_firebird_database_score,
    pdo_mysql_database_score,
    pdo_pgsql_database_score,
    pdo_unsupported_database_score,
    postgresql_database_score,
    sql_server_database_score,
    sqlite3_database_score,
    sqlite_database_score,
    sybase_database_score,
    tokyotyrant_database_score,
)
from .Utils import get_variable_value


class PHPDataObjectDetector(AbstractDetector):
    """PHPDataObjectDetector attempts to detect a wide variety of PDO usage scenarios.

    Most of scenarios revolve around the database that the database that the PDO is intended to
    connect to (MySQL, PostgreSQL, etc.).

    Below is a list of supported databases from https://www.php.net/manual/en/pdo.drivers.php:

    | Driver name  | Supported databases                                                |
    |--------------|--------------------------------------------------------------------|
    | PDO_CUBRID   | Cubrid (no SSL?)                                                   |
    | PDO_DBLIB    | FreeTDS / Microsoft SQL Server / Sybase (no SSL?)                  |
    | PDO_FIREBIRD | Firebird (no SSL?)                                                 |
    | PDO_IBM      | IBM DB2 (SSL, but configured in separate file)                     |
    | PDO_INFORMIX | IBM Informix Dynamic Server (SSL, but configured in separate file) |
    | PDO_MYSQL    | MySQL 3.x/4.x/5.x (configured in PHP)                              |
    | PDO_OCI      | Oracle Call Interface (separate config file)                       |
    | PDO_ODBC     | ODBC v3 (IBM DB2, unixODBC and win32 ODBC)(separate config file)   |
    | PDO_PGSQL    | PostgreSQL (separate config file)                                  |
    | PDO_SQLITE   | SQLite 3 and SQLite 2 (separate config file)                       |
    | PDO_SQLSRV   | Microsoft SQL Server / SQL Azure (separate config file)            |
    | PDO_4D       | 4D (SSL supported)                                                 |
    """

    class DriverEnum(IntEnum):
        """Enumerated type for each of the possible native PDOs."""

        CUBRID = auto()
        DBLIB = auto()
        FIREBIRD = auto()
        IBM = auto()
        INFORMIX = auto()
        MYSQL = auto()
        OCI = auto()
        ODBC = auto()
        PGSQL = auto()
        SQLITE = auto()
        SQLSRV = auto()
        _4D = auto()

    # Unsupported databases are the ones in which it is not feasible for this program to check if they employ security.
    unsupportedDatabases = [
        DriverEnum.IBM,
        DriverEnum.INFORMIX,
        DriverEnum.OCI,
        DriverEnum.ODBC,
        DriverEnum.SQLITE,
    ]

    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 29))
        self.finding_type = ScoreType.DATABASE

        self.pdos: dict = {e: set() for e in self.DriverEnum}
        self.__find_new_pdos()

    def __find_new_pdos(self):
        # Find where PDOs are instantiated.
        query = """
        match (a)-[:PARENT_OF]->(b)-[:PARENT_OF]->(c) 
        where a.type =~ "AST_NEW" 
            and b.type =~ "AST_NAME" 
            and c.code =~ "PDO"
        return a.id as id
        """
        results = self.graph.run(query)
        for result in results:

            i = result["id"]
            query = f"""
            match (a)-[:PARENT_OF]->(b)-[:PARENT_OF]->(c) where a.id = {i} 
                and b.type =~ "AST_ARG_LIST"
            return collect(c) as args
            """
            arg_nodes = self.graph.evaluate(query)

            args = []
            if arg_nodes is None:
                return
            for arg_node in arg_nodes:
                if re.match("AST_ARRAY", arg_node["type"]):
                    query = f"""
                    match (a)-[:PARENT_OF*]->(b) where a.id = {arg_node['id']}
                        and b.type =~ "string"
                    return collect(b.code)
                    """
                    strings = self.graph.evaluate(query)
                    if strings:
                        args.extend(strings)
                else:
                    query = f"""
                    match (a) where a.id = {arg_node['id']} return a
                    """
                    arg_node = self.graph.evaluate(query)
                    code = arg_node.get("code", None)
                    value = get_variable_value(
                        self.graph, arg_node["id"], node_type=arg_node["type"]
                    )
                    if code is not None:
                        args.append(code)
                    if value is not None and value != code:
                        args.append(value)

            if args is None:
                continue
            args_str = "\n".join(args).lower()

            # Match strings to a database connector.
            for driver in self.DriverEnum:
                # Manually handle 4D driver, else just dynamically assign name.
                name = "4d" if driver.name == "_4D" else driver.name.lower()
                if name in args_str:
                    self.pdos[driver].add(i)
                    break

    def __find_cubrid(self):
        ids = self.pdos[self.DriverEnum.CUBRID]

        for new_node_id in ids:
            query = f"""
            match (a) where a.id = {new_node_id} return a as n
            """
            result = self.graph.run(query).evaluate()
            if self._db_test_if_local(result["id"]):
                self.new_finding(
                    node_dict={"n": result},
                    score=pdo_cubrid_database_score(is_local=True),
                    reason=f"CUBRID connects to local database.",
                )
            else:
                self.new_finding(
                    node_dict={"n": result},
                    score=pdo_cubrid_database_score(is_local=False),
                    reason=f"CUBRID doesn't support connections over SSL.",
                )

    def __find_dblib(self):
        ids = self.pdos[self.DriverEnum.DBLIB]

        for new_node_id in ids:
            query = f"""
            match (a) where a.id = {new_node_id} return a as n
            """
            result = self.graph.run(query).evaluate()

            if self._db_test_if_local(result["id"]):
                self.new_finding(
                    node_dict={"n": result},
                    score=pdo_dblib_database_score(is_local=True),
                    reason=f"Microsoft SQL Server and Sybase Functions connects to local database.",
                )
            else:
                self.new_finding(
                    node_dict={"n": result},
                    score=pdo_dblib_database_score(is_local=False),
                    reason=f"Microsoft SQL Server and Sybase Functions doesn't support connections over SSL.",
                )

    def __find_firebird(self):
        ids = self.pdos[self.DriverEnum.FIREBIRD]

        for new_node_id in ids:
            query = f"""
            match (a) where a.id = {new_node_id} return a as n
            """
            result = self.graph.run(query).evaluate()

            if self._db_test_if_local(result["id"]):
                self.new_finding(
                    node_dict={"n": result},
                    score=pdo_firebird_database_score(is_local=True),
                    reason=f"Firebird connects to local database.",
                )
            else:
                self.new_finding(
                    node_dict={"n": result},
                    score=pdo_firebird_database_score(is_local=False),
                    reason=f"Firebird doesn't support connections over SSL.",
                )

    def __find_unsupported(self):
        for e in self.unsupportedDatabases:
            ids = self.pdos[e]

            for new_node_id in ids:
                query = f"""
                match (a) where a.id = {new_node_id} return a as n
                """
                result = self.graph.run(query).evaluate()

                if self._db_test_if_local(result["id"]):
                    self.new_finding(
                        node_dict={"n": result},
                        score=pdo_unsupported_database_score(is_local=True),
                        reason=f"{e.name} connects to local database.",
                    )
                else:
                    self.new_finding(
                        node_dict={"n": result},
                        score=pdo_unsupported_database_score(is_local=False),
                        reason=f"{e.name} network security is configured in other configuration files that this isn't able to check.",
                    )

    def __find_mysql(self):
        flags = {
            "MYSQL_ATTR_SSL_CA",
            "MYSQL_ATTR_SSL_CERT",
            "MYSQL_ATTR_SSL_KEY",
        }

        ids = self.pdos[self.DriverEnum.MYSQL]

        for new_node_id in ids:
            query = f"""
            match (a)-[:PARENT_OF]->(b)-[:PARENT_OF]->(c) where a.id = {new_node_id} and b.type =~ "AST_ARG_LIST" and c.childnum = 3
            return c as n
            """
            result = self.graph.run(query).evaluate()
            if result is None:
                self.new_finding(
                    node_dict={"n": result},
                    score=Score.error_score(),
                    reason=f"MySQL PDO is missing one or more SSL flags: {str(flags)}.",
                )
            elif result["type"] == "AST_ARRAY":
                # Read array elements.
                query = f"""
                match (a)-[:PARENT_OF*]->(b) where a.id = {result['id']} and b.type =~ "string"
                return collect(b.code) as l
                """
                children = self.graph.run(query).evaluate()

                if children is not None:
                    # Three checks:
                    # 'MYSQL_ATTR_SSL_CA'
                    # 'MYSQL_ATTR_SSL_CERT'
                    # 'MYSQL_ATTR_SSL_KEY' are all set
                    present_flags = flags.intersection(children)
                    is_local = self._db_test_if_local(result["id"])
                    if present_flags == flags:
                        self.new_finding(
                            node_dict={"n": result},
                            score=pdo_mysql_database_score(True, is_local=is_local),
                            reason=f"MySQL PDO called with all SSL flags."
                            if not is_local
                            else "MySQL PDO connects to local database.",
                        )
                    else:
                        self.new_finding(
                            node_dict={"n": result},
                            score=pdo_mysql_database_score(False, is_local=is_local),
                            reason=f"MySQL PDO is missing one or more SSL flags."
                            if not is_local
                            else "MySQL PDO connects to local database.",
                        )
                else:
                    self.new_finding(
                        node_dict={"n": result},
                        score=Score.error_score(),
                        reason=f"Encountered problem when reading arguments to PDO instantiation.",
                    )
            elif result["type"] == "AST_VAR":
                # TODO: find where this is defined
                self.new_finding(
                    node_dict={"n": result},
                    score=Score.error_score(),
                    reason=f"Encountered problem when reading arguments to PDO instantiation.",
                )
            else:
                # TODO: something went wrong
                self.new_finding(
                    node_dict={"n": result},
                    score=Score.error_score(),
                    reason=f"Encountered problem when reading arguments to PDO instantiation.",
                )

    def __find_pgsql(self):
        # Useful source: https://stackoverflow.com/questions/46852880/connecting-to-pgsql-over-ssl-via-php-pdo
        flags = {
            "sslmode",
            "sslcert",
            "sslkey",
        }

        ids = self.pdos[self.DriverEnum.PGSQL]

        for new_node_id in ids:
            query = f"""
            match (a) where a.id = {new_node_id} return a as n
            """
            root_node = self.graph.run(query).evaluate()

            query = f"""
            match (a)-[:PARENT_OF]->(b)-[:PARENT_OF]->(c) where a.id = {new_node_id} and b.type =~ "AST_ARG_LIST" and c.childnum = 0
            return c as n
            """
            conn_str_node = self.graph.run(query).evaluate()

            if conn_str_node is None:
                self.new_finding(
                    node_dict={"n": root_node},
                    score=Score.error_score(),
                    reason=f"PostgreSQL PDO is missing a connection string?",
                )
            else:
                conn_str = get_variable_value(
                    self.graph, conn_str_node["id"], node_type=conn_str_node["type"]
                )
                if conn_str is None:
                    self.new_finding(
                        node_dict={"n": root_node},
                        score=Score.error_score(),
                        reason=f"PostgreSQL PDO: couldn't find DB connection string; couldn't verify that the flags {', '.join(flags)} were set.",
                    )
                else:
                    all_match = True
                    is_local = self._db_test_if_local(root_node["id"])
                    for flag in flags:
                        all_match = all_match and flag in conn_str
                    if all_match:
                        self.new_finding(
                            node_dict={"n": root_node},
                            score=pdo_pgsql_database_score(True, is_local=is_local),
                            reason=f"PostgreSQL PDO: all SSL flags {', '.join(flags)} are set."
                            if not is_local
                            else "PostgreSQL PDO connects to local database.",
                        )
                    else:
                        self.new_finding(
                            node_dict={"n": root_node},
                            score=pdo_pgsql_database_score(False, is_local=is_local),
                            reason=f"PostgreSQL PDO: all required SSL flags {', '.join(flags)} are NOT set."
                            if not is_local
                            else "PostgreSQL PDO connects to local database.",
                        )

    def __find_4d(self):
        # Useful source: https://doc.4d.com/4Dv15/4D/15.2/Using-a-connection-string.200-2885363.en.html
        flags = {"ssl"}

        ids = self.pdos[self.DriverEnum._4D]

        for new_node_id in ids:
            query = f"""
            match (a) where a.id = {new_node_id} return a as n
            """
            root_node = self.graph.run(query).evaluate()

            query = f"""
            match (a)-[:PARENT_OF]->(b)-[:PARENT_OF]->(c) where a.id = {new_node_id} and b.type =~ "AST_ARG_LIST" and c.childnum = 0
            return c as n
            """
            conn_str_node = self.graph.run(query).evaluate()

            if conn_str_node is None:
                self.new_finding(
                    node_dict={"n": root_node},
                    score=Score.error_score(),
                    reason=f"4D PDO is missing a connection string?",
                )
            else:
                conn_str = get_variable_value(
                    self.graph, conn_str_node["id"], node_type=conn_str_node["type"]
                )
                if conn_str is None:
                    self.new_finding(
                        node_dict={"n": root_node},
                        score=Score.error_score(),
                        reason=f"4D PDO: couldn't find DB connection string; couldn't verify that the flags {', '.join(flags)} were set.",
                    )
                else:
                    all_match = True
                    is_local = self._db_test_if_local(root_node["id"])
                    for flag in flags:
                        all_match = all_match and flag in conn_str
                    if all_match:
                        self.new_finding(
                            node_dict={"n": root_node},
                            score=pdo_4d_database_score(True, is_local=is_local),
                            reason=f"4D PDO: all required SSL flags {', '.join(flags)} are set."
                            if not is_local
                            else "4D PDO connects to local database.",
                        )
                    else:
                        self.new_finding(
                            node_dict={"n": root_node},
                            score=pdo_4d_database_score(False, is_local=is_local),
                            reason=f"4D PDO: all required SSL flags {', '.join(flags)} are NOT set."
                            if not is_local
                            else "4D PDO connects to local database.",
                        )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        finders = [
            method_name
            for method_name in dir(self)
            if method_name.startswith("_PHPDataObjectDetector__find_")
            and callable(getattr(self, method_name))
            and method_name != "_PHPDataObjectDetector__find_new_pdos"
        ]
        methods = [getattr(self, finder) for finder in finders]

        with ThreadPoolExecutor() as executor:
            running_tasks = [executor.submit(method) for method in methods]
        print(f"### Finish running {self.__class__.__name__}")


class MySQLiDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Look for MySQLi usages and ensure that SSL flags or functions are set or called.

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2020, 7, 13))
        self.finding_type = ScoreType.DATABASE

    def __find_mysqli_oo(self):
        # Idea: OO calls must either have some ssl_set call or have MYSQLI_CLIENT_SSL as a option ->
        # must use real_connect method eventually.
        query = f"""
        match 
            init_path=(init_call)-[:PARENT_OF*..2]->(init_code) 
        where 
            init_code.code =~ "mysqli_init" and 
            init_call.type =~ "AST_CALL"
        optional match 
            i2s=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(ssl_set_call)-[:PARENT_OF*..2]->(ssl_set_code)
        where 
            ssl_set_call.type =~ "AST_METHOD_CALL" and 
            ssl_set_code.code =~ "ssl_set"
        match 
            i2c=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(connect_call)-[:PARENT_OF*..2]->(connect_code)
        where 
            connect_call.type =~ "AST_METHOD_CALL" and 
            connect_code.code =~ "real_connect"
        optional match 
            (connect_call)-[:PARENT_OF*]->(client_ssl_flag)
        where
            client_ssl_flag.code =~ "MYSQLI_CLIENT_SSL"
        return init_call, ssl_set_call, connect_call, client_ssl_flag
        """
        calls = self.graph.run(query)
        for r in calls:
            if not r:
                continue
            init_call, ssl_set_call, connect_call, client_ssl_flag = r
            if self._db_test_if_local(connect_call["id"]):
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(True, local=True),
                    reason="MySQLi connects to local database.",
                )
            elif init_call and connect_call and client_ssl_flag:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(True),
                    reason="MySQLi real_connect called with SSL flag.",
                )
            elif init_call and ssl_set_call and connect_call:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(True),
                    reason="MySQLi real_connect called with ssl_set.",
                )
            else:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(False),
                    reason="MySQLi is used without ssl_set or setting the option MYSQLI_CLIENT_SSL in real_connect.",
                )

        query = """
        match 
            (new_connect_call)-[:PARENT_OF*..3]->(connect_code)
        where 
            new_connect_call.type =~ "AST_NEW" and 
            connect_code.code =~ "mysqli"
        return collect(new_connect_call)
        """
        calls = self.graph.evaluate(query)
        for connect_call in calls:
            if self._db_test_if_local(connect_call["id"]):
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(False, local=True),
                    reason="MySQLi connects to local database.",
                )
            else:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(False),
                    reason='MySQLi "new mysqli" is used, which does not have any SSL options.',
                )

    def __find_mysqli_procedural(self):
        query = f"""
        match 
            init_path=(init_call)-[:PARENT_OF*..2]->(init_code) 
        where 
            init_code.code =~ "mysqli_init" and 
            init_call.type =~ "AST_CALL"
        optional match 
            i2s=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(ssl_set_call)-[:PARENT_OF*..2]->(ssl_set_code)
        where 
            ssl_set_call.type =~ "AST_CALL" and 
            ssl_set_code.code =~ "mysqli_ssl_set"
        match 
            i2c=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(connect_call)-[:PARENT_OF*..2]->(connect_code)
        where 
            connect_call.type =~ "AST_CALL" and 
            connect_code.code =~ "mysqli_real_connect"
        optional match 
            (connect_call)-[:PARENT_OF*]->(client_ssl_flag)
        where
            client_ssl_flag.code =~ "MYSQLI_CLIENT_SSL"
        return init_call, ssl_set_call, connect_call, client_ssl_flag
        """
        calls = self.graph.run(query)
        for r in calls:
            if not r:
                continue
            init_call, ssl_set_call, connect_call, client_ssl_flag = r
            if self._db_test_if_local(connect_call["id"]):
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(True, local=True),
                    reason="MySQLi connects to local database.",
                )
            elif init_call and connect_call and client_ssl_flag:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(True),
                    reason="MySQLi mysqli_real_connect called with SSL flag MYSQLI_CLIENT_SSL.",
                )
            elif init_call and ssl_set_call and connect_call:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(True),
                    reason="MySQLi mysqli_real_connect called with mysqli_ssl_set.",
                )
            else:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(False),
                    reason="MySQLi is used without mysqli_ssl_set or setting the option MYSQLI_CLIENT_SSL in mysqli_real_connect.",
                )

        query = """
        match 
            (connect_call)-[:PARENT_OF*..2]->(connect_code)
        where 
            connect_call.type =~ "AST_CALL" and 
            connect_code.code =~ "mysqli_connect"
        return collect(connect_call)
        """
        calls = self.graph.evaluate(query)
        for connect_call in calls:
            if self._db_test_if_local(connect_call["id"]):
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(False, local=True),
                    reason="MySQLi connects to local database.",
                )
            else:
                self.new_finding(
                    node_dict=connect_call,
                    score=mysqli_database_score(False),
                    reason='MySQLi "new mysqli" is used, which does not have any SSL options.',
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_mysqli_oo()
        self.__find_mysqli_procedural()
        print(f"### Finish running {self.__class__.__name__}")


class MySQLDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Look for simple mysql_* usages, which were deprecated in PHP 5.5.0 and removed in PHP 7.0.0.

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2020, 7, 6))
        self.finding_type = ScoreType.DATABASE

    def __find_mysql_connect(self) -> list:
        """Find usages of mysql_connect, which starts a MySQL session.

        Returns:
            list: List of nodes that match.
        """
        return self._simple_match("mysql_connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_mysql_connect()

        for node in connect_nodes:
            # Get the arguments to the collect call.
            query = f"""
            match (a)<-[:PARENT_OF*]-(c)-[:PARENT_OF]->(d)-[:PARENT_OF]->(e) where a.id = {node['id']}
            and c.type =~ "AST_.*CALL" and d.type =~ "AST_ARG_LIST"
            optional match p = (e)-[:PARENT_OF*]->()
            return e as arg, [n in nodes(p) where n.code is not null | n.code] AS codes
            """
            args = self.graph.run(query)
            if args is None:
                print("[Error] MySQL used without arguments")
                continue

            strings = []
            for arg in args:
                arg_node = arg["arg"]
                codes = arg["codes"]
                # # Try to dereference the variables.
                actual_value = get_variable_value(
                    self.graph, arg_node["id"], node_type=arg_node["type"]
                )
                if actual_value is not None:
                    strings.append(actual_value)
                strings.extend(codes)

            for i, string in enumerate(strings):
                strings[i] = string.lower()

            if self._db_test_if_local(node["id"]):
                self.new_finding(
                    node_dict=node,
                    score=mysql_database_score(True),
                    reason="mysql_connect connects to local database. However, mysql_* is deprecated as of PHP 5.5.0 and removed in PHP 7.0.0.",
                )
            elif "MYSQL_CLIENT_SSL".lower() in strings:
                self.new_finding(
                    node_dict=node,
                    score=mysql_database_score(True),
                    reason="mysql_connect called with SSL flag. However, mysql_* is deprecated as of PHP 5.5.0 and removed in PHP 7.0.0.",
                )
            else:
                self.new_finding(
                    node_dict=node,
                    score=mysql_database_score(False),
                    reason="mysql_connect called without SSL flag. MySQL extension is deprecated as of PHP 5.5.0 and removed in PHP 7.0.0.",
                )
        print(f"### Finish running {self.__class__.__name__}")


class CubridDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_cubrid_connect(self) -> List[dict]:
        return self._simple_match("cubrid_connect(|_with_url)")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_cubrid_connect()
        for node in connect_nodes:
            is_local = self._db_test_if_local(node["id"])
            if is_local:
                self.new_finding(
                    node,
                    pdo_cubrid_database_score(is_local=is_local),
                    "CUBRID connects to a local database.",
                )
            else:
                self.new_finding(
                    node,
                    pdo_cubrid_database_score(is_local=is_local),
                    "CUBRID does not support transit encryption.",
                )
        print(f"### Finish running {self.__class__.__name__}")


class DbplusDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("dbplus_open")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            is_local = self._db_test_if_local(node["id"])
            if is_local:
                self.new_finding(
                    node,
                    dbplus_database_score(is_local=is_local),
                    "DBPlus is unmaintained. DBPlus connects to a local database.",
                )
            else:
                self.new_finding(
                    node,
                    dbplus_database_score(is_local=is_local),
                    "DBPlus is unmaintained. DBPlus does not support transit encryption.",
                )
        print(f"### Finish running {self.__class__.__name__}")


class DbaseDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("dbase_open")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            is_local = self._db_test_if_local(node["id"])
            if is_local:
                self.new_finding(
                    node,
                    dbase_database_score(is_local=is_local),
                    "DBase connects to a local database and is recommended against for production environments: https://www.php.net/manual/en/intro.dbase.php",
                )
            else:
                self.new_finding(
                    node,
                    dbase_database_score(is_local=is_local),
                    "DBase does not support transit encryption and is recommended against for production environments: https://www.php.net/manual/en/intro.dbase.php.",
                )
        print(f"### Finish running {self.__class__.__name__}")


class FileProDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("filepro")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                filepro_database_score(is_local=self._db_test_if_local(node["id"])),
                "filePro is unmaintained: https://pecl.php.net/package/filepro",
            )
        print(f"### Finish running {self.__class__.__name__}")


class FirebirdInterBaseDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("(fbird|ibase)_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                firebird_database_score(is_local=self._db_test_if_local(node["id"])),
                "InterBase supports transit encryption and Firebird/Interbase support data-at-rest encryption, "
                "but it cannot be determined if these are enabled.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class FrontBaseDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("fbsql_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                frontbase_database_score(is_local=self._db_test_if_local(node["id"])),
                "FrontBase does not support transit encryption or data-at-rest encryption.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class IBMDb2Detector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Finds Db2 security settings. Does not work with VCAP_SERVICES.

        Args:
            graph (py2neo.Graph): [description]
        """
        super().__init__(graph, date(2020, 7, 14))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        #print("debug step 1")
        query = f"""
        MATCH (new_connect:AST{{type:'AST_CALL'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "odbc_(p|)connect"
        OPTIONAL MATCH (flag:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(new_connect)
        WHERE flag.code =~ ".*SECURITY=SSL.*"
        return distinct new_connect, collect(distinct flag)
        """
        results = self.graph.run(query)
        #print("debug step 2")
        for r in results:
            if not r:
                continue
            call, flags = r
            if flags:
                self.new_finding(
                    call,
                    ibm_db2_database_score(True, is_local=self._db_test_if_local(call["id"])),
                    "Db2 called with SECURITY=SSL option.",
                )
            else:
                self.new_finding(
                    call,
                    ibm_db2_database_score(False, is_local=self._db_test_if_local(call["id"])),
                    "Db2 not called with SECURITY=SSL option.",
                )
        #print("debug step 3")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class InformixDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 15))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("ifx_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                informix_database_score(is_local=self._db_test_if_local(node["id"])),
                "Informix supports connections over SSL, but it is configured elsewhere.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class IngresDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 15))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("ingres_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                ingres_database_score(is_local=self._db_test_if_local(node["id"])),
                "Ingres does not support transit security.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class maxdbDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        """Look for maxdb usages and ensure that SSL flags or functions are set or called.

        Args:
            graph (py2neo.Graph): The Neo4j PHP AST graph to analyze.
        """
        super().__init__(graph, date(2020, 7, 15))
        self.finding_type = ScoreType.DATABASE

    def __find_maxdb_oo(self):
        # Idea: OO calls must either have some ssl_set call or have maxdb_CLIENT_SSL as a option ->
        # must use real_connect method eventually.
        query = f"""
        match 
            init_path=(init_call)-[:PARENT_OF*..2]->(init_code) 
        where 
            init_code.code =~ "maxdb_init" and 
            init_call.type =~ "AST_CALL"
        optional match 
            i2s=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(ssl_set_call)-[:PARENT_OF*..2]->(ssl_set_code)
        where 
            ssl_set_call.type =~ "AST_METHOD_CALL" and 
            ssl_set_code.code =~ "ssl_set"
        match 
            i2c=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(connect_call)-[:PARENT_OF*..2]->(connect_code)
        where 
            connect_call.type =~ "AST_METHOD_CALL" and 
            connect_code.code =~ "real_connect"
        optional match 
            (connect_call)-[:PARENT_OF*]->(client_ssl_flag)
        where
            client_ssl_flag.code =~ "maxdb_CLIENT_SSL"
        return init_call, ssl_set_call, connect_call, client_ssl_flag
        """
        calls = self.graph.run(query)
        for r in calls:
            if not r:
                continue
            init_call, ssl_set_call, connect_call, client_ssl_flag = r
            if init_call and connect_call and client_ssl_flag:
                self.new_finding(
                    node_dict=connect_call,
                    score=maxdb_database_score(
                        True, is_local=self._db_test_if_local(connect_call["id"])
                    ),
                    reason="maxdb real_connect called with SSL flag.",
                )
            elif init_call and ssl_set_call and connect_call:
                self.new_finding(
                    node_dict=connect_call,
                    score=maxdb_database_score(
                        True, is_local=self._db_test_if_local(connect_call["id"])
                    ),
                    reason="maxdb real_connect called with ssl_set.",
                )
            else:
                self.new_finding(
                    node_dict=connect_call,
                    score=maxdb_database_score(
                        False, is_local=self._db_test_if_local(connect_call["id"])
                    ),
                    reason="maxdb is used without ssl_set or setting the option maxdb_CLIENT_SSL in real_connect.",
                )

        query = """
        match 
            (new_connect_call)-[:PARENT_OF*..3]->(connect_code)
        where 
            new_connect_call.type =~ "AST_NEW" and 
            connect_code.code =~ "maxdb"
        return collect(new_connect_call)
        """
        calls = self.graph.evaluate(query)
        for connect_call in calls:
            self.new_finding(
                node_dict=connect_call,
                score=maxdb_database_score(False),
                reason='maxdb "new maxdb" is used, which does not have any SSL options.',
            )

    def __find_maxdb_procedural(self):
        query = f"""
        match 
            init_path=(init_call)-[:PARENT_OF*..2]->(init_code) 
        where 
            init_code.code =~ "maxdb_init" and 
            init_call.type =~ "AST_CALL"
        optional match 
            i2s=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(ssl_set_call)-[:PARENT_OF*..2]->(ssl_set_code)
        where 
            ssl_set_call.type =~ "AST_CALL" and 
            ssl_set_code.code =~ "maxdb_ssl_set"
        match 
            i2c=(init_call)<-[:PARENT_OF*0..]-()-[:REACHES]->()-[:PARENT_OF*0..]->(connect_call)-[:PARENT_OF*..2]->(connect_code)
        where 
            connect_call.type =~ "AST_CALL" and 
            connect_code.code =~ "maxdb_real_connect"
        optional match 
            (connect_call)-[:PARENT_OF*]->(client_ssl_flag)
        where
            client_ssl_flag.code =~ "MAXDB_CLIENT_SSL"
        return init_call, ssl_set_call, connect_call, client_ssl_flag
        """
        calls = self.graph.run(query)
        for r in calls:
            if not r:
                continue
            init_call, ssl_set_call, connect_call, client_ssl_flag = r
            if init_call and connect_call and client_ssl_flag:
                self.new_finding(
                    node_dict=connect_call,
                    score=maxdb_database_score(
                        True, is_local=self._db_test_if_local(connect_call["id"])
                    ),
                    reason="maxdb maxdb_real_connect called with SSL flag maxdb_CLIENT_SSL.",
                )
            elif init_call and ssl_set_call and connect_call:
                self.new_finding(
                    node_dict=connect_call,
                    score=maxdb_database_score(
                        True, is_local=self._db_test_if_local(connect_call["id"])
                    ),
                    reason="maxdb maxdb_real_connect called with maxdb_ssl_set.",
                )
            else:
                self.new_finding(
                    node_dict=connect_call,
                    score=maxdb_database_score(
                        False, is_local=self._db_test_if_local(connect_call["id"])
                    ),
                    reason="maxdb is used without maxdb_ssl_set or setting the option maxdb_CLIENT_SSL in maxdb_real_connect.",
                )

        query = """
        match 
            (connect_call)-[:PARENT_OF*..2]->(connect_code)
        where 
            connect_call.type =~ "AST_CALL" and 
            connect_code.code =~ "maxdb_connect"
        return collect(connect_call)
        """
        calls = self.graph.evaluate(query)
        for connect_call in calls:
            self.new_finding(
                node_dict=connect_call,
                score=maxdb_database_score(
                    False, is_local=self._db_test_if_local(connect_call["id"])
                ),
                reason="maxdb maxdb_connect is used, which does not have any SSL options.",
            )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_maxdb_oo()
        self.__find_maxdb_procedural()
        print(f"### Finish running {self.__class__.__name__}")


class MongoDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 15))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        query = f"""
        MATCH (new_connect:AST{{type:'AST_NEW'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "MongoClient"
        OPTIONAL MATCH (flag:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(new_connect)
        WHERE flag.code =~ ".*ssl.*"
        return distinct new_connect, collect(distinct flag)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, flags = r
            if flags:
                self.new_finding(
                    call,
                    mongo_database_score(True, is_local=self._db_test_if_local(call["id"])),
                    "Mongo driver is deprecated but called with SSL option.",
                )
            else:
                self.new_finding(
                    call,
                    mongo_database_score(False, is_local=self._db_test_if_local(call["id"])),
                    "Mongo driver is deprecated and does not use SSL.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class MongoDbDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        query = f"""
        MATCH (new_connect:AST{{type:'AST_NEW'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "MongoDB\\\\\\\\(Clie|Driver\\\\\\\\Manag).*"
        OPTIONAL MATCH (ssl:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(new_connect)
        WHERE ssl.code =~ ".*(tls|ssl)=true.*"
        OPTIONAL MATCH (autoencryption:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(new_connect)
        WHERE autoencryption.code =~ ".*auto[eE]ncryption.*"
        return distinct new_connect, collect(distinct ssl), collect(distinct autoencryption)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, ssl, autoencryption = r
            if ssl and autoencryption:
                self.new_finding(
                    call,
                    mongodb_database_score(True, True, is_local=self._db_test_if_local(call["id"])),
                    "MongoDB called with ssl=true option and uses autoencryption.",
                )
            elif ssl:
                self.new_finding(
                    call,
                    mongodb_database_score(
                        True, False, is_local=self._db_test_if_local(call["id"])
                    ),
                    "MongoDB called with ssl=true option but does not use autoencryption.",
                )
            elif autoencryption:
                self.new_finding(
                    call,
                    mongodb_database_score(
                        False, True, is_local=self._db_test_if_local(call["id"])
                    ),
                    "MongoDB called without ssl=true option but uses autoencryption.",
                )
            else:
                self.new_finding(
                    call,
                    mongodb_database_score(
                        False, False, is_local=self._db_test_if_local(call["id"])
                    ),
                    "MongoDB not called with ssl=true option or autoencryption.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class MsqlDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("msql_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                msql_database_score(is_local=self._db_test_if_local(node["id"])),
                "Msql does not support transit security.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class Oci8Detector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("oci_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                oci8_database_score(is_local=self._db_test_if_local(node["id"])),
                "OCI8 supports SSL in configuration files.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class ParadoxDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("px_(new|open_fp)")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                paradox_database_score(is_local=True),
                "Paradox needs no transit encryption, however ensure that personal information is stored encrypted.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class PostgreSQLDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        query = f"""
        MATCH (new_connect:AST{{type:'AST_CALL'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "pg_(p|)connect"
        OPTIONAL MATCH (ssl:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(new_connect)
        WHERE ssl.code =~ ".*(sslmode=(disable|allow|prefer|require)|requiressl).*"
        return distinct new_connect, collect(distinct ssl)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, ssl = r
            mode = None
            for s in ssl:
                if s["code"] is not None:
                    mode = s["code"]
                    break
            if not ssl or mode == "disable":
                self.new_finding(
                    call,
                    postgresql_database_score(False, is_local=self._db_test_if_local(call["id"])),
                    "PostgreSQL is connected with no transit security.",
                )
            elif mode == "allow" or mode == "prefer":
                self.new_finding(
                    call,
                    postgresql_database_score(True, is_local=self._db_test_if_local(call["id"])),
                    "PostgreSQL is connected with transit security; use sslmode=require for best security.",
                )
            elif mode == "require":
                self.new_finding(
                    call,
                    postgresql_database_score(True, is_local=self._db_test_if_local(call["id"])),
                    "PostgreSQL is connected with transit security.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class SqliteDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("sqlite_(p|)open")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                sqlite_database_score(is_local=True),
                "Sqlite needs no transit encryption, however ensure that personal information is stored encrypted. "
                "Sqlite is deprecated and Sqlite3 should be used instead.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class Sqlite3Detector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        # return self._simple_match("sqlite_(p|)open")
        query = f"""
        MATCH (new_connect:AST{{type:'AST_NEW'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "SQLite3"
        optional match (new_connect)-[:PARENT_OF]->(args)-[:PARENT_OF]->(argchild)
        where args.type =~ "AST_ARG_LIST" and argchild.childnum = 2
        return distinct new_connect, collect(distinct argchild)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            new_node, arg_node = r
            if arg_node:
                self.new_finding(
                    new_node,
                    sqlite3_database_score(True, is_local=True),
                    "Sqlite3 is used with encryption extension.",
                )
            else:
                self.new_finding(
                    new_node,
                    sqlite3_database_score(False, is_local=True),
                    "Sqlite3 is not used with encryption extension.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class SqlServerDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        query = f"""
        MATCH (connect_call:AST{{type:'AST_CALL'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "sqlsrv_(p|)connect"
        OPTIONAL MATCH (encrypt:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(connect_call)
        WHERE encrypt.code =~ ".*[Ee]ncrypt.*"
        OPTIONAL MATCH (colencrypt:AST)-[{allTraversalType()}{getMaxTraversalLength()}]->(connect_call)
        WHERE colencrypt.code =~ ".*ColumnEncryption.*"
        return distinct connect_call, collect(distinct encrypt), collect(distinct colencrypt)
        """
        results = self.graph.run(query)
        for r in results:
            if not r:
                continue
            call, enc, col_enc = r
            if enc and col_enc:
                self.new_finding(
                    call,
                    sql_server_database_score(
                        True, True, is_local=self._db_test_if_local(call["id"])
                    ),
                    "SQL Server used with encrypted connections and column encryption.",
                )
            elif not enc and col_enc:
                self.new_finding(
                    call,
                    sql_server_database_score(
                        False, True, is_local=self._db_test_if_local(call["id"])
                    ),
                    "SQL Server used unencrypted connections and column encryption.",
                )
            elif enc and not col_enc:
                self.new_finding(
                    call,
                    sql_server_database_score(
                        True, False, is_local=self._db_test_if_local(call["id"])
                    ),
                    "SQL Server used with encrypted connections and no column encryption.",
                )
            else:
                self.new_finding(
                    call,
                    sql_server_database_score(False, False),
                    "SQL Server used without any transit or data-at-rest security.",
                )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class SybaseDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self) -> List[dict]:
        return self._simple_match("sybase_(p|)connect")

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        # Get nodes of interest.
        connect_nodes = self.__find_connect()
        for node in connect_nodes:
            self.new_finding(
                node,
                sybase_database_score(is_local=self._db_test_if_local(node["id"])),
                "Sybase is removed/unmaintained and does not support any data security.",
            )
        print(f"### Finish running {self.__class__.__name__}")


class TokyoTyrantDetector(AbstractDetector):
    def __init__(self, graph: py2neo.Graph):
        super().__init__(graph, date(2020, 7, 16))
        self.finding_type = ScoreType.DATABASE

    def __find_connect(self):
        query = f"""
        MATCH (new_connect:AST{{type:'AST_NEW'}})-[:PARENT_OF]->(:AST{{type:'AST_NAME'}})-[:PARENT_OF]->(connect_str:AST{{type:'string'}})
        where connect_str.code =~ "TokyoTyrant"
        return collect(distinct new_connect)
        """
        results = self.graph.evaluate(query)
        for call in results:
            self.new_finding(
                call,
                tokyotyrant_database_score(is_local=self._db_test_if_local(call["id"])),
                "Tokyo Tyrant is not longer maintained and doesn't support data security.",
            )

    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find_connect()
        print(f"### Finish running {self.__class__.__name__}")


class GenericDatabaseUsageDetector(AbstractDetector):

    databases_procedural = [
        "cubrid",  # CUBRID
        "db2",  # IBM DB2
        "dbase",  # dBase
        "dbplus",  # DB++
        "fbird",  # Firebird
        "fbsql",  # FrontBase
        "filepro",  # filePro
        "ibase",  # Interbase
        "ifx",  # Informix
        "ingress",  # Ingress
        "maxdb",  # MaxDB
        "msql",  # mSQL
        "mssql",  # Microsoft SQL Server
        "mysql",  # MySQL
        "oci",  # OCI
        "pg",  # PostgreSQL
        "px",  # Paradox
        "sqlite",  # SQLite
        "sqlsrv",  # SQLSRV
        "sybase",  # Sybase
    ]

    databases_query = [
        "dbDelta",
        "exec",
        "execute",
        "get_col",
        "get_results",
        "get_row",
        "prepare",
        "query",
    ]

    def __init__(self, graph: py2neo.Graph):
        """Detector intended to be a catch-all for all otherwise undetected database usages.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(graph, date(2020, 8, 10))
        self.finding_type = ScoreType.DATABASE

    def __find(self):
        regex_databases = f"(({'|'.join(self.databases_procedural)}))"
        regex_calls = f"(({'|'.join(self.databases_query)}))"
        regex = f"(?i){regex_databases}\\\\S*{regex_calls}\\\\S*"

        query = f"""
        match 
            (fn_call:AST)-[:PARENT_OF*..2]->(fn_name:AST)
        where 
            fn_name.code =~ "{regex}" and
            fn_call.type =~ "AST.*_CALL"
        return fn_name, fn_call
        """
        results = self.graph.run(query).data()
        for r in results:
            if not r:
                continue
            name, call = r
            if len(name["code"]) > GENERIC_MAX_LEN:
                continue
            score = Score.database_score(
                Score.store_score(False, False, False, False, True),
                Score.transit_score(False, False, False, False, True, True),
            )
            score.categories["generic"] = True
            score.categories["database_usage"] = True
            self.new_finding(
                call,
                score,
                f"Found generic database usage \"{name['code']}\".",
            )

    # def __find_weak(self):
    #     """Find usages that are similar to patterns that we expect for PDOs and object-oriented interfaces."""
    #     regex_calls = f"({'|'.join(self.databases_query)})"
    #     #no need to find regex calls because they were what's used to create the SQL AST trees
    #     query = f"""
    #     MATCH (fn_call:AST)-[:PARENT_OF*..2]->(fn_name:AST)
    #     WHERE fn_name.code =~ "(?i){regex_calls}" AND fn_call.type =~ "AST.*_CALL"
    #     OPTIONAL MATCH (fn_call)<-[:PARENT_OF*0..]-()-[:PARENT_OF]->(sql_start:AST_SQL)
    #     WHERE sql_start.type =~ "AST_SQL_START"
    #     OPTIONAL MATCH (sql_start)-[:PARENT_OF*]->(pretable:AST_SQL)-[:SQL_FLOWS_TO*]->(names:AST_SQL)
    #     WHERE pretable.type =~ "AST_SQL_(INTO|UPDATE)" AND (names.type = "AST_SQL_Name" OR names.type = "AST_SQL_Placeholder")
    #     OPTIONAL MATCH (sql_start)-[:PARENT_OF*]->(sql_modify:AST_SQL)
    #     WHERE sql_modify.type =~ "AST_SQL_(INSERT|UPDATE)"
    #     RETURN fn_name, fn_call, sql_start, collect(names.code), collect(DISTINCT sql_modify.type)
    #     """
    #     results = self.graph.run(query)
    #     for r in results:
    #         if not r:
    #             continue
    #         name, call, sql_start, sql_names, sql_modify = r
    #         if len(name["code"]) > GENERIC_MAX_LEN or not sql_modify:
    #             continue
    #         score = Score.database_score(
    #             Score.store_score(False, False, False, False, True),
    #             Score.transit_score(False, False, False, False, True, True),
    #         )
    #         if sql_names:
    #             score.categories["table_name"] = sql_names[0]
    #         if sql_modify:
    #             score.categories["operations"] = sql_modify
    #         score.categories["generic"] = True
    #         score.categories["database_usage"] = True

    #         self.new_finding(
    #             call,
    #             score,
    #             f"Found generic database usage (weak match) \"{name['code']}\": {', '.join(sql_modify)} on table {'(unknown)' if not sql_names else sql_names[0]}.",
    #              )
    def __find_wpdb(self):
        #TODO: implement modeling of wpdb insert, update, replace
        graph = getGraph()
        query = f"""
        MATCH (prep:AST{{childnum:1,type:'string'}})<-[:PARENT_OF]-(n:AST{{type:'AST_METHOD_CALL'}})-[:PARENT_OF]->(var:AST{{childnum:0,type:'AST_VAR'}})-[:PARENT_OF]->(str:AST{{type:'string',code:'wpdb'}})
        WHERE prep.code in ['insert','update','replace']
        MATCH (n)-[:PARENT_OF]->(arg_list:AST{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(args:AST)
        WITH args
        ORDER BY args.childnum ASC
        RETURN COLLECT(args.id)
        """
        # MATCH (n)-[:PARENT_OF]->(arg_list:AST{{childnum:2,type:'AST_ARG_LIST'}})-[:PARENT_OF]->(args:AST)
        # RETURN COLLECT(args) ORDER BY args.childnum
        result = graph.evaluate(cypher=query)
        if result:
            pass
    
    def __find_weak(self):
        # Now look for all SQL query operations.
        SQLParentNodes = getSQLParentNodes()
        for sql_node in SQLParentNodes:
            sql_info = getStatementSQLInfo(sql_node)
            if not sql_info:
                continue
            if sql_info.operation in ['select','update','insert']:
                #first try to find all fields of the table by finding the create statement
                allFields = set(sql_info.fields)
                for sql_node2 in SQLParentNodes:
                    sql_info2 = getStatementSQLInfo(sql_node2)
                    if not sql_info2:
                        continue
                    if sql_info2.operation=='create' and sql_info2.table_name==sql_info.table_name:
                        allFields.update(sql_info2.fields)
                score = Score.database_op_score(sql_info.operation,sql_info.table_name,list(allFields))
                self.new_finding(
                    getNode(sql_node),
                    score,
                    f"Found generic database {sql_info.operation} on table '{sql_info.table_name}', with fields {list(sql_info.fields)}"
                )





    def _run(self):
        print(f"### Start running {self.__class__.__name__}")
        self.__find()
        self.__find_weak()
        # self.__find_create_table()
        # self.__find_select()
        print(f"### Finish running {self.__class__.__name__}")
