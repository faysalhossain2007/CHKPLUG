# GDPR Checker - Results.py
# Patrick Thomas pwt5ca
# Created 210101

import sqlite3
import time
from datetime import datetime
from sqlite3.dbapi2 import Connection
from typing import Iterable, List, Optional, Tuple

global __DB_TIMEOUT, __PLUGIN_TIME, __PLUGIN_ID, __DETECTOR_COUNTER, __DATABASE_DIR
__DB_TIMEOUT = 60  # Length to wait until giving up on sqlite database.
__PLUGIN_TIME = str(datetime.now())
__PLUGIN_ID = 0
__DETECTOR_COUNTER = 0
__DATABASE_DIR = ""


def create_table(database_dir: str):
    global __DATABASE_DIR
    __DATABASE_DIR = database_dir
    try:
        with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute(
                """ CREATE TABLE IF NOT EXISTS "Plugins" (
                        "plugin ID"	INTEGER,
                        "plugin name"	TEXT NOT NULL,
                        "date analyzed"	TEXT NOT NULL,
                        PRIMARY KEY("plugin ID" AUTOINCREMENT)
                    )"""
            )
            c.execute(
                """ CREATE TABLE IF NOT EXISTS "Detectors" (
                    "detector ID"	INTEGER NOT NULL,
                    "plugin ID"	INTEGER NOT NULL,
                    "detector name"	TEXT NOT NULL,
                    "detector type"	TEXT NOT NULL,
                    "file name"	TEXT NOT NULL,
                    "line number"	INTEGER NOT NULL,
                    "node ID"	INTEGER NOT NULL,
                    "description"	TEXT,
                    "cryptography method"	TEXT,
                    "api endpoint"	TEXT,
                    "personal data" TEXT,
	                PRIMARY KEY("detector ID","plugin ID")
                )"""
            )
            c.execute(
                """ CREATE TABLE IF NOT EXISTS "Paths" (
                    "path ID"	INTEGER NOT NULL,
                    "plugin ID"	INTEGER NOT NULL,
                    "node index"	INTEGER NOT NULL,
                    "node ID"	INTEGER NOT NULL,
                    "AST type"	TEXT NOT NULL,
                    "variable name"	TEXT,
                    "caller"	TEXT,
                    "callee"	TEXT,
                    "file name"	TEXT,
                    "line number"	INTEGER,
                    "detector type"	TEXT,
                    PRIMARY KEY("plugin ID","path ID","node index")
                );"""
            )
            c.execute(
                """ CREATE TABLE IF NOT EXISTS "PathAnalyzer" (
                    "plugin ID" INTEGER NOT NULL,
                    "path analyzer topic"   TEXT NOT NULL,
                    "path ID"   INTEGER NOT NULL,
                    "stage" TEXT NOT NULL,
                    "node id"   INTEGER NOT NULL,
                    "level" TEXT NOT NULL,
                    "description"   TEXT,
                    PRIMARY KEY("plugin ID","path analyzer topic","path ID","stage","node id")
                );"""
            )
            c.execute(
                """ CREATE TABLE IF NOT EXISTS "PathAnalyzerDecision" (
                    "plugin ID" INTEGER NOT NULL,
                    "path analyzer topic"   TEXT NOT NULL,
                    "stage" TEXT NOT NULL,
                    "compliant" TEXT NOT NULL,
                    PRIMARY KEY("plugin ID", "path analyzer topic", "stage")
                );"""
            )
            c.execute(
                """ CREATE TABLE IF NOT EXISTS "SourceSink" (
                    "plugin ID" INTEGER NOT NULL,
                    "source id"   INTEGER NOT NULL,
                    "sink id"   INTEGER NOT NULL,
                    PRIMARY KEY("plugin ID","source id","sink id")
                );"""
            )
            conn.commit()
            c.execute(
                """ CREATE VIEW IF NOT EXISTS BatchResults AS
                SELECT *, (
                    SELECT COUNT(*) FROM "Detectors" as t2
                    WHERE t."plugin ID" = t2."plugin ID" AND (t2."detector type" = "storage" OR t2."detector type" = "database" OR t2."detector type" = "retrieval")
                ) as "num storage", (
                    SELECT COUNT(*) FROM "Detectors" as t2
                    WHERE t."plugin ID" = t2."plugin ID" AND (t2."detector type" = "cryptography")
                ) as "num crypto", (
                    SELECT group_concat("api endpoint", ",") FROM "Detectors" as t2
                    WHERE t."plugin ID" = t2."plugin ID" AND "api endpoint" IS NOT NULL
                ) as apis
                FROM "Plugins" as t;
                """
            )
            conn.commit()
    except sqlite3.OperationalError:
        # Wait for someone else to make the database...
        time.sleep(10)


def register_plugin(database_dir: str, plugin_name: str):
    global __PLUGIN_ID, __PLUGIN_TIME
    if not __PLUGIN_ID:
        create_table(database_dir)
        with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute(
                """INSERT INTO "Plugins" ("plugin name", "date analyzed") VALUES (?, ?) """,
                (plugin_name, __PLUGIN_TIME),
            )
            conn.commit()

            c.execute(
                """SELECT MAX("plugin ID") FROM "Plugins" WHERE "plugin name"=? AND "date analyzed"=? """,
                (plugin_name, __PLUGIN_TIME),
            )
            __PLUGIN_ID = int(c.fetchone()[0])


def write_plugin_detector_results(
    detector_name: str = "",
    detector_type: str = "",
    file_name: str = "",
    line_number: int = -1,
    node_ID: int = -1,
    description: str = "",
    cryptography_method: Optional[str] = None,
    api_endpoint: List[str] = None,
    personal_data: List[str] = None
):
    global __DETECTOR_COUNTER
    print(f"{description},{cryptography_method},{api_endpoint}")
    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO "Detectors"
        ("detector ID", "plugin ID", "detector name", "detector type", "file name", "line number", "node ID", "description", "cryptography method", "api endpoint","personal data")
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) """,
            (
                __DETECTOR_COUNTER,
                __PLUGIN_ID,
                detector_name,
                detector_type,
                file_name,
                line_number,
                node_ID,
                description,
                cryptography_method,
                str(api_endpoint),
                str(personal_data)
            ),
        )
        conn.commit()
        __DETECTOR_COUNTER = __DETECTOR_COUNTER + 1


def get_conn() -> Connection:
    return sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT)


def write_data_flow_path_row(
    path_id: int,
    row_num: int,
    node_id: int,
    ast_type: str = "",
    variable_name: str = "",
    caller: str = "",
    callee: str = "",
    file_name: str = "",
    line_number: int = -1,
    detector_type: str = "",
):
    global __DETECTOR_COUNTER
    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO "Paths"
        ("path ID", "plugin ID", "node index", "node ID", "AST type", "variable name", "caller", "callee", "file name", "line number", "detector type")
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) """,
            (
                path_id,
                __PLUGIN_ID,
                row_num,
                node_id,
                ast_type,
                variable_name,
                caller,
                callee,
                file_name,
                line_number,
                detector_type,
            ),
        )
        conn.commit()


def write_data_flow_path_row_many(
    data: List[
        Tuple[
            int,
            int,
            int,
            str,
            str,
            str,
            str,
            str,
            int,
            str,
        ]
    ]
):
    global __DETECTOR_COUNTER
    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        cursor = conn.cursor()
        cursor.executemany(
            """INSERT INTO "Paths"
                ("plugin ID", "path ID", "node index", "node ID", "AST type", "variable name", "caller", "callee", "file name", "line number", "detector type")
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(__PLUGIN_ID, *d) for d in data],
        )
        conn.commit()

def write_source_sink(sourceSinkList:List[Tuple[int,int]]):
    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        cursor = conn.cursor()
        cursor.executemany(
            """
            INSERT INTO "SourceSink"
                ("plugin ID", "source id", "sink id")
            VALUES
                (?, ?, ?)
            """,
            [(__PLUGIN_ID, *d) for d in sourceSinkList],
        )
        conn.commit()
def write_path_analyzer_decision(path_analyzer_topic: str, stage: str, compliant: bool):
    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO "PathAnalyzerDecision"
                ("plugin ID", "path analyzer topic", "stage", "compliant")
            VALUES
                (?, ?, ?, ?)
            """,
            (__PLUGIN_ID, path_analyzer_topic, stage, str(compliant)),
        )
        conn.commit()


def write_path_analyzer_log_row(
    path_analyzer_topic: str,
    path_id: int,
    stage: str,
    node_id: int,
    level: int,
    description: str,
    types: Iterable[str],
):
    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO "PathAnalyzer"
                ("plugin ID", "path analyzer topic", "path ID", "stage", "node id", "level", "description")
            VALUES
                (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                __PLUGIN_ID,
                path_analyzer_topic,
                path_id,
                stage,
                node_id,
                level,
                ", ".join(types) + " | " + description,
            ),
        )
        conn.commit()


def get_report() -> str:
    if not __PLUGIN_ID:
        return ""

    with sqlite3.connect(__DATABASE_DIR, timeout=__DB_TIMEOUT) as conn:
        plugin_name = ""
        c = conn.cursor()
        c.execute(
            """SELECT "plugin name" FROM Plugins WHERE "plugin ID"=?""",
            (__PLUGIN_ID,),
        )
        plugin_name = c.fetchone()[0]

        detector_data = []
        c = conn.cursor()
        c.execute(
            """SELECT "plugin name", "detector name", "detector type", "file name", "line number", "node ID", "description", "cryptography method", "api endpoint" FROM Plugins NATURAL JOIN Detectors WHERE "plugin ID"=?""",
            (__PLUGIN_ID,),
        )
        for p_name, d_name, d_type, f_name, line, n_id, desc, crypt, api in c:
            detector_data.append(
                {
                    "plugin name": p_name,
                    "detector name": d_name,
                    "detector type": d_type,
                    "file name": f_name,
                    "line number": line,
                    "node ID": n_id,
                    "description": desc,
                    "cryptography method": crypt,
                    "api endpoint": api,
                }
            )

        path_data = []
        c = conn.cursor()
        c.execute(
            """SELECT "path ID", "plugin name", "node index", "node ID", "AST type", "variable name", "caller", "callee", "file name", "line number", "detector type" FROM Plugins NATURAL JOIN Paths WHERE "plugin ID"=?""",
            (__PLUGIN_ID,),
        )
        for (
            path_id,
            p_name,
            n_index,
            n_id,
            ast_type,
            var_name,
            caller,
            callee,
            f_name,
            line,
            d_type,
        ) in c:
            path_data.append(
                {
                    "path ID": path_id,
                    "plugin name": p_name,
                    "node index": n_index,
                    "node ID": n_id,
                    "AST type": ast_type,
                    "variable name": var_name,
                    "caller": caller,
                    "callee": callee,
                    "file name": f_name,
                    "line number": line,
                    "detector type": d_type,
                }
            )

    # Print in markdown format.
    strs: List[str] = []
    strs.append(f"# {plugin_name}")
    strs.append("")
    strs.append(f"## Detector Results and Nodes of Interest")
    strs.append("")

    detector_data.sort(key=lambda x: x["line number"])
    detector_data.sort(key=lambda x: x["file name"])
    for d in detector_data:
        s = f""" -  {d['file name']}:{d['line number']} -- {d['detector name']}
     -  node ID: {d['node ID']}
     -  detector type: {d['detector type']}
     -  description: {d['description']}"""
        strs.append(s)
        if d["cryptography method"]:
            strs.append(f"     -  cryptography method: {d['cryptography method']}")
        if d["api endpoint"]:
            strs.append(f"     -  API endpoint: {d['api endpoint']}")

    return "\n".join(strs)


if __name__ == "__main__":
    # db = "./test.sqlite"
    # register_plugin(db, "MyPlugin")
    # write_plugin_detector_results(
    #     detector_name="TestDetector",
    #     detector_type="storage",
    #     file_name="myfile.php",
    #     line_number=100,
    #     node_ID=1000,
    #     description="This is a test.",
    # )
    # write_plugin_detector_results(
    #     detector_name="TestDetector",
    #     detector_type="storage",
    #     file_name="myfile2.php",
    #     line_number=80,
    #     node_ID=1000,
    #     description="This is a test.",
    #     api_endpoint="https://google.com/"
    # )
    # write_plugin_detector_results(
    #     detector_name="TestDetector",
    #     detector_type="cryptography",
    #     file_name="myfile.php",
    #     line_number=102,
    #     node_ID=1000,
    #     description="This is a test.",
    #     cryptography_method="sha512"
    # )

    print(get_report())
