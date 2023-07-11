from tqdm import tqdm

from functools import partial
from itertools import tee
from subprocess import check_output
from typing import List
import csv
import json
import os
import sys

__last_len: int = 0

progress_bar = partial(tqdm, ncols=60, leave=True, disable=None)


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def rewrite_print(s: str):
    if os.isatty(sys.stdout.fileno()):
        global __last_len
        diff = max(__last_len - len(s), 0)
        ss = f"{s}{' ' * diff}"
        __last_len = len(s)

        print("\r", end="", flush=True)
        print(ss, end="", flush=True)
    else:
        print(s)


def create_dir(directory_path: str) -> bool:
    """Create a directory.

    Args:
        directory_path (str): Path to the directory to create.

    Returns:
        bool: Whether the directory has successfully created or not.
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        return True
    return False


def read_file(file_path: str) -> str:
    """Read a file from the disk into a string.

    Args:
        file_path (str): Path to the file to read.

    Returns:
        str: The entire file's contents as a string.
    """
    with open(file_path, "r") as f:
        return f.read()


def readCSVbyTab(input_file: str) -> List[List[str]]:
    """Read a TSV file from the disk.

    Args:
        input_file (str): Path to the input file.

    Returns:
        List[List[str]]: List of rows.
    """
    
    maxInt = sys.maxsize
    #solve problem where csv field exceeds largest limit. source: https://stackoverflow.com/questions/15063936/csv-error-field-larger-than-field-limit-131072
    while True:
        # decrease the maxInt value by factor 10 
        # as long as the OverflowError occurs.

        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt/10)
    try:
        with open(input_file, newline="",encoding = "ISO-8859-1") as csvfile:
            # Filter out NULL bytes in input file.
            csv_lines = [l.replace("\0", "") for l in csvfile]
            csv_reader = csv.reader(
                csv_lines,
                delimiter="\t",
                escapechar="\\",
                quotechar='"',
                doublequote=False,
                strict=True,
            )
            rows = list(csv_reader)
            if len(rows) > 0:
                return rows[1:]
            return rows
    except FileNotFoundError:
        print(f"Couldn't read CSV {input_file}; returning empty list")
        return []


def writeCSVbyTab(loc: str, data: List[List[str]], type: str):
    """Save a TSV to the disk.

    Args:
        loc (str): Path to save the file to.
        data (List[List[str]]): Data to save.
        type (str): Mode to open the file in. Should be "w" in most circumstances.
    """
    # Make sure the input is mutable.
    mutable = [list(t) for t in data]
    # Do extra escaping for backslashes to help Batch Import.
    for i in range(len(mutable)):
        for j in range(len(mutable[i])):
            if isinstance(mutable[i][j], str):
                mutable[i][j] = mutable[i][j].replace("\\", "\\\\")

    with open(loc, mode=type, newline="") as file:
        csv_writer = csv.writer(
            file,
            delimiter="\t",
            escapechar="\\",
            quotechar='"',
            doublequote=False,
            strict=True,
            quoting=csv.QUOTE_ALL,
        )
        csv_writer.writerows(mutable)


def getAllFilepathsWithEXT(directory, extension):
    dirs = (check_output(
        ["find", os.path.abspath(directory), "-iname",
         f"*{extension}"]).decode().strip().split("\n"))
    abs_dirs = [os.path.abspath(d) for d in dirs]
    return abs_dirs, len(abs_dirs)


def read_json(filename):
    with open(filename, "r") as input_file:
        data_list = json.load(input_file)

    return data_list


def header_print(s: str) -> None:
    """Print something in a block of #'s.

    Args:
        s (str): String to print. Strings with newlines will be split, and all lines are stripped of spaces.
    """
    lines = s.split("\n")
    for i, _ in enumerate(lines):
        lines[i] = lines[i].strip()
    lens = [len(l) for l in lines]

    print(f"\n####{'#' * max(lens)}####")
    for l in lines:
        print(f"### {l.ljust(max(lens))} ###")
    print(f"####{'#' * max(lens)}####")


def subheader_print(s: str) -> None:
    """Print something in a block of #'s.

    Args:
        s (str): String to print. Strings with newlines will be split, and all lines are stripped of spaces.
    """
    lines = s.split("\n")
    for i, _ in enumerate(lines):
        lines[i] = lines[i].strip()
    lens = [len(l) for l in lines]

    print(f"\n##{'#' * max(lens)}##")
    for l in lines:
        print(f"# {l.ljust(max(lens))} #")
    print(f"##{'#' * max(lens)}##")


# def write_csv_file(loc, data, type):
#     with open(loc, mode=type, newline="") as file:
#         csv_writer = csv.writer(file)
#         # , delimiter = ',', quoting = csv.QUOTE_MINIMAL
#         if type == TAG_NODE:
#             for dict in data:
#                 csv_writer.writerow(
#                     [
#                         dict[COLUMN_INDEX_ID],
#                         dict[COLUMN_INDEX_LABELS],
#                         dict[COLUMN_INDEX_TYPE],
#                         dict[COLUMN_INDEX_FLAGS],
#                         dict[COLUMN_INDEX_LINE],
#                         dict[COLUMN_INDEX_CODE],
#                         dict[COLUMN_INDEX_CHILDNUM],
#                         dict[COLUMN_INDEX_FUNCID],
#                         dict[COLUMN_INDEX_CLASSNAME],
#                         dict[COLUMN_INDEX_NAMESPACE],
#                         dict[COLUMN_INDEX_ENDLINE],
#                         dict[COLUMN_INDEX_NAME],
#                         dict[COLUMN_INDEX_DOCCOMMENT],
#                     ]
#                 )

#         elif type == TAG_EDGES:
#             return False

#         elif type == TAG_CPG_EDGES:
#             for dict in data:
#                 csv_writer.writerow(
#                     [
#                         dict[COLUMN_INDEX_START],
#                         dict[COLUMN_INDEX_END],
#                         dict[COLUMN_INDEX_TYPE],
#                         dict[COLUMN_INDEX_VAR],
#                         dict[COLUMN_INDEX_TAINTSRC],
#                         dict[COLUMN_INDEX_TAINTDST],
#                         dict[COLUMN_INDEX_FLOWLABEL],
#                     ]
#                 )

# def moveFile(source, destination):
#     shutil.move(source, destination)

# def copyFile():
#     shutil.copyfile(NODES_CSV_MODIFIED_FILE_LOC, NEO4J_IMPORT_NODES_CSV_LOC)
#     shutil.copyfile(EDGES_CSV_MODIFIED_FILE_LOC, NEO4J_IMPORT_EDGES_CSV_LOC)
#     shutil.copyfile(CPG_EDGES_CSV_MODIFIED_FILE_LOC, NEO4J_IMPORT_CPG_EDGES_CSV_LOC)

# def read_JS_dir(fileloc):
#     data_list = []
#     for file in os.listdir(fileloc):
#         if file.endswith(".js"):
#             filepath = os.path.join(fileloc, file)
#             # data = read_CSV_file(filepath)
#             data_list.append(filepath)
#             # print(os.path.join(fileloc, file))
#     return data_list

# def readCSVFile(loc):
#     data_list = []
#     with open(loc, mode="r", newline="") as csv_file:
#         csv_reader = csv.reader(csv_file)
#         for row in csv_reader:
#             data_list.append(row)
#             print(row)
#             print("new line")
#     return data_list

# def nodeFileReformat():
#     rloc = NODES_CSV_FILE_LOC
#     wloc = "../../navex_docker/result/results/nodes_w.csv"

#     # 13
#     total_column = 13

#     lines = read_file(rloc)
#     list = []
#     for line in lines:

#         print(line)
#         print("new line")

#         if line:
#             data = line.split("\t")

#             if len(data) == total_column:
#                 dict = {}

#                 dict[COLUMN_INDEX_ID] = data[0]
#                 dict[COLUMN_INDEX_LABELS] = data[1]
#                 dict[COLUMN_INDEX_TYPE] = data[2]
#                 dict[COLUMN_INDEX_FLAGS] = data[3]
#                 dict[COLUMN_INDEX_LINE] = data[4]
#                 dict[COLUMN_INDEX_CODE] = data[5]
#                 dict[COLUMN_INDEX_CHILDNUM] = data[6]
#                 dict[COLUMN_INDEX_FUNCID] = data[7]
#                 dict[COLUMN_INDEX_CLASSNAME] = data[8]
#                 dict[COLUMN_INDEX_NAMESPACE] = data[9]
#                 dict[COLUMN_INDEX_ENDLINE] = data[10]
#                 dict[COLUMN_INDEX_NAME] = data[11]
#                 dict[COLUMN_INDEX_DOCCOMMENT] = data[12]

#                 list.append(dict)

#     write_csv_file(wloc, list, TAG_NODE)

# def write_json(data, filename, type):
#     # with open(filename, type) as output:
#     #     outstr = json.dumps(data, indent=2)
#     #     output.write(outstr)

#     with open(filename, type, encoding="utf-8") as f:
#         json.dump(data, f, ensure_ascii=False, indent=2)
#     print("data has been written to- " + filename)

# def make_cpg_edges_format():
#     rloc = NODES_CSV_FILE_LOC
#     wloc = "../../navex_docker/result/results/cpg_edges_w.csv"

#     lines = read_file(rloc)
#     list = []
#     for line in lines:
#         if line:
#             data = line.split("\t")

#             if len(data) > 6:
#                 dict = {}
#                 dict[COLUMN_INDEX_START] = data[0]
#                 dict[COLUMN_INDEX_END] = data[1]
#                 dict[COLUMN_INDEX_TYPE] = data[2]
#                 dict[COLUMN_INDEX_VAR] = data[3]
#                 dict[COLUMN_INDEX_TAINTSRC] = data[4]
#                 dict[COLUMN_INDEX_TAINTDST] = data[5]
#                 dict[COLUMN_INDEX_FLOWLABEL] = data[6]

#                 list.append(dict)

#     write_csv_file(wloc, list, TAG_CPG_EDGES)

# def readUsingPandas():
#     import pandas as pd

#     rloc = NODES_CSV_FILE_LOC
#     df = pd.read_csv(rloc)
#     saved_column = df.column_name
#     print(saved_column)

# def removeQuoteFromCSV(input, output):
#     with open(input, "r", newline="") as f, open(output, "w", newline="") as fo:
#         for line in f:
#             fo.write(line.replace('"', "").replace("'", ""))

# def convertTabWithComma(input, output):
#     """
#     it will convert all the tab to comma. we need to convert this before importing the csv file to Neo4j.
#     """
#     with open(input, "r", encoding="utf-8", errors="ignore") as f, open(
#         output, "w", encoding="utf-8"
#     ) as fo:
#         for line in f:
#             fo.write(line.replace("\t", ","))

# def splitFile(input, output):
#     """
#     it will split the big file into multiple files. In each file highest number of allowable row is MINIMUM_ROW_NUMBER, which can be modified from Settings.py
#     sample input file will have the following format - "edges_w.csv", where the output will be "edges_w_1.csv", "edges_w_2.csv" and so on.
#     """

#     csvfile = open(input, "r").readlines()
#     filenumber = 1
#     header = ""
#     needHeader = False
#     for i in range(len(csvfile)):
#         if i == 0:
#             header = csvfile[i]  # we need to write header to each of multiple files
#         if i % MINIMUM_ROW_NUMBER == 0:
#             filename = output.split(".")[0] + "_" + str(filenumber) + ".csv"
#             if needHeader == True:
#                 content = [header] + csvfile[i : i + MINIMUM_ROW_NUMBER]
#                 open(str(filename), "w+").writelines(content)
#             else:  # we will not write the header for the first file
#                 open(str(filename), "w+").writelines(csvfile[i : i + MINIMUM_ROW_NUMBER])
#                 needHeader = True
#             filenumber += 1

# def convert_tabs():
#     convertTabWithComma(NODES_CSV_FILE_LOC, NODES_CSV_MODIFIED_FILE_LOC)
#     convertTabWithComma(CPG_EDGES_CSV_FILE_LOC, CPG_EDGES_CSV_MODIFIED_FILE_LOC)
#     convertTabWithComma(EDGES_CSV_FILE_LOC, EDGES_CSV_MODIFIED_FILE_LOC)

# if __name__ == "__main__":
#     convert_tabs()
