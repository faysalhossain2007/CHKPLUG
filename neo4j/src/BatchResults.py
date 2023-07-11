# GDPR Checker - BatchResults.py
# Patrick Thomas pwt5ca
# Created 200813

import argparse
import csv
import os
from typing import Optional, Set

from Detectors.FlowScores import FlowSecurity
from Settings import ROOT_DIR


class ResultDatabase:
    """Class to provide an interface to log and save broad, overall results from a batch run."""

    _header = [
        "plugin_name",
        "crypt_nodes",
        "storage_nodes",
        "third_parties",
        "api_urls",
        "data_paths",
        "secure_data_paths",
        "insecure_data_paths",
        *(f"path_{v.name}" for v in list(FlowSecurity)),
    ]

    def __init__(self, path: Optional[str] = None):
        """Create a new batch results manager.

        Args:
            path (str, optional): Path to write the CSV to. Defaults to None.
        """
        if not path:
            path = os.path.join(ROOT_DIR, "results", "batch_results.csv")
        self.output_file = path

    def new_table(self):
        """Erase the old batch results CSV and replace it with a blank no file. THIS WILL OVERWRITE ALL RESULTS, use with caution!"""
        with open(self.output_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(self._header)

    def save(
        self,
        plugin_name: str,
        storage_nodes: int,
        crypto_nodes: int,
        all_paths: dict,
        api_urls: Set[str],
    ):
        """Save a line to the batch results CSV.

        Args:
            plugin_name (str): The name of the plugin.
            storage_nodes (int): The number of storage node in the AST.
            crypto_nodes (int): The number of cryptography nodes in the AST.
            all_paths (dict): A dict from path ID to DataFlowPath for all regsitered data flows.
            api_urls (Set[str]): A set of API URLs used by the PHP application.
        """
        secure_paths = []
        insecure_paths = []

        for k, v in all_paths.items():
            try:
                v.scoreFlow()
            except Warning:
                pass
            if v.score.flow_overall in {
                FlowSecurity.UNKNOWN_SECURITY_SAVED,
                FlowSecurity.HIGH_SECURITY_SAVED,
                FlowSecurity.LOW_SECURITY_SAVED,
            }:
                secure_paths.append(v.score)
            elif v.score.flow_overall == FlowSecurity.NO_SECURITY_SAVED:
                insecure_paths.append(v.score)

        flow_security_per_path = [v.score.flow_overall for v in all_paths.values()]

        line = [
            plugin_name,
            crypto_nodes,
            storage_nodes,
            len(api_urls) > 0,
            sorted(list(api_urls)),
            len(all_paths),
            len(secure_paths),
            len(insecure_paths),
        ]

        score_stats = [0 for member in FlowSecurity]
        for index, member in enumerate(FlowSecurity):
            score_stats[index] = flow_security_per_path.count(member)

        line.extend(score_stats)

        # Create a new table/write the header if the file is gone.
        if not os.path.isfile(self.output_file):
            self.new_table()

        # Save the line of data.
        with open(self.output_file, "a+", newline="") as f:
            w = csv.writer(f)
            w.writerow(line)

    def close(self):
        """Close the manager.

        Raises:
            DeprecationWarning: No longer needed since CSVs are now used rather than SQLite.
        """
        raise DeprecationWarning("close() is no longer needed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset the batch run database.")
    parser.add_argument("-r", "--reset", help="Reset the database", action="store_true")
    parser.add_argument("-t", "--test", help="Run tests", action="store_true")

    args = parser.parse_args()
    if args.reset:
        input(
            "Are you sure? THIS WILL DELETE ALL CURRENT BATCH SUMMARY RESULTS. Press enter to continue."
        )
        db = ResultDatabase()
        db.new_table()
    elif args.test:
        # Test the database.
        print("Results database test")
        db = ResultDatabase()
        db.new_table()
        # db.save("test", 5, 3, 2)
