#!/bin/python3

"""
GDPR Checker
Patrick Thomas

This script reformats the plugin directory structure that we normally use. Since Rivanna has somewhat script limits on the number of allowed directories in user /scratch directories, it makes more sense for plugins to be unzipped as needed. This also only keeps unique plugins and does not keep duplicates.

Old directory structure:
plugins
    -   category a
        -   plugin a1
            -   code
                -   plugin a1
        -   plugin a2
            -   code
                -   plugin a2
        -   plugin a3
            -   code
                -   plugin a3
    -   category b
        -   plugin b1
            -   code
                -   plugin b1
        -   plugin b2
            -   code
                -   plugin b2
        -   plugin b3
            -   code
                -   plugin b3

New directory structure:
plugins_zip
    -   plugin a1.zip (zipped directory is one inside of code)
    -   plugin b1.zip
    -   plugin a2.zip
    -   plugin b2.zip
    -   plugin a3.zip
    -   plugin b3.zip
"""

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from progress.bar import Bar

LOCK = threading.Lock()

ROOT_DIR = "/run/media/thomas/storage/Documents/batch-run"
PLUGIN_DIR = "/run/media/thomas/storage/Documents/batch-run/wp_plugin"
DEST_DIR = "/run/media/thomas/storage/Documents/batch-run/wp_plugin_zip"


def run_cmd(cmd: str) -> int:
    result = subprocess.run(cmd, shell=True)
    # Exit script if signaled to stop.
    if result.returncode < 0:
        sys.exit(result.returncode)
    return result.returncode


if __name__ == "__main__":

    run_cmd(f""" mkdir -p {DEST_DIR} """)

    os.chdir(ROOT_DIR)
    all_plugin_dirs = []
    all_plugins = set()
    reduced_plugin_dirs = set()
    for category in os.listdir(PLUGIN_DIR):
        p = os.path.join(PLUGIN_DIR, category)
        if not os.path.isdir(p):
            continue
        for plugin in os.listdir(p):
            plugin_dir = os.path.join(p, plugin)
            all_plugin_dirs.append(plugin_dir)
            if plugin not in all_plugins:
                all_plugins.add(plugin)
                reduced_plugin_dirs.add(plugin_dir)

    # Skip zips that already exist.
    to_remove = set()
    current_zips = set(os.listdir(DEST_DIR))
    for p in reduced_plugin_dirs:
        dest = p.split("/")[-1] + ".zip"
        if dest in current_zips:
            to_remove.add(p)

    print(f"Of {len(all_plugin_dirs)} total plugins, {len(reduced_plugin_dirs)} are unique.")
    print(
        f"Skipping {len(to_remove)} plugins, should have {len(reduced_plugin_dirs) - len(to_remove)} plugins to compress."
    )

    plugins_to_compress = reduced_plugin_dirs.difference(to_remove)

    with Bar("Plugins", max=len(reduced_plugin_dirs), suffix="%(index)d - %(eta_td)s") as bar:
        bar.index = len(to_remove)
        with ThreadPoolExecutor(max_workers=4) as tpe:

            # Threaded function.
            def _job(d, bar):
                plugin_name = d.split("/")[-1]
                src = os.path.join(d, "code", d.split("/")[-1])
                dest = os.path.join(
                    DEST_DIR,
                    d.split("/")[-1] + ".zip",
                )
                run_cmd(
                    f""" cd "{os.path.join(d, "code")}" && zip -r {dest} ./{plugin_name} &> /dev/null """
                )
                LOCK.acquire()
                bar.next()
                LOCK.release()

            futures = [tpe.submit(_job, d, bar) for d in plugins_to_compress]
