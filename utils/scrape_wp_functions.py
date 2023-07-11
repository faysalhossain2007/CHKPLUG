#!/bin/python3

import collections
import concurrent.futures
import json
import multiprocessing
import re

import requests
from bs4 import BeautifulSoup


PAGES_MAX = 100


def get_links(u):
    # print(u + "...", end="")
    r = requests.get(u)
    soup = BeautifulSoup(r.text, "html.parser")

    if "Page not found" in "".join(soup.stripped_strings):
        # print("Page not found. Stopping group.")
        return {}

    content = soup.find("div", id="content")
    links = content.find_all("h1")
    return {str(l.a.contents[0]).strip("()") for l in links}


def get_func_info(k):
    url = f"https://developer.wordpress.org/reference/functions/{k}/"
    # print(f"\n{k}: {url}")
    r = requests.get(url)

    soup = BeautifulSoup(r.text, "html.parser")
    output = {"url": url}
    params = soup.find("section", attrs={"class": "parameters"})
    if params and params.dl:
        for dt in params.dl.find_all("dt"):
            dd = dt.find_next_sibling("dd")
            desc = dd.find_next("p", attrs={"class": "desc"})
            default = desc.find_next("p", attrs={"class": "default"})
            arg_info_spans = desc.find_all("span", recursive=False)

            output[dt.contents[0]] = dict()

            for s in arg_info_spans:
                if s["class"] == ["type"]:
                    output[dt.contents[0]]["type"] = []
                    results = s.find_all("span", recursive=False)
                    for t in results:
                        output[dt.contents[0]]["type"].append(str(t["class"][0]))
                elif s["class"] == ["required"]:
                    output[dt.contents[0]]["required"] = "Required" in "".join(s.strings)
                elif s["class"] == ["description"]:
                    output[dt.contents[0]]["description"] = re.sub(
                        "\s+", " ", " ".join(s.stripped_strings)
                    )

            if default:
                output[dt.contents[0]]["default"] = default.contents[0].split(":", 1)[-1].strip()

    return_val = soup.find("section", attrs={"class": "return"})
    if return_val:
        output["returns"] = dict()
        return_type = return_val.find("span", attrs={"class": "return-type"})
        return_description = str(return_type.next_sibling).strip()

        output["returns"]["types"] = "".join(return_type.stripped_strings).strip("()").split("|")
        output["returns"]["description"] = re.sub("\s+", " ", str(return_description))

    return output


def run():
    # Get a list of all function names.
    all_keywords = set()
    urls1 = [
        f"https://developer.wordpress.org/reference/functions/page/{i}/"
        for i in range(1, PAGES_MAX)
    ]
    urls2 = [
        f"https://developer.wordpress.org/?s=wp&post_type%5B0%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls3 = [
        f"https://developer.wordpress.org/?s=update&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls4 = [
        f"https://developer.wordpress.org/?s=add&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls5 = [
        f"https://developer.wordpress.org/?s=get_&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls5 = [
        f"https://developer.wordpress.org/?s=user&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls5 = [
        f"https://developer.wordpress.org/?s=post&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls6 = [
        f"https://developer.wordpress.org/?s=delete&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls7 = [
        f"https://developer.wordpress.org/?s=remove&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls8 = [
        f"https://developer.wordpress.org/?s=meta&post_type%5B%5D=wp-parser-function&paged={i}"
        for i in range(1, PAGES_MAX)
    ]
    urls = [urls1, urls2, urls3, urls4, urls5, urls6, urls7, urls8]

    lock = multiprocessing.Lock()

    for url_group in urls:
        with concurrent.futures.ProcessPoolExecutor() as executor:
            futures = [executor.submit(get_links, u) for u in url_group]
            # exec_map = zip(url_group, executor.map(get_links, url_group))
            for i, f in enumerate(futures):
                if f.cancelled():
                    break
                links = f.result()
                lock.acquire()
                all_keywords.update(links)
                print(url_group[i], len(all_keywords))

                if not links:
                    print("Cancelling all later jobs...")
                    for f in futures[i:]:
                        f.cancel()
                    lock.release()
                    break

                lock.release()

    all_keywords = sorted(list(all_keywords))
    all_info = collections.OrderedDict()

    lock = multiprocessing.Lock()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for k, result in zip(all_keywords, executor.map(get_func_info, all_keywords)):
            all_info[k] = result
            lock.acquire()
            print(k)
            lock.release()

    with open("Detectors/wordpress_functions.json", "w") as f:
        json.dump(all_info, f, indent=2)


if __name__ == "__main__":
    run()
