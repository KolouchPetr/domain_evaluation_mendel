""" File: json_output.py
    Author: Petr Kolouch
    ----
    Functionality for outputting results into a JSON file, cache IO
"""

import json
import os

"""
print_results_to_json takes all the AI model results and stores them inside a JSON file

:param fileName: name of the JSON file
:param results: Mendel data based results
:param results_fetched: results based on fetched data from 3rd party apis
:param results_combined: Mendel results enhanced with fetched data
"""
def print_results_to_json(fileName, results, results_fetched, results_combined, topList=False):
    fileName = "/home/ddos7/results/{0}".format(fileName)
    result = [{"mendel": a, "fetched": b, "combined": c} for a, b, c in zip(results, results_fetched, results_combined)]
    if topList:
        result = [{"fetched": a} for a in results]

    if not os.path.isfile(fileName):
        with open(fileName, "w") as f:
            json.dump({"results": []}, f)

    with open(fileName, "r+") as f:
        try:
            existing_data = json.load(f)
        except json.decoder.JSONDecodeError:
            existing_data = {"results": []}
        existing_data["results"].extend(result)
        f.seek(0)
        f.truncate(0)
        json.dump(existing_data, f, indent=4)


"""
load_cache loads, return the cache file

:param cacheFile: name of the cache file
"""
def load_cache(cacheFile):
    if not os.path.isfile(cacheFile):
        return {}
    
    with open(cacheFile, "r") as f:
        return json.load(f)
    
"""
print_cache_into_file dumps the cache into a file

:param cacheFile: the cache file
:param cacheObject: an object to be dumped into the cache
"""
def print_cache_into_file(cacheFile, cacheObject):
    with open(cacheFile, "w") as f:
        json.dump(cacheObject, f, indent=4)

