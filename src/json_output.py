import json
import os

def print_results_to_json(fileName, results, results_fetched, results_combined):
    fileName = "/tmp/ddos-7/{0}".format(fileName)
    result = [{"mendel": a, "fetched": b, "combined": c} for a, b, c in zip(results, results_fetched, results_combined)]

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


def load_cache(cacheFile):
    if not os.path.isfile(cacheFile):
        return {}
    
    with open(cacheFile, "r") as f:
        return json.load(f)
    
def print_cache_into_file(cacheFile, cacheObject):
    with open(cacheFile, "w") as f:
        json.dump(cacheObject, f, indent=4)

