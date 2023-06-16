import json
import pandas as pd
import sys


def load_json(file):
    with open(file, "r") as f:
        data = json.load(f)
    return data

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jsonToCSV.py <json_file>")
        return

    file = sys.argv[1]
    data = load_json(file)

    expanded_data = []
    for result in data["results"]:
        for key in result:
            item = result[key].copy()
            item["type"] = key
            expanded_data.append(item)

    df = pd.DataFrame(expanded_data)
    df.to_csv("sheet.csv", index=False)

if __name__ == "__main__":
    main()
