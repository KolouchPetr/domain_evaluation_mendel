# domain evaluation
## implementation for Mendel by GREYCORTEX
### Based on https://github.com/poli-cz/domain_evaluation

# Instalation
- clone repository
- pip3 install -r requirements.txt
- create .env.mendel file with *MENDEL_CONNECTION_STRING* and *IPINFO_TOKEN* inside /src

# Usage
- execute the script as python3 init.py [--aggressive] [--json] [--protocol PROTOCOL]

## Flags
- **--aggressive** fetch missing information from 3rd party apis
- **--json** store results into json files inside /tmp/ddos7
- **--protocol** choose whether to fetch HTTP/HTTPS data from database (HTTPS is default)

# Results

## Files
In case you use the --json flag, there will be a file with all the results *resultsFormated.json*
and a result with combined result < 0.20 and accuracy >= 0.94 in *badResultsFornated.json*
both in /tmp/ddos7

## Structure
``` json
"results": [
        {
            "mendel": {
                "domain_name": "0733c26c6c58be065ae365ff0bc32f97.safeframe.googlesyndication.com",
                "lexical": 0.001,
                "data-based": 0.031,
                "svm": 0.0,
                "combined": 0.024,
                "accuracy": 0.893
            },
            "fetched": {
                "domain_name": "0733c26c6c58be065ae365ff0bc32f97.safeframe.googlesyndication.com",
                "lexical": 0.001,
                "data-based": 0.073,
                "svm": 0.0,
                "combined": 0.023,
                "accuracy": 0.875
            },
            "combined": {
                "domain_name": "0733c26c6c58be065ae365ff0bc32f97.safeframe.googlesyndication.com",
                "lexical": 0.001,
                "data-based": 0.031,
                "svm": 0.0,
                "combined": 0.02430372290685773,
                "accuracy": 0.893
            }
        },
 ```
 
- **mendel** represents data fetched from mendel database only
- **fetched** represents data fetched from apis only
- **combined** represents data from mendel enhanced by data from fetched

| Key        | Value                      |
|------------|----------------------------|
| domain_name| name of the domain         |
| lexical    | results from lexical model  |
| data-based | results from data based model|
| svm        | results from SVM           |
| combined   | combined results           |
| accuracy   | results accuracy           |

