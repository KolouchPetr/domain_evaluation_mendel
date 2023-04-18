""" File: init.py
    Author: Jan Polisensky
    ----
    Example usage of classifier core module
"""


# Import basic modules and libraries
import json
import os
import sys

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import numpy as np
import argparse

import Database
from Data_loader import Base_parser
import SSL_loader
import Parser
from Parser import Net
from Preprocessor import preprocess
import psycopg2
from dotenv import dotenv_values

# Load custom modules
from Core import clasifier
from mendelDB import *
from json_output import *
from datetime import datetime, timedelta
import time

SECONDS_IN_DAY = 86400
SECONDS_IN_WEEK = SECONDS_IN_DAY * 7
env = dotenv_values(".env.mendel")
CACHE_FILE = "/tmp/ddos-7/cache.json"


class resolver:
    """
    Class for controling core module
    ...
    Attributes
    ----------
    domain_name : str
        string containing domain name

    """

    def __init__(
        self, domain_name, ssl_data, geo_data, dns_data, ip, useAggressive
    ) -> None:
        self.cls = clasifier(ssl_data, geo_data, dns_data, ip, useAggressive)
        self.domain_name = domain_name

    # Get combined prediction, details can be found in REDME or documentation
    # Returns -> dictionary containg prediction of domain badnes
    def get_combined(self) -> dict:
        lexical = self.cls.get_lexical(self.domain_name)
        data_based, data_based_fetched, data_based_combined = self.cls.get_data(
            self.domain_name
        )
        svm, svm_fetched, svm_combined = self.cls.get_svm(self.domain_name)

        (
            combined,
            accuracy,
            combined_fetched,
            accuracy_fetched,
            combined_combined,
            accuracy_combined,
        ) = self.cls.get_mixed(self.domain_name)
        if combined is None or accuracy is None:
            return None

        combined = np.around(combined, 3)
        accuracy = np.around(accuracy, 3)

        combined_fetched = np.around(combined_fetched, 3)
        accuracy_fetched = np.around(accuracy_fetched, 3)

        combined = np.around(combined_combined, 3)
        accuracy = np.around(accuracy_combined, 3)

        svm = np.around(svm, 3)
        svm_fetched = np.around(svm_fetched, 3)
        svm_combined = np.around(svm_combined, 3)

        lexical = np.around(lexical, 3)

        data_based = np.around(data_based, 3)
        data_based_fetched = np.around(data_based_fetched, 3)
        data_based_combined = np.around(data_based_combined, 3)

        rating = {
            "domain_name": self.domain_name,
            "lexical": lexical,
            "data-based": data_based,
            "svm": svm,
            "combined": combined,
            "accuracy": accuracy,
        }

        rating_fetched = {
            "domain_name": self.domain_name,
            "lexical": lexical,
            "data-based": data_based_fetched,
            "svm": svm_fetched,
            "combined": combined_fetched,
            "accuracy": accuracy_fetched,
        }

        rating_combined = {
            "domain_name": self.domain_name,
            "lexical": lexical,
            "data-based": data_based_combined,
            "svm": svm_combined,
            "combined": combined_combined,
            "accuracy": accuracy_combined,
        }
        return rating, rating_fetched, rating_combined

    # Get prediction based only on lexical features(does not need to fetch any data)
    # Returns -> dictionary containg prediction of domain badnes
    def get_lexical(self) -> dict:
        lexical = self.cls.get_lexical(self.domain_name)
        lexical = np.around(lexical, 3)
        rating = {"domain_name": self.domain_name, "lexical": lexical}

        return rating

    # Get prediction from SVM model
    # Returns -> dictionary containg prediction of domain badnes
    def get_svm(self) -> dict:
        svm = self.cls.get_svm(self.domain_name)
        svm = np.around(svm, 3)
        rating = {"domain_name": self.domain_name, "support-vector-machines": svm}

        return rating

    # Get prediction based on main Data model
    # Returns -> dictionary containg prediction of domain badnes
    def get_data(self) -> dict:
        data_based = self.cls.get_data(self.domain_name)
        data_based = np.around(data_based, 3)
        rating = {"domain_name": self.domain_name, "data-based_prediction": data_based}

        return rating

    # Param data: JSON object to be printed to output file
    def output_json(self, data) -> None:
        rating_json = json.dumps(data, indent=4)

        with open(self.domain_name + ".json", "w") as outfile:
            outfile.write(rating_json)

    # Param data: JSON object to be printed to STDOUT
    def output_stdout(self, data) -> None:
        print(json.dumps(data, indent=4))


if __name__ == "__main__":
    print("[INFO] script starting")
    parser = argparse.ArgumentParser(
        prog="Mendel URL Analyser",
        description="Mendel implementation of domain name analysis tool",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Fetch missing information from 3rd party APIs",
    )
    parser.add_argument(
        "--json", action="store_true", help="Store results into JSON files"
    )

    args = parser.parse_args()
    useAggressive = args.aggressive
    toJSON = args.json

    conn = psycopg2.connect(env["MENDEL_CONNECTION_STRING"])

    cur = conn.cursor()

    # DNS_QUERY = "SELECT src_json->'questions', dst_json->'answers' FROM nb.flows01, unnest(src_app_json) AS src_json, unnest   (dst_app_json) AS dst_json WHERE service='DNS' LIMIT 100;"

    # TODO update HTTP query
    HTTP_QUERY = """
                    SELECT array_unique(src_ip_addr) AS src_ip_addr, array_unique(dst_ip_addr),dst_domains 
                    FROM nb.flows30 
                    WHERE service='HTTP'AND dst_domains IS NOT NULL
                    GROUP BY dst_domains
                    LIMIT 100;
                """
    #    HTTPS_QUERY = """
    #                    SELECT array_unique(src_ip_addr) AS src_ip_addrs, array_unique(dst_ip_addr) AS dst_ip_addrs,
    #                    dst_domains[1], array_unique(dst_json->'Valid from') AS valid_from ,
    #                    array_unique(dst_json->'Valid until') AS Valid_until, array_unique(dst_json->'issuerdn') AS issuerdn,
    #                    dst_ip_rep
    #                    FROM nb.flows30
    #                    TABLESAMPLE BERNOULLI (10),
    #                    unnest(dst_app_json) AS dst_json
    #                    WHERE timestamp >= now() - interval '24h' AND service='HTTPS' AND dst_domains IS NOT NULL AND dst_sn_addr IS NULL
    #                    GROUP BY dst_domains, timestamp, dst_ip_rep ORDER BY random(), timestamp DESC
    #                    LIMIT 25;
    #                  """

    today = datetime.today()
    dateStart = (today - timedelta(days=2)).strftime("%Y-%m-%d")
    tomorrow = (today + timedelta(days=1)).strftime("%Y-%m-%d")
    currentTimestamp = int(str(time.time()).split(".")[0])
    HTTPS_QUERY = """
                    SELECT * FROM (
                    SELECT array_unique(src_ip_addr) AS src_ip_addrs, array_unique(dst_ip_addr) AS dst_ip_addrs, dst_domain, array_unique(dst_json->'Valid from') AS valid_from ,
                    array_unique(dst_json->'Valid until') AS Valid_until, array_unique(dst_json->'issuerdn') AS issuerdn
                    FROM nb.flows30, unnest(dst_domains) dst_domain, unnest(dst_app_json) AS dst_json
                    WHERE timestamp >= '{0}' AND timestamp < '{1}' AND service='HTTPS' AND dst_domains IS NOT NULL AND dst_sn_addr IS NULL AND src_sn_addr IS NOT NULL
                    AND dst_ip_rep IS NULL
                    group by dst_domain
                    HAVING split_part(dst_domain,'.',-2) NOT IN 
                    ('google','amazonaws','microsoft','windows','apple','facebook','googlevideo','live','icloud','googleapis','cloudfront','akadns','skype','googleusercontent','doubleclick')
                    LIMIT 15
                    ) x
                    order by array_length(src_ip_addrs,1) desc
                """.format(
        dateStart, tomorrow
    )

    print("[INFO] dateStart: {0} tomorrow: {1}".format(dateStart, tomorrow))

    print("[INFO] creating ddos-7 folder in temp")
    if not os.path.exists("/tmp/ddos-7"):
        os.mkdir("/tmp/ddos-7", mode=0o777)

    print("[INFO] fetching HTTPS data")
    cur.execute(HTTPS_QUERY)
    https_result = cur.fetchall()
    print(f"https result: {https_result}")
    https_json = createQueryResultObject("https_result", https_result, "https")
    i = 0
    domains = []

    results = []
    badResults = []

    results_fetched = []
    badResults_fetched = []

    results_combined = []
    badResults_combined = []

    cache = load_cache(CACHE_FILE)

    for https_record in https_json["results"]:
        hostname = https_record["dst_domain"]

        if hostname not in cache:
            cache[hostname] = currentTimestamp
        elif cache["hostname"] + (SECONDS_IN_WEEK) >= currentTimestamp:
            print(
                "[INFO] hostname {0} found in cache, skipping evaluation".format(
                    hostname
                )
            )
            continue

        ip = https_record["dst_ip_addrs"][0]
        i += 1
        domains.append(hostname)
        DNS_QUERY = """ SELECT array_unique(src_json->'questions') AS questions,
            array_unique(dst_json->'answers') AS answers 
            FROM nb.flows30,
            unnest(src_app_json) AS src_json,
            unnest(dst_app_json) AS dst_json, 
            jsonb_array_elements(src_json->'questions') AS question 
            WHERE timestamp >= '{0}' AND timestamp < '{1}' AND service='DNS' AND (question->>'rrname')::text='{2}';
            """.format(
            dateStart, tomorrow, hostname
        )

        GEOIP_QUERY = """
            SELECT ip_addrs, country_code, latitude, longitude, city, geoip_asn.company,geoip_asn.code 
            FROM ti.geoip_asn
            JOIN ti.asns ON geoip_asn.code=asns.code
            WHERE '{0}'::inet << ip_addrs
            LIMIT 1
            """.format(
            ip
        )

        print("[INFO] fetching geo data for " + hostname + " with ip: " + ip)
        cur.execute(GEOIP_QUERY)
        geoip_result = cur.fetchall()
        geo = createQueryResultObject("geoip_result", geoip_result, "geoip")

        print("[INFO] fetching dns data for " + hostname)
        cur.execute(DNS_QUERY)
        dns_result = cur.fetchall()
        dns = createQueryResultObject("dns_result", dns_result, "dns")

        # FIXME geo and/or dns can be null at certain times
        # print("[GEO] " , geo)
        # print("[DNS]" , dns)

        res = resolver(
            hostname,
            https_record,
            geo["results"][0],
            dns["results"][0],
            ip,
            useAggressive,
        )
        print("[INFO] getting predictions")
        r_data, r_data_fetched, r_data_combined = res.get_combined()
        if r_data is None or r_data_fetched is None or r_data_combined is None:
            print("[Error] result of type None received")
            continue
        else:
            if float(r_data["combined"]) <= 0.20 and float(r_data["accuracy"]) >= 0.94:
                badResults.append(r_data)
            results.append(r_data)

            if (
                float(r_data_fetched["combined"]) <= 0.20
                and float(r_data_fetched["accuracy"]) >= 0.94
            ):
                badResults_fetched.append(r_data_fetched)
            results_fetched.append(r_data_fetched)

            if (
                float(r_data_combined["combined"]) <= 0.20
                and float(r_data_combined["accuracy"]) >= 0.94
            ):
                badResults_combined.append(r_data_combined)
            results_combined.append(r_data_combined)
            # res.output_stdout(r_data)

    print_cache_into_file(CACHE_FILE, cache)
    if toJSON == True:
        print_results_to_json(
            "resultsFormated.json", results, results_fetched, results_combined
        )
        print_results_to_json(
            "badResultsFormated.json",
            badResults,
            badResults_fetched,
            badResults_combined,
        )

    # with open("domains.txt", "w") as f:
    #    for hostname in domains:
    #        f.write(hostname+'\n')
    cur.close()
    conn.close()
