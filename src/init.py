""" File: init.py
    Author: Jan Polisensky, Petr Kolouch
    ----
    Main file for encapsulation functionality for Mendel implementation of domain evaluation
"""


# Import basic modules and libraries
import json
import os

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import numpy as np
import argparse

import re
import Database
from Data_loader import Base_parser
import SSL_loader
import Parser
from Parser import Net
from Preprocessor import preprocess
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import dotenv_values

# Load custom modules
from Core import clasifier
from mendelDB import *
from json_output import *
from queries import *

SECONDS_IN_DAY = 86400
SECONDS_IN_WEEK = SECONDS_IN_DAY * 7
env = dotenv_values(".env.mendel")
CACHE_FILE = "/tmp/ddos-7/cache.json"
PROTO_REGEX = re.compile("^https?:\/\/(www.)?", re.IGNORECASE)
PATH_REGEX = re.compile("/.*$", re.IGNORECASE)
WWW_REGEX = re.compile("^www.", re.IGNORECASE)


class resolver:
    """
    Class for controling core module

    :param domain_name: string containing domain name
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
    
    #Argument parsing
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

    parser.add_argument("--test", type=str, help="Testing only")
    parser.add_argument("--protocol", type=str, default='https', help='specify the protocol (http/https)')

    args = parser.parse_args()

    testing = args.test;
    if testing is not None:
        print("[INFO] testing mode enabled")
        testing_url = args.test
        res = resolver(testing_url, None, None, None, None, args.aggressive)
        test_results, fetched_results, combined_results = res.get_combined()
        print(f"the test result is: {test_results}\n fetched: {fetched_results}\n combined: {combined_results}")
        exit(0)


    # Fetch data from 3rd party apis if true
    useAggressive = args.aggressive
    # Store results into a JSON file
    toJSON = args.json
    # Protocol to evaluate (HTTP/HTTPS) 
    protocol = args.protocol.lower()

    #Database connection
    conn = psycopg2.connect(env["MENDEL_CONNECTION_STRING"])
    cur = conn.cursor()

    print("[INFO] dateStart: {0} dateEnd: {1}".format(dateStart, dateEnd))
    print("[INFO] accessing ddos-7 folder in /tmp")

    # Create 
    if not os.path.exists("/tmp/ddos-7"):
        print("[INFO] creating ddos-7 folder in temp")
        os.mkdir("/tmp/ddos-7", mode=0o777)

    print(f"[INFO] executing QUERY for {protocol}")
    if(protocol=='http'):
        cur.execute(HTTP_QUERY)
    else:
        protocol = 'https'
        cur.execute(HTTPS_QUERY)

    # While there are results being fetched
    while True:
        print(f"[INFO] fetching {protocol} QUERY")
        protocol_result = cur.fetchmany(5000)
        if not protocol_result:
            print("no more results to fetch, exiting...")
            break
        domains = []
    
        # All model results
        results = []
        badResults = []

        # Results based on information fetched from 3rd party apis only
        results_fetched = []
        badResults_fetched = []

        # Results based on Mendel database enhanced by 3rd party apis
        results_combined = []
        badResults_combined = []

        cache = load_cache(CACHE_FILE)

        # Get parsed data for the model
        for record in createQueryResultObject(protocol_result, protocol):
            protocol_record, dns = record

            hostname = protocol_record["dst_domain"]
            hostname = re.sub(PROTO_REGEX, "", hostname)
            hostname = re.sub(PATH_REGEX, "", hostname)
            hostname = re.sub(WWW_REGEX, "", hostname)
            
            if hostname not in cache:
                cache[hostname] = currentTimestamp
            elif cache[hostname] + (SECONDS_IN_WEEK) >= currentTimestamp:
                print(
                    "[INFO] hostname {0} found in cache, skipping evaluation".format(
                        hostname
                    )
                )
                continue

            ip = protocol_record["dst_ip_addrs"]
            domains.append(hostname)

            GEOIP_QUERY = getGEOIP_QUERY(ip)
           
            print("[INFO] fetching geo data for " + hostname + " with ip: " + ip)
            cur.execute(GEOIP_QUERY)
            geoip_result = cur.fetchall()
            geo = createGeoObject(geoip_result)

            print(f"[INFO] the values are: hostname: {hostname}\t record{protocol_record}\t geo: {geo}\t dns: {dns}")
            try:
                res = resolver(
                    hostname,
                    protocol_record,
                    geo,
                    dns,
                    ip,
                    useAggressive,
                )
            except IndexError:
                print("data error at index")
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
    cur.close()
    conn.close()
