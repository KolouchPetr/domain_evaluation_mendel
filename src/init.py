""" File: init.py
    Author: Jan Polisensky
    ----
    Example usage of classifier core module
"""


# Import basic modules and libraries
import json
import os
import sys
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
import numpy as np
import argparse


import psycopg2
from dotenv import dotenv_values

# Load custom modules
import Database
from Data_loader import Base_parser
import SSL_loader
import Parser
from Parser import Net
from Preprocessor import preprocess 
from Core import clasifier
from mendelDB import *

env = dotenv_values(".env.mendel")


class resolver:
    """
    Class for controling core module 
    ...
    Attributes
    ----------
    domain_name : str
        string containing domain name  

    """

    def __init__(self, domain_name, ssl_data, geo_data, dns_data, ip, useAggressive) -> None:
        self.cls = clasifier(ssl_data, geo_data, dns_data, ip, useAggressive)
        self.domain_name = domain_name

    # Get combined prediction, details can be found in REDME or documentation
    # Returns -> dictionary containg prediction of domain badnes
    def get_combined(self) -> dict:
        lexical = self.cls.get_lexical(self.domain_name)
        data_based = self.cls.get_data(self.domain_name)
        svm = self.cls.get_svm(self.domain_name)
        
        combined, accuracy = self.cls.get_mixed(self.domain_name) 
        if(combined is None or accuracy is None):
            return None

        combined = np.around(combined, 3)
        accuracy = np.around(accuracy, 3)

        svm = np.around(svm, 3)
        lexical = np.around(lexical, 3)
        data_based = np.around(data_based, 3)

        rating ={
            "domain_name" : self.domain_name,
            "lexical" : lexical,
            "data-based" : data_based,
            "svm" : svm,
            "combined": combined,
            "accuracy": accuracy
        }
        return rating

    # Get prediction based only on lexical features(does not need to fetch any data)
    # Returns -> dictionary containg prediction of domain badnes
    def get_lexical(self) -> dict:
        lexical = self.cls.get_lexical(self.domain_name)
        lexical = np.around(lexical, 3)
        rating = {
            "domain_name" : self.domain_name,
            "lexical" : lexical
        }

        return rating

    # Get prediction from SVM model
    # Returns -> dictionary containg prediction of domain badnes
    def get_svm(self) -> dict:
        svm = self.cls.get_svm(self.domain_name)
        svm = np.around(svm, 3)
        rating = {
            "domain_name" : self.domain_name,
            "support-vector-machines" : svm
        }

        return rating

    # Get prediction based on main Data model
    # Returns -> dictionary containg prediction of domain badnes
    def get_data(self) -> dict:
        data_based = self.cls.get_data(self.domain_name)
        data_based = np.around(data_based, 3)
        rating = {
            "domain_name" : self.domain_name,
            "data-based_prediction" : data_based
        }

        return rating

    # Param data: JSON object to be printed to output file
    def output_json(self, data) -> None:
        rating_json = json.dumps(data, indent = 4)

        with open(self.domain_name + '.json', "w") as outfile:
            outfile.write(rating_json)

    # Param data: JSON object to be printed to STDOUT
    def output_stdout(self, data) -> None:
        print(json.dumps(data, indent = 4))
        



if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='Mendel URL Analyser', description='Mendel implementation of domain name analysis tool')
    parser.add_argument('--aggressive', action='store_true', help='Fetch missing information from 3rd party APIs')

    args = parser.parse_args()
    useAggressive = args.aggressive

    conn = psycopg2.connect(env['MENDEL_CONNECTION_STRING'])

    cur = conn.cursor()

    #DNS_QUERY = "SELECT src_json->'questions', dst_json->'answers' FROM nb.flows01, unnest(src_app_json) AS src_json, unnest   (dst_app_json) AS dst_json WHERE service='DNS' LIMIT 100;"
   
   #TODO update HTTP query
    HTTP_QUERY = """
                    SELECT array_unique(src_ip_addr) AS src_ip_addr, array_unique(dst_ip_addr),dst_domains 
                    FROM nb.flows01 
                    WHERE service='HTTP'AND dst_domains IS NOT NULL
                    GROUP BY dst_domains
                    LIMIT 100;
                """

   # HTTPS_QUERY =   """
   #                 SELECT DISTINCT ON (dst_domains) timestamp, src_ip_addr,
   #                 dst_ip_addr, dst_domains, dst_json->'Valid from',
   #                 dst_json->'Valid until', dst_json->'issuerdn' 
   #                 FROM nb.flows01, unnest(dst_app_json) AS dst_json 
   #                 WHERE service='HTTPS' AND dst_domains IS NOT NULL
   #                 LIMIT 100;"""

    HTTPS_QUERY = """
                    SELECT array_unique(src_ip_addr) AS src_ip_addrs, array_unique(dst_ip_addr) AS dst_ip_addrs,
                    dst_domains[1], array_unique(dst_json->'Valid from') AS valid_from ,
                    array_unique(dst_json->'Valid until') AS Valid_until, array_unique(dst_json->'issuerdn') AS issuerdn
                    FROM nb.flows01,
                    unnest(dst_app_json) AS dst_json 
                    WHERE timestamp >= now() - interval '24h' AND service='HTTPS' AND dst_domains IS NOT NULL AND dst_json->'issuerdn' IS NOT NULL
                    AND length(dst_domains[1])<20 AND dst_domains[1] ~* '^[a-zA-Z].*'
                    GROUP BY dst_domains, timestamp ORDER BY timestamp DESC
                    limit 10;
                  """


    cur.execute(HTTPS_QUERY)
    https_result = cur.fetchall()
    https_json = createQueryResultObject("https_result", https_result, "https")
    i = 0
    domains = []
    for https_record in https_json["results"]:
            hostname = https_record['dst_domains']
            ip = https_record['dst_ip_addrs'][0]
            i+=1
            domains.append(hostname)
            DNS_QUERY=""" SELECT array_unique(src_json->'questions') AS questions,
            array_unique(dst_json->'answers') AS answers 
            FROM nb.flows01,
            unnest(src_app_json) AS src_json,
            unnest(dst_app_json) AS dst_json, 
            jsonb_array_elements(src_json->'questions') AS question 
            WHERE timestamp >= now() - interval '24h' AND service='DNS' AND (question->>'rrname')::text='{0}';
            """.format(hostname)

            GEOIP_QUERY ="""
            SELECT ip_addrs, country_code, latitude, longitude, city, geoip_asn.company,geoip_asn.code 
            FROM ti.geoip_asn
            JOIN ti.asns ON geoip_asn.code=asns.code
            WHERE '{0}'::inet << ip_addrs
            """.format(ip)

            cur.execute(GEOIP_QUERY)
            geoip_result = cur.fetchall()
            geo = createQueryResultObject("geoip_result", geoip_result, "geoip") 

            cur.execute(DNS_QUERY)
            dns_result = cur.fetchall()
            dns = createQueryResultObject("dns_result", dns_result, "dns")

            #FIXME geo and/or dns can be null at certain times
            #print("[GEO] " , geo)
            #print("[DNS]" , dns)
            
            res = resolver(hostname, https_record, geo["results"][0], dns["results"][0], ip, useAggressive)
            r_data = res.get_combined()
            if(r_data is None):
                print("[Error] result of type None received")
                continue
            else:
                res.output_stdout(r_data)
            

    with open("domains.txt", "w") as f:
        for hostname in domains:
            f.write(hostname+'\n')
    cur.close()
    conn.close()
    

