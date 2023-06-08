""" File: Data_loader.py
    Author: Jan Polisensky
    ----
    Class and functions for domain data collection
"""


# Import generic modules

import socket
import concurrent.futures
import requests
import json
import sys
from pymongo import MongoClient
import pymongo
import urllib
import re
import io
import os
import time
import csv
import whois
from dotenv import dotenv_values 
from datetime import datetime
import dns.resolver

# Import custom modules
import Database
import SSL_loader

env = dotenv_values(".env.mendel")
#######################
#### resolver setup ###
#######################
ip_auth_token=env["IPINFO_TOKEN"]  # seznam token
forbiddenIps = {"0.0.0.0", "127.0.0.1", "255.255.255.255"} # nonsense IPs, feel free to add more
nonvalidTypes = {"csv"}  
validTxtTypes = {"plain", "octet-stream", "html"} 
validArchTypes = {"x-gzip"}  
ipRegEx = r"^((?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::)))))|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
ValidHostnameRegex = r"(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]"

class Data_loader:  
    def get_hostnames(self, file_path, position, max=1000):
        with open(file_path, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
            i = 0
            top_1k = []
            for row in spamreader:
                if i == max:
                    break
                try:
                    top_1k.append(row[position])
                    i=i+1
                except:
                    continue

            return top_1k
    
    def get_links(self, file_path):
        links = []
        with open(file_path) as csvf:
            reader = csv.reader(csvf)
            for row in reader:
                links.append(row[1])
            links = links[12:]
            links = [x for x in links if x!='']
            return links

    def clean_links(self, links):
        out_links = []
        for link in links:
            domain = re.search(ValidHostnameRegex, link)
            if domain:

                out_links.append(domain.group(0))

        return out_links
    
    def get_hostnames_from_links(self, input):
        ips = []
        hostnames = []
        i = 0
        for source in input:
            print("LOADED", i)
            i=i+1
            if i > 60:
                return hostnames
            if source.startswith("http"):
                try:
                    retrieved = urllib.request.urlretrieve(source, filename=None)
                except urllib.error.HTTPError as e:
                    #print(str(e) + " " + source, file=sys.stderr)
                    continue
                except urllib.error.URLError as e:
                    #print(str(e) + " " + source,file=sys.stderr)
                    continue
                # retrieved file
                file_tmp = retrieved[0]

                # file type of retrieved file
                file_info = retrieved[1]

                ctype = file_info.get_content_subtype()
                print(ctype)
                if ctype in nonvalidTypes:
                    continue

                print("Reading " + source + " " + ctype)

                if ctype in validTxtTypes:
                    with io.open(file_tmp, "r", encoding="utf-8") as f:
                        for line in f:
                            # All kinds of comments are being used in the sources, they could contain non-malicious domains
                            if len(line) != 0 and  \
                                    not line.startswith("#") and \
                                    not line.startswith(";") and \
                                    not line.startswith("//"):
                                x = re.search(ipRegEx, line)
                                if x:
                                    ip = x.group()
                                    if ip not in forbiddenIps:
                                        #print(ip)
                                        pass

                                        ##ips.append(ip)
                                    # if there is a nonsense ip the script still needs to ask if 
                                    # there is a domain because some of the sources look like this: 0.0.0.0 adservice.google.com.vn
                                    else:
                                        #print(ip)
                                        pass

                                else:
                                    domain = re.search(ValidHostnameRegex, line)
                                    if domain:

                                        hostnames.append(domain.group(0))
                    os.remove(file_tmp)
        return hostnames

class Base_parser:
    def __init__(self, hostname, resolver_timeout, ip, useAggressive=False):
        print("[Info]: Starting resolver for:", hostname)
        self.timeout = resolver_timeout
        self.hostname = hostname
        self.dns_data = None
        self.ip = ip
        self.geo_data = None
        self.whois_data = None
        self.ssl_data = None
        self.dns_data_fetched = None
        self.geo_data_fetched = None
        self.ssl_data_fetched = None
        self.dns_data_combined = None
        self.geo_data_combined = None
        self.ssl_data_combined = None
        self.useAggressive = useAggressive

        self.dns = None

        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        self.dns_resolver.timeout = resolver_timeout
        self.dns_resolver.lifetime = resolver_timeout

    def get_dns(self):
        return self.dns_data, self.dns_data_fetched, self.dns_data_combined

    def get_ip(self):
        return self.ip

    def get_geo_data(self):
        return self.geo_data, self.geo_data_fetched, self.geo_data_combined

    def get_ssl_data(self):
        return self.ssl_data, self.ssl_data_fetched, self.ssl_data_combined

    def get_whois_data(self):
        return self.whois_data

    def load_whois_data(self):
        #print("[Info]: LOADING WHOIS DATA\n")
        whois_record = {}
        try:
            types = ['registrar', 'creation_date', 'expiration_date', 'dnssec', 'emails']
            w = whois.whois(self.hostname)
            #print("[INFO] w from whois is: \n")
            #print(w)
            i = 0
            for type in types:
                try:
                    whois_record[types[i]] = w[types[i]]
                except:
                    whois_record[types[i]] = None

                i=i+1
            self.whois_data = whois_record
            #print("whois data\n")
            #print(whois_record)
            return True

        except Exception as e:
            print("[Info]: Resolver can't load all whois data")
            return False

    def fetch_missing_info(self, type_t, result):
        if self.useAggressive is None:
            return

        missing_data = [key for key, value in result.items() if value is None]
        print(f"{type_t} has missing attributes: {missing_data}")

        fetch_function = {
            "dns": self.fetch_dns_data,
            "geo": self.fetch_geo_info,
            "ssl": self.fetch_ssl_data,
        }.get(type_t)

        if fetch_function:
            fetched = fetch_function()
            print(f"[INFO] fetched: {fetched}")
            data_dict = getattr(self, f"{type_t}_data_combined")
            for missing in missing_data:
                print(f"[INFO] missing is: {missing}")
                if fetched[missing] is not None:
                    data_dict[missing] = fetched[missing]
                    print(f"[info] missing {missing} was fetched using aggressive mode, fetched value: {fetched[missing]}")


    def load_dns_data(self, result):
        dns_types = ['A', 'AAAA', 'CNAME', 'SOA', 'NS', 'MX', 'TXT']
        dns_records = {
                'A':None,
                'AAAA':None,
                'CNAME':None,
                'SOA':None,
                'NS':None,
                'MX':None,
                'TXT':None
                }
        if(result is not None and result["answers"] is not None):
            if result.get("answers") is not None and result.get("answers").get("answers") is not None and len(result.get("answers").get("answers")) > 0:
                answer = result.get("answers").get("answers")[0]
            else:
                return;
            if answer["rrtype"] == "SOA":
                dns_records["SOA"] = "{0} {1} {2} {3} {4} {5} {6}".format(answer["mname"] if "mname" in answer else None,
                                                                                                 answer["rname"] if "rname" in answer else None,
                                                                                                 answer["serial"] if "serial" in answer else None,
                                                                                                 answer["refresh"] if "refresh" in answer else None,
                                                                                                 answer["retry"] if "retry" in answer else None,
                                                                                                 answer["expire"] if "expire" in answer else None,
                                                                                                 answer["minimum"] if "minimum" in answer else None)
            elif answer["rrtype"] == "A":
                dns_records["A"] = answer["rdata"] if "rdata" in answer else None
            elif answer["rrtype"] == "AAAA":
                dns_records["AAAA"] = answer["rdata"]if "rdata" in answer else None
            elif answer["rrtype"] == "CNAME":
                dns_records["CNAME"] = answer["rdata"]if "rdata" in answer else None
            elif answer["rrtype"] == "NS":
                dns_records["NS"] = answer["rdata"]if "rdata" in answer else None
            elif answer["rrtype"] == "MX":
                dns_records["MX"] = answer["rdata"]if "rdata" in answer else None
            elif answer["rrtype"] == "TXT":
                dns_records["TXT"] = answer["rdata"]if "rdata" in answer else None

                    #print(type + " " + self.hostname + " --> " + str(result[0]))
        self.dns_data = dns_records.copy()
        self.dns_data_combined = dns_records.copy()
        self.fetch_missing_info('dns', dns_records)

    def load_geo_info(self, result):
        print(f"[INFO] result is: {result}")

        geo_data = {
                'country':None,
                'region':None,
                'city':None,
                'loc':None,
                'org':None,
                }
        if result is None:
            self.geo_data = geo_data.copy()
            self.geo_data_combined = geo_data.copy()
            return self.fetch_missing_info('geo', geo_data)
        #TODO region missing
        keys = ['country', 'region' ,'city' ,'loc' ,'org']
        for key in keys:
            if(key in result):
                geo_data[key] = result[key]
            else:
                geo_data[key] = None

        self.geo_data = geo_data.copy()
        self.geo_data_combined = geo_data.copy()
        print("[INFO] calling fetch_missing_info with geo")
        self.fetch_missing_info('geo', geo_data)

    def load_ssl_data(self, result):
        if result is None:
            ssl_data = {'is_ssl': None,
                    'ssl_data': {
                    'issuer': None,
                    'end_date': None,
                    'start_date': None
                        }
             }

            self.ssl_data = ssl_data.copy()
            self.ssl_data_combined = ssl_data.copy()
            return self.fetch_missing_info('ssl', ssl_data)


        is_ssl = result['ssl_issuer'] is not None
        ssl_data = {'is_ssl': is_ssl,
                    'ssl_data': {
                    'issuer': result['ssl_issuer'] if is_ssl else None,
                    'end_date': datetime.strptime(result['ssl_valid_until'], "%Y-%m-%dT%H:%M:%S") if is_ssl else None,
                    'start_date': datetime.strptime(result['ssl_valid_from'], "%Y-%m-%dT%H:%M:%S") if is_ssl else None
                        }
             }
        self.ssl_data = ssl_data.copy()
        self.ssl_data_combined = ssl_data.copy()
        self.fetch_missing_info('ssl', ssl_data)

    def fetch_dns_data(self):
        types = ['A', 'AAAA', 'CNAME', 'SOA', 'NS', 'MX', 'TXT']
        dns_records = {}
        for type_t in types:
            result = None;
            try:
                result = self.dns_resolver.resolve(self.hostname, type_t)
            except Exception as e:
                dns_records[type_t] = None
                continue

            dns_records[type_t] = str(result[0])

        self.dns_data_fetched = dns_records
        return dns_records

    def fetch_geo_info(self):
        print("[INFO] fetch_geo_info is being called")
        if self.ip is None:
            self.ip = self.ip_from_host()[self.hostname][0]
        
        geo_data = {}
        keys = ['country', 'region' ,'city' ,'loc' ,'org']
        url =  "https://ipinfo.io/" + str(self.ip) + "/?token=" + ip_auth_token
        raw_json = None
        try:
            raw_json = requests.get(url).json()
        except:
            self.geo_data = None
            return
        for i in range(len(keys)):
            try:
                geo_data[keys[i]] = raw_json[keys[i]]
            except:
                geo_data[keys[i]] = None

        self.geo_data_fetched = geo_data
        print(f"[INFO] setting geo data to {geo_data}")
        return geo_data

    def fetch_ssl_data(self):
        ssl_data = SSL_loader.discover_ssl(self.hostname, self.timeout)
        self.ssl_data_fetched = ssl_data
        return ssl_data


    def ip_from_host(self):
        hostname = self.hostname

        ips = []
        domainsIps = {}

        try:
            answer = self.dns_resolver.resolve(hostname)

            for item in answer:
                ips.append(item.to_text())

            domainsIps[hostname] = ips
            return domainsIps

        except Exception as e:
            print(answer)
            print(ips)
  
            print(str(e))
            domainsIps[hostname] = []
            return domainsIps

# fetch all data
def get_data(hostname):
    domain = Base_parser(hostname)
    domain.load_dns_data()
    domain.load_geo_info()
    domain.load_whois_data()
    

    dns_data = domain.get_dns()
    geo_data = domain.get_geo_data()
    whois_data = domain.get_whois_data()
 
    domain_data = {"name": hostname, "dns_data": dns_data, "geo_data": geo_data, "whois_data": whois_data}
    return domain_data

def get_database():
    client = MongoClient("mongodb://localhost/domains")
    return client['domains']

# insert good domains
def insert(hostname):
    db = get_database()
    print(hostname)
    good_domain_collection = db['goodDomains']
    data = get_data(hostname)
    print("G")
    print(str(good_domain_collection.replace_one({'name': data['name']},data, upsert=True)))

# insert bad domains
def insert_bad(hostname):
    db = get_database()
    bad_domain_collection = db['badDomains']
    data = get_data(hostname)
    print("B")
    print(str(bad_domain_collection.replace_one({'name': data['name']},data, upsert=True)))
    
def geo_corrector(collection):
    db = get_database()
    bad_domain_collection = db[collection]
    for domain in bad_domain_collection.find():
        print(domain)
        try:
            geo_data = domain['geo_data']
        except:
            print(domain)

            if domain['dns_data']['A'] != None:
                print(domain['name'], "resolvable!")
                p = Base_parser(domain['name'])
                p.load_geo_info(domain['dns_data']['A'])
                geo_data = p.get_geo_data()
                domain['geo_data'] = geo_data
                print(domain['name'])
                print(bad_domain_collection.replace_one({'name': domain['name']}, domain, upsert=True))
                print("corrected")




# If script is launched explicitly as main, it can be used to fill database with 
if __name__ == '__main__':

    l = Data_loader()
    db = get_database()

    d = Database.Database('domains')
    allDomains = d.return_db()
    fetched = True



    if not fetched:
        ### Fetch data ###
        ### Load data from links ###
        raw_blacklisted = l.get_links('../Data/blacklists-2021.01.csv')
        good_hostnames = l.get_hostnames('../Data/top-1m.csv', 1, 100000)
        bad_hostnames_1 = l.get_hostnames_from_links(raw_blacklisted)
        raw_spam = l.get_hostnames('../Data/spyware.csv', 0, 70000)

        # clean links from source
        cleaned_spam = l.clean_links(raw_spam)

        bad_hostnames = cleaned_spam + bad_hostnames_1
        ### inserting data in db ###
        good_domains = {
            "name": "good_domains",
            "domain_count": len(good_hostnames),
            "names": good_hostnames
        }

        bad_domains = {
            "name": "bad_domains",
            "domain_count": len(bad_hostnames),
            "names": bad_hostnames
        }
    #############################
    all_doms = d.return_collection('allDomains')

    result = all_doms.insert_many([good_domains, bad_domains])

    # Create a new collection
    good_domains = d.return_collection('allDomains')

    all_good_domains = good_domains.find_one({"name": "good_domains"})
    all_bad_domains = good_domains.find_one({"name": "bad_domains"})

    bad_domains = all_good_domains['names']
    good_domains = all_good_domains['names']



    bad_collection = d.return_collection("goodDomains")
    bad_in_db = []
    good_collection = d.return_collection("goodDomains")

    for domain in bad_collection.find():
        bad_in_db.append(domain['name'])


    print("filtering for duplicit records")
    bad_domains = list(dict.fromkeys(bad_domains))


    print("filtering already fetched data from database")
    final = []
    i=0
    for name in bad_domains:
        if name not in bad_in_db:
            final.append(name)
            i=i+1
            print(i)
            if i > 7000:
                break


    print("Ok, found", i, " Not fetched ips")

    print(len(good_domains))
    #input()


    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        list(pool.map(insert, final))
    #  list(pool.map(insert_bad, final))


            


