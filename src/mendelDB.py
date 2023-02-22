import psycopg2
import datetime
import json


#TODO rewrite this bash function to python

##
# From mendel.bash:
# Prepare insert query for SM event
#
# For detailed description of all arguments, see definition of
# plpgsql function sm.insert_event
#
# Usage:
#   prepare_sm_event_query "" "sensor" "-580" "" "" "904" "Detailed
#description"
#
# @param $1 timestamp
# @param $2 sensor
# @param $3 sid
# @param $4 src_ip
# @param $5 src_mac
# @param $6 dst_port
# @param $7 description
# @return query
##
#function prepare_sm_event_query() {
#
#     ts="$(_convert_to_null_or_add_sql_quotes "$1")"
#     sensor="$(_convert_to_null_or_add_sql_quotes "$2")"
#     sid="$(_convert_to_null_or_add_sql_quotes "$3")"
#     src_ip="$(_convert_to_null_or_add_sql_quotes "$4")"
#     src_mac="$(_convert_to_null_or_add_sql_quotes "$5")"
#     dst_port="$(_convert_to_null_or_add_sql_quotes "$6")"
#
#     # Commands can contain bad characters so prevent query breakage
#     description="$7"
#     if [ -z "$description" ]; then description="NULL"; else
#         single_quote="'"
#         escaped_single_quote="\\''"
#description="'${description//$single_quote/$escaped_single_quote}'"
#     fi
#
#     echo "SELECT sm.insert_event(""$ts""::timestamp with time zone,
#""$sensor""::varchar, ""$sid""::bigint, ""$src_ip""::inet,
#""$src_mac""::macaddr, ""$dst_port""::integer, ""$description""::varchar);"
#}
#

def convert_to_null_or_add_sql_quotes(param):
    if(param):
        return "'"+param+"'"
    return None


def prepare_sm_event_query(timestamp, sensor, sid, src_ip, src_mac, dst_port, description):
    timestamp = convert_to_null_or_add_sql_quotes(timestamp)
    sensor = convert_to_null_or_add_sql_quotes(sensor)
    sid = convert_to_null_or_add_sql_quotes(sid)
    src_ip = convert_to_null_or_add_sql_quotes(src_ip)
    src_mac = convert_to_null_or_add_sql_quotes(src_mac)
    dst_port = convert_to_null_or_add_sql_quotes(dst_port)
    description = convert_to_null_or_add_sql_quotes(description)



##
# Report Asset Discovery Tool event to the database
#
# @param connstr connection string to connect to database
# @param ip_address IP address to report event for
# @param event event SID
# @param msg message to add to the event
# @param service service or port to add
#
# @returns
#  0 on success
#  1 on error
#





#function report_adt_event()

#    def load_whois_data(self):
#            #print("[Info]: LOADING WHOIS DATA\n")
#            whois_record = {}
#            try:
#                types = ['registrar', 'creation_date', 'expiration_date', 'dnssec', 'emails']
#                w = whois.whois(self.hostname)
#                #print("[INFO] w from whois is: \n")
#                #print(w)
#                i = 0
#                for type in types:
#                    try:
#                        whois_record[types[i]] = w[types[i]]
#                    except:
#                        whois_record[types[i]] = None
#
#                    i=i+1
#                self.whois_data = whois_record
#                #print("whois data\n")
#                #print(whois_record)
#                return True
#
#
#    def load_dns_data(self, result):
#        if(result = None):
#            self.dns = None
#            return
#            #print("Loading DNS data")
#            types = ['A', 'AAAA', 'CNAME', 'SOA', 'NS', 'MX', 'TXT']
#            #types = ['TXT']
#            dns_records = {}
#            i = 0
#            for type in types:
#                    dns_records[types[i]] = result[types[i]]
#                    i=i+1
#
#                #print(type + " " + self.hostname + " --> " + str(result[0]))
#                #input()
#                if type == 'A':
#                    self.ip = result[0]
#                print("DNS type " + type +" " + str(result[0]))
#                dns_records[types[i]] = str(result[0])
#                i=i+1
#            self.dns = dns_records
#
#        def load_geo_info(self, ip, result):
#            #print("Loading Geo info data")
#            
#            geo_data = {}
#            keys = ['country', 'region' ,'city' ,'loc' ,'org']
#            for i in range(len(keys)):
#                geo_data[keys[i]] = result[keys[i]]
#
#            self.geo_data = geo_data
#            print("geo data:")
#            print(geo_data)
#
#        def load_ssl_data(self, result):
#            ssl_data = {'is_ssl': result['is_ssl'],
#                        'ssl_data': {
#                            'issuer': result['issuer'],
#                            'end_date': datetime.datetime(result['end_date']),
#                            'start_date': datetime.datetime(result['start_date'])
#                            }
#            print("ssl data:")
#            print(self.ssl_data)
#                if type == 'A':
#                    self.ip = result[0]
#                print("DNS type " + type +" " + str(result[0]))
#                dns_records[types[i]] = str(result[0])
#                i=i+1
#            self.dns = dns_records
#
#        def load_geo_info(self, ip, result):
#            #print("Loading Geo info data")
#            
#            geo_data = {}
#            keys = ['country', 'region' ,'city' ,'loc' ,'org']
#            for i in range(len(keys)):
#                geo_data[keys[i]] = result[keys[i]]
#
#            self.geo_data = geo_data
#            print("geo data:")
#            print(geo_data)
#
#        def load_ssl_data(self, result):
#            ssl_data = {'is_ssl': result['is_ssl'],
#                        'ssl_data': {
#                            'issuer': result['issuer'],
#                            'end_date': datetime.datetime(result['end_date']),
#                            'start_date': datetime.datetime(result['start_date'])
#                            }
#            print("ssl data:")
#            print(self.ssl_data)

def get_connection_string(ident='DBConnDB'):
    ret = None
    with open('/etc/ti.conf', "r") as f:
        for line in f:
            if ident + '=' in line:
                ret = line.split(ident + '=')[1]
    ret = ret.strip()
    if not 'postgresql://' in ret:
        cmd = 'TPTIAC=key aesCrypt "{}"'.format(ret.replace('$', '\\$'))
        from subprocess import Popen, PIPE, STDOUT
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        ret = p.stdout.read().strip().decode()
    return ret

def writeQueryResultIntoFile(filename, result, type_t):
                    with open(filename+".json", "w") as f:
                        f.write("{ \"results\":[")
                        resultCounter = 0
                        resultCount = len(result)
                        for row in result:
                            if(type_t == "https"):
                                if(row[6] != None):
                                    ssl_issuer = row[6].split(', ')
                                    for substr in ssl_issuer:
                                        if(substr.startswith("O=")):
                                            ssl_issuer=substr
                                            break;
                                result_dict = {
                                        "timestamp":row[0],
                                        "src_ip_addr":row[1],
                                        "dst_ip_addr":row[2],
                                        "dst_domains":row[3],
                                        "ssl_valid_from":row[4],
                                        "ssl_valid_until":row[5],
                                        "ssl_issuer":ssl_issuer
                                }
                            elif(type_t == "http"):
                                result_dict = {
                                        "timestamp":row[0],
                                        "src_ip_addr":row[1],
                                        "dst_ip_addr":row[2],
                                        "dst_domains":row[3],
                                        }
                            elif(type_t == "geoip"):
                                result_dict = {
                                        "ip_addrs":row[0],
                                        "country_code":row[1],
                                        "latitude":row[2],
                                        "longitude":row[3]
                                        }
                            elif(type_t == "dns"):
                                result_dict = {
                                        "questions":row[0],
                                        "answers":row[1]
                                        }
                            result_json = json.dumps(result_dict, indent=4, default=str)
                            f.write(result_json)
                            resultCounter +=1
                            if(resultCounter < resultCount):
                                f.write(",")
                        f.write("]}")

def main():
    connectionString = get_connection_string()
    conn = psycopg2.connect(connectionString)

    cur = conn.cursor()

    ip = ""
    domain = ""
    #DNS_QUERY = "SELECT src_json->'questions', dst_json->'answers' FROM nb.flows01, unnest(src_app_json) AS src_json, unnest   (dst_app_json) AS dst_json WHERE service='DNS' LIMIT 100;"
    
    HTTP_QUERY = """
                    SELECT timestamp, src_ip_addr, dst_ip_addr, dst_domains 
                    FROM nb.flows01 
                    WHERE service='HTTP'AND dst_domains IS NOT NULL 
                    LIMIT 100;
                """

    HTTPS_QUERY =   """
                    SELECT timestamp, src_ip_addr, dst_ip_addr, dst_domains, dst_json->'Valid from',
                    dst_json->'Valid until', dst_json->'issuerdn' 
                    FROM nb.flows01, unnest(dst_app_json) AS dst_json 
                    WHERE service='HTTPS' AND dst_domains IS NOT NULL
                    LIMIT 100;"""


    cur.execute(HTTPS_QUERY)
    https_result = cur.fetchall()
    writeQueryResultIntoFile("https_result", https_result, "https")    
    
    with open("https_result.json") as f:
        https_json = json.load(f)
        i = 0
        for https_record in https_json["results"]:
            if(i < 5):
                domain = https_record['dst_domains'][0]
                ip = https_record['dst_ip_addr']
                i+=1
                DNS_QUERY="""
                    SELECT src_json->'questions', dst_json->'answers' 
                    FROM nb.flows01, 
                         unnest(src_app_json) AS src_json, 
                         unnest(dst_app_json) AS dst_json, 
                         jsonb_array_elements(src_json->'questions') AS question 
                    WHERE service='DNS' AND question->>'rrname'='{0}' 
                    LIMIT 100;""".format(domain)
                GEOIP_QUERY ="""
                SELECT ip_addrs, country_code, latitude, longitude 
                FROM ti.geoip_asn
                WHERE '{0}'::inet << ip_addrs
                LIMIT 10;
                """.format(ip)
                cur.execute(GEOIP_QUERY)
                geoip_result = cur.fetchall()
                writeQueryResultIntoFile("geoip_result", geoip_result, "geoip")
                cur.execute(DNS_QUERY)
                dns_result = cur.fetchall()
                writeQueryResultIntoFile("dns_result", dns_result, "dns")
            break
                

    cur.close()
    conn.close()

if __name__ == "__main__":
    main()


#SELECT timestamp, 
#FROM nb.flows01
#WHERE service='HTTP' OR (service='DNS' AND dst_domains IN (SELECT dst_domains FROM nb.flows01 WHERE service='HTTP'))

