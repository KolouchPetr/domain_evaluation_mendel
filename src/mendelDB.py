import psycopg2
from datetime import datetime
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

#def load_dns_data(result):
#    dns_types = ['A', 'AAAA', 'CNAME', 'SOA', 'NS', 'MX', 'TXT']
#    dns_records = {
#            'A':None,
#            'AAAA':None,
#            'CNAME':None,
#            'SOA':None,
#            'NS':None,
#            'MX':None,
#            'TXT':None
#            }
#    if(result is not None and result["answers"] is not None):
#        for answers in result["answers"]:
#            for answer in answers:
#                    #print("in answer: ")
#                    #print(answer)
#                i = 0
#                for dns_type in dns_types:
#                    if(dns_types[i] == answer["rrtype"]):
#                        if(dns_records[dns_types[i]] is None):
#                            if(dns_types[i] == 'SOA'):
#                                dns_records[dns_types[i]] = "{0} {1} {2} {3} {4} {5} {6}".format(answer["mname"],
#                                                                                                 answer["rname"],
#                                                                                                 answer["serial"],
#                                                                                                 answer["refresh"],
#                                                                                                 answer["retry"],
#                                                                                                 answer["expire"],
#                                                                                                 answer["minimum"])
#                            elif("rdata" in answer): 
#                                dns_records[dns_types[i]] = answer["rdata"]
#                    i=i+1
#
#                    #print(type + " " + self.hostname + " --> " + str(result[0]))
#    return dns_records
#
#def load_geo_info(result):
# geo_data = {}
# #TODO region missing
# keys = ['country', 'region' ,'city' ,'loc' ,'org']
# for i in range(len(keys)):
#    if(keys[i] in result):
#     geo_data[keys[i]] = result[keys[i]]
#    else:
#        geo_data[keys[i]] = None
# return geo_data
#
#def load_ssl_data( result):
# is_ssl = result['ssl_issuer'] is not None
# ssl_data = {'is_ssl': is_ssl,
#             'ssl_data': {
#             'issuer': result['ssl_issuer'] if is_ssl else None,
#             'end_date': datetime.strptime(result['ssl_valid_from'][0], "%Y-%m-%dT%H:%M:%S") if is_ssl else None,
#             'start_date': datetime.strptime(result['ssl_valid_until'][0], "%Y-%m-%dT%H:%M:%S") if is_ssl else None
#                        }
#             }
# return ssl_data

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

def createQueryResultObject(filename, result, type_t):
     returnJson = { "results":[]}
     resultCounter = 0
     resultCount = len(result)
     for row in result:
         if(type_t == "https"):
             ssl_issuer = None
             if(row[5] != None):
                 ssl_issuer = str(row[5]).split(', ')
                 for substr in ssl_issuer:
                     if(substr.startswith("O=")):
                         ssl_issuer=substr
                         break;
             result_dict = {
                     "src_ip_addrs":row[0],
                     "dst_ip_addrs":row[1],
                     "dst_domains":row[2],
                     "ssl_valid_from":row[3],
                     "ssl_valid_until":row[4],
                     "ssl_issuer":ssl_issuer
             }
         elif(type_t == "http"):
             result_dict = {
                     "src_ip_addrs":row[0],
                     "dst_ip_addrs":row[1],
                     "dst_domains":row[2],
                     }
         elif(type_t == "geoip"):
             result_dict = {
                     "ip_addrs":row[0],
                     "country":row[1],
                     "loc":str(row[2])+", "+str(row[3]),
                     "city":row[4],
                     "org":"AS"+str(row[6])+" "+str(row[5])
                     }
         elif(type_t == "dns"):
             result_dict = {
                     "questions":row[0],
                     "answers":row[1]
                     }
         resultCounter +=1
         returnJson["results"].append(result_dict)
     return returnJson

def main():
    connectionString = "postgresql://melanie:5432/tidb?user=tidb&password=10.23456"
    conn = psycopg2.connect(connectionString)

    cur = conn.cursor()

    ip = ""
    domain = ""
    #DNS_QUERY = "SELECT src_json->'questions', dst_json->'answers' FROM nb.flows01, unnest(src_app_json) AS src_json, unnest   (dst_app_json) AS dst_json WHERE service='DNS' LIMIT 100;"
    
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
                  dst_domains, array_unique(dst_json->'Valid from') AS valid_from ,
                  array_unique(dst_json->'Valid until') AS Valid_until, array_unique(dst_json->'issuerdn') AS issuerdn
                  FROM nb.flows01,
                  unnest(dst_app_json) AS dst_json 
                  WHERE service='HTTPS' AND dst_domains IS NOT NULL 
                  GROUP BY dst_domains
                  limit 50;
                  """


    cur.execute(HTTPS_QUERY)
    https_result = cur.fetchall()
    print(https_result)
   # returnJson = createQueryResultObject("https_result", https_result, "https")
   # 
   # https_json = returnJson
   # i = 0
   # for https_record in https_json["results"]:
   #     if(i < 10):
   #         domain = https_record['dst_domains'][0]
   #         ip = https_record['dst_ip_addrs'][0]
   #         i+=1

   #         DNS_QUERY=""" SELECT array_unique(src_json->'questions') AS questions,
   #         array_unique(dst_json->'answers') AS answers 
   #         FROM nb.flows01,
   #         unnest(src_app_json) AS src_json,
   #         unnest(dst_app_json) AS dst_json, 
   #         jsonb_array_elements(src_json->'questions') AS question 
   #         WHERE service='DNS' AND (question->>'rrname')::text='{0}';
   #         """.format(domain)

   #         GEOIP_QUERY ="""
   #         SELECT ip_addrs, country_code, latitude, longitude, city, geoip_asn.company,geoip_asn.code 
   #         FROM ti.geoip_asn
   #         JOIN ti.asns ON geoip_asn.code=asns.code
   #         WHERE '{0}'::inet << ip_addrs
   #         LIMIT 10;
   #         """.format(ip)

   #         cur.execute(GEOIP_QUERY)
   #         geoip_result = cur.fetchall()
   #         geo = createQueryResultObject("geoip_result", geoip_result, "geoip") 

   #         cur.execute(DNS_QUERY)
   #         dns_result = cur.fetchall()
   #         dns = createQueryResultObject("dns_result", dns_result, "dns")

   #         ssl_data = load_ssl_data(https_record)
   #         geo_data = load_geo_info(geo["results"][0])
   #         dns_data = load_dns_data(dns["results"][0])
   #         domainResult = {"ssl": ssl_data,
   #                         "geo": geo_data,
   #                         "dns": dns_data}
   #         print("result for domain {0}".format(domain))
   #         print(domainResult)
   #         print("*********************************************************************")
   #     else:
   #         break

    cur.close()
    conn.close()

if __name__ == "__main__":
    main()


