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
             #if(row[6] is not None):
             #   dst_ip_rep.append(str(row[6]))
             #else:
             #   dst_ip_rep.append("None")
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
                     "dst_domain":row[2],
                     "ssl_valid_from":row[3],
                     "ssl_valid_until":row[4],
                     "ssl_issuer":ssl_issuer
             }
         elif(type_t == "http"):
             result_dict = {
                     "src_ip_addrs":row[0],
                     "dst_ip_addrs":row[1],
                     "dst_domain":row[2],
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
