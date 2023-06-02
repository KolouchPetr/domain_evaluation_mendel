""" File: mendelDB.py
    Author: Petr Kolouch, Michal Novotny
    ----
    Main file for encapsulation functionality for Mendel implementation of domain evaluation
"""

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

"""
convert_to_null_or_add_sql_quotes adds sql quotes to a param

:param param: string to add the sql quotes to
"""
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



"""
 Report Asset Discovery Tool event to the database

 :param connstr: connection string to connect to database
 :param ip_address: IP address to report event for
 :param event: event SID
 :param msg: message to add to the event
 :param service: service or port to add

 :returns
  0 on success
  1 on error
"""

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

"""
createQueryResultObject takes fetched data from the Mendel database and parses
it into an object, that the AI models can work with

:param result: database query result
:param protocol: protocol that was fetched (either HTTP/HTTPS)
"""
def createQueryResultObject(result, protocol):
    if(protocol == "https"):
            for row in result:
             ssl_issuer = None
             valid_from = None
             valid_until = None
             if(row[2] != None):
                 dst_info = str(row[2]).split(', ')
                 for substr in dst_info:
                     if(substr.startswith("O=")):
                         ssl_issuer=substr
                         break;

                 valid_from = row[2].get('Valid from')
                 valid_until = row[2].get('Valid until')

             https_result_dict = {
                     "src_ip_addrs":row[3][0],
                     "dst_ip_addrs":row[4][0],
                     "dst_domain":row[0],
                     "ssl_valid_from":valid_from,
                     "ssl_valid_until":valid_until,
                     "ssl_issuer":ssl_issuer
             }
             dns_result_dict = {
                     "questions":row[5],
                     "answers":row[6]
                     }
             yield https_result_dict, dns_result_dict
    elif(protocol == "http"):
        for row in result:
            http_result_dict = {
                "src_ip_addrs":row[1][0],
                "dst_ip_addrs":row[2][0],
                "dst_domain":row[0],
                "ssl_valid_from":None,
                "ssl_valid_until":None,
                "ssl_issuer": None
                }
            dns_result_dict = {
                "questions":row[3],
                "answers":row[4]
                }
            yield http_result_dict, dns_result_dict, 


"""
createGeoObject creates an object the AI models can work with to GEOIP data

:param result: database query result
"""
def createGeoObject(result):
    if(len(result) < 1):
        return {}
    row = result[0]
    result_dict = {
    "ip_addrs":row[0],
                     "country":row[1],
                     "loc":str(row[2])+", "+str(row[3]),
                     "city":row[4],
                     "org":"AS"+str(row[6])+" "+str(row[5])
                     }
    return result_dict

