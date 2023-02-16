import psycopg2

ip = ""
domain = ""
#DNS_QUERY = "SELECT src_json->'questions', dst_json->'answers' FROM nb.flows01, unnest(src_app_json) AS src_json, unnest(dst_app_json) AS dst_json WHERE service='DNS' LIMIT 100;"
HTTP_QUERY = """
                SELECT timestamp, src_ip_addr, dst_ip_addr, dst_domains 
                FROM nb.flows01 
                WHERE service='HTTP' 
                LIMIT 100;"""

HTTPS_QUERY = """
                SELECT timestamp, src_ip_addr, dst_ip_addr, dst_domains, dst_json->'Valid from', dst_json->'Valid until', dst_json->'issuerdn' 
                FROM nb.flows01, unnest(dst_app_json) AS dst_json 
                WHERE service='HTTPS' 
                LIMIT 100;"""
GEOIP_QUERY = """
                SELECT country_code, latitude, longitude 
                FROM ti.geoip_asn 
                WHERE ip_addr={0}""".format(ip)

DNS_QUERY="""
                SELECT src_json->'questions', question->>'rrname', dst_json->'answers' 
                FROM nb.flows01, 
                     unnest(src_app_json) AS src_json, 
                     unnest(dst_app_json) AS dst_json, 
                     jsonb_array_elements(src_json->'questions') AS question 
                WHERE service='DNS' AND question->>'rrname'='{0}' 
                LIMIT 100;""".format(domain)


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
#{
#     local connstr="${1}"
#     local ip_address="${2}"
#     local event="${3}"
#     local msg="${4}"
#     local service="${5}"
#
#     local sensor="$(get_local_sensor_name)"
#
#     if [ -z "$event" ]; then
#         return 1
#     fi
#
#     qry="SELECT mac_addrs[1] FROM ti.hosts WHERE ip_addr =
#'${ip_address}' LIMIT 1;"
#     if ! mac="$(psql_select "${connstr}" "${qry}")"; then
#         mac="00:00:00:00:00:00"
#     fi
#     qry="$(prepare_sm_event_query "NOW()" "${sensor}" "-${event}"
#"${ip_address}" "${mac}" "${service}" "${msg}")"
#     if ! psql_insert "${connstr}" "${qry}"; then
#         gcx_log_error "Query '${qry}' failed"
#         return 1
#     else
#         return 0
#     fi
#}


def load_dns_data(self):
        #print("Loading DNS data")
        types = ['A', 'AAAA', 'CNAME', 'SOA', 'NS', 'MX', 'TXT']
        #types = ['TXT']
        dns_records = {}
        i = 0
        for type in types:
            result = None;
            try:
                result = self.dns_resolver.resolve(self.hostname, type)
            except Exception as e:
                #print(type + " is not available for this hostname")
                dns_records[types[i]] = None
                i=i+1
                continue

            #print(type + " " + self.hostname + " --> " + str(result[0]))
            #input()
            if type == 'A':
                self.ip = result[0]
            print("DNS type " + type +" " + str(result[0]))
            dns_records[types[i]] = str(result[0])
            i=i+1
        self.dns = dns_records

    def load_geo_info(self, ip=None):
        #print("Loading Geo info data")
        if ip is None:
            if self.ip is None:
                #print("Ip of hostname not discovered, doing it manualy...")
                try:
                    self.ip = self.ip_from_host()[self.hostname][0]
                except:
                    print("[Info]: Cant resolve hostname to IP")
                return False
        else:
            self.ip = ip
        
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

        self.geo_data = geo_data
        print("geo data:")
        print(geo_data)

    def load_ssl_data(self):
        self.ssl_data = SSL_loader.discover_ssl(self.hostname, self.timeout)
        print("ssl data:")
        print(self.ssl_data)

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


def main():
    connectionString = get_connection_string()
    conn = psycopg2.connect(connectionString)

    cur = conn.cursor()




    #cur.execute("SELECT * from nb.flows01 where service='HTTP' LIMIT 100;")
    result = cur.fetchall()

    for row in result:
        print(row)

    cur.close()
    conn.close()

if __name__ == "__main__":
    main()