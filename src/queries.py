""" File: queries.py
    Author: Petr Kolouch
    ----
    File for storing Mendel database queries
"""
import time
from datetime import datetime, timedelta

currentTimestamp = int(str(time.time()).split(".")[0])

try:
    with open('timestamp.txt', 'r') as f:
        previous_timestamp = int(f.read())
except FileNotFoundError:
        previous_timestamp = int(datetime(2023, 6, 13).timestamp())

current_timestamp = previous_timestamp - 24*60*60

previous_date = datetime.fromtimestamp(previous_timestamp)
current_date = datetime.fromtimestamp(current_timestamp)

dateStart = (current_date - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S+00')
dateEnd = current_date.strftime('%Y-%m-%d %H:%M:%S+00')

with open('timestamp.txt', 'w') as f:
    f.write(str(current_timestamp))

HTTP_QUERY = """
            WITH http_data AS materialized (
            SELECT * FROM (
            SELECT unnest(dst_domains) AS dst_domain,
            array_unique(src_ip_addr) AS src_ip_addr,
            array_unique(dst_ip_addr) AS dst_ip_addr
            FROM nb.flows30 
            WHERE timestamp >= '{0}' AND timestamp < '{1}' AND service='HTTP'
            GROUP BY 1
            ) AS a WHERE split_part(dst_domain, '.', -2) NOT IN ('google', 'amazonaws', 'microsoft', 'windows', 'apple', 'facebook', 'googlevideo', 'live', 'icloud', 'googleapis', 'cloudfront', 'akadns', 'skype', 'googleusercontent', 'doubleclick')
            ),
            dns_data AS materialized (
            SELECT * FROM (
            SELECT unnest(src_app_json) AS dns_request,
            unnest(dst_app_json) AS dns_reply FROM nb.flows30 WHERE timestamp >= '{0}' AND timestamp < '{1}' AND service='DNS' GROUP BY 1,2)
            AS a WHERE split_part(dns_request::text, '.', -2) NOT IN ('google', 'amazonaws', 'microsoft', 'windows', 'apple', 'facebook', 'googlevideo', 'live', 'icloud', 'googleapis', 'cloudfront', 'akadns', 'skype', 'googleusercontent', 'doubleclick')
            ) SELECT * FROM http_data JOIN dns_data ON dns_request::text ilike '%' || dst_domain || '%'
            ;
            """.format(dateStart, dateEnd)

HTTPS_QUERY = """
            WITH https_data AS materialized (
            SELECT * FROM (
            SELECT unnest(dst_domains) AS dst_domain,
            unnest(src_app_json) AS https_request,
            unnest(dst_app_json) AS https_reply,
            array_unique(src_ip_addr) AS src_ip_addr,
            array_unique(dst_ip_addr) AS dst_ip_addr
            FROM nb.flows30 
            WHERE timestamp >= '{0}' AND timestamp < '{1}' AND service='HTTPS'
            GROUP BY 1,2,3
            ) AS a WHERE split_part(dst_domain, '.', -2) NOT IN ('google', 'amazonaws', 'microsoft', 'windows', 'apple', 'facebook', 'googlevideo', 'live', 'icloud', 'googleapis', 'cloudfront', 'akadns', 'skype', 'googleusercontent', 'doubleclick')
            ),
            dns_data AS materialized (
            SELECT * FROM (
            SELECT unnest(src_app_json) AS dns_request,
            unnest(dst_app_json) AS dns_reply FROM nb.flows30 WHERE timestamp >= '{0}' AND timestamp < '{1}' AND service='DNS' GROUP BY 1,2)
            AS a WHERE split_part(dns_request::text, '.', -2) NOT IN ('google', 'amazonaws', 'microsoft', 'windows', 'apple', 'facebook', 'googlevideo', 'live', 'icloud', 'googleapis', 'cloudfront', 'akadns', 'skype', 'googleusercontent', 'doubleclick')
            ) SELECT * FROM https_data JOIN dns_data ON dns_request::text ilike '%' || dst_domain || '%'
            ;
                """.format(dateStart, dateEnd)

"""
getGEOIP_QUERY receive formated GEOIP query if a certain IP address

:param ip: An IP address to format the query with
"""
def getGEOIP_QUERY(ip):
    GEOIP_QUERY = """
    SELECT ip_addrs, country_code, latitude, longitude, city, geoip_asn.company,geoip_asn.code 
    FROM ti.geoip_asn
    JOIN ti.asns ON geoip_asn.code=asns.code
    WHERE '{0}'::inet << ip_addrs
    LIMIT 1
    """.format(
    ip
)
    return GEOIP_QUERY
