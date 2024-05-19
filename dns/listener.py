#!/usr/bin/env python3
# pylint: disable=W0718
import sys
import json
import os
import logging
import time
import socket
import re
import sqlite3
import datetime
import hashlib

logger = logging.getLogger("HomeAssistant")
log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s:%(funcName)s] %(levelname)s: %(message)s ', datefmt="%Y-%m-%d %H:%M:%S")) # (%(thread)d %(threadName)s)
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

try:
    from dnslib.dns import DNSError, DNSQuestion
    from dnslib import DNSRecord,QTYPE,RCODE
    from dnslib.server import DNSServer,BaseResolver,DNSLogger
except ModuleNotFoundError:
    logger.error('Dnslib not Installed - try pip install dnslib')
    sys.exit(1)

try:
    import netaddr
except ModuleNotFoundError:
    logger.error('netaddr not Installed - try pip install netaddr')
    sys.exit(1)

# Some Configurable Options
try:
    with open('/data/options.json', "r", encoding="utf8") as file:
        options_f = file.read()
except Exception:
    logger.info('🚨🚨 Unable to -> FIND <- Home Assistant Options, will use DEFAULTS 🚨🚨')
else:
    try:
        options_data = json.loads(options_f)
    except Exception:
        logger.error('🚨🚨 Unable to ==> LOAD <== Home Assistant Options, will use DEFAULTS 🚨🚨')
        logger.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])

DEBUG_MODE = False      # Default => INFO
try:
    DEBUG_MODE = bool(options_data['debug'])
except Exception:
    pass
finally:
    logger.info('🫥  debug => %s', DEBUG_MODE)
    if DEBUG_MODE:
        logger.setLevel(logging.DEBUG)


UKNOWN_IP_PASS = True # Should default IPs learn? (True => Yes, False => Block)
try:
    if options_data['unknown_ip_action'] in ['ignore', 'block']:
        if options_data['unknown_ip_action'] == 'ignore':
            UKNOWN_IP_PASS = True
        if options_data['unknown_ip_action'] == 'block':
            UKNOWN_IP_PASS = False
except Exception:
    pass
logger.info('🫥  unknown_ip_action => %s',  UKNOWN_IP_PASS)

SOA_FAIL_ACTION = "ignore" # what to do if SOA lookup fails.
try:
    if options_data['soa_failure_action'] in ['ignore', 'block']:
        SOA_FAIL_ACTION = options_data['soa_failure_action']
except Exception:
    pass
finally:
    logger.debug('🫥  soa_failure_action => %s',  SOA_FAIL_ACTION)

DNS_DETECT_ON_HOST = False      # Default => Detect on Domain (SOA) Changes
try:
    DNS_DETECT_ON_HOST = bool(options_data['detect_on_host_query'])
except Exception:
    pass
finally:
    logger.info('🫥  detect_on_host_query => %s', DNS_DETECT_ON_HOST)

DNS_FIREWALL_ON = False      # Default => notify (detect) mode only
try:
    DNS_FIREWALL_ON = bool(options_data['dns_blocking_mode'])
except Exception:
    pass
finally:
    logger.info('🫥  dns_blocking_mode => %s', DNS_FIREWALL_ON)

LOCAL_NETWORKS = [] # LAN / IoT Network
try:
    LOCAL_NETWORKS = options_data['networks']
except Exception:
    LOCAL_NETWORKS.append('127.0.0.1') # Local Host for Testing :)
finally:
    logger.debug('🫥  Loading Networks => %s', str(LOCAL_NETWORKS))

LEARNING_DURATION = 30
try:
    LEARNING_DURATION = int(options_data['learning_duration'])
except Exception:
    pass
finally:
    logger.info('🫥  learning_duration => %s days', str(LEARNING_DURATION))

UPSTREAM_RESOLVERS = [] # DNS Servers
try:
    UPSTREAM_RESOLVERS = options_data['resolvers']
except Exception:
    pass
finally:
    logger.debug('🫥  Custom Resolvers => %s', str(UPSTREAM_RESOLVERS))

# Some Internal VARS
DB_T_DOMAINS = "domains"
DB_SCHEMA_T_DOMAINS = f'CREATE TABLE "{DB_T_DOMAINS}" ("id" TEXT, "domain" TEXT, "counter" INTEGER,"scope" TEXT, "action" TEXT,"last_seen" TEXT)'
DB_T_QUERIES = "queries"
DB_SCHEMA_T_QUERIES = f'CREATE TABLE "{DB_T_QUERIES}" ("id" TEXT, "src" TEXT,"src_type" TEXT, "query" TEXT, "query_type", "counter" INTEGER, "action" TEXT, "last_seen" TEXT, "domain_id" TEXT)'
DB_T_NETWORKS = "networks"
DB_SCHEMA_T_NETWORKS = f'CREATE TABLE "{DB_T_NETWORKS}" ("id" TEXT, "ip" TEXT,"type" TEXT, "action" TEXT,"created" TEXT)'
DB_T_HOSTS = "hosts"
DB_SCHEMA_T_HOSTS = f'CREATE TABLE "{DB_T_HOSTS}" ("ip" TEXT, "scope_id" TEXT, "name" TEXT)'

DB_ID_SALT = 'This is not for security, it is for uniqueness'
DB_SCHEMA = [
    (DB_T_DOMAINS, DB_SCHEMA_T_DOMAINS),
    (DB_T_NETWORKS, DB_SCHEMA_T_NETWORKS),
    (DB_T_QUERIES, DB_SCHEMA_T_QUERIES),
    (DB_T_HOSTS, DB_SCHEMA_T_HOSTS)
]

# Initial Config vars.
if os.path.exists("/share/"):
    CONFIG_DB_PATH = "/share/"
else:
    CONFIG_DB_PATH = "./"               # Make config option

CONFIG_DB_NAME = "dns.db"        # Later, this should be user config

# CLasses & Functions...
class DNSInterceptor(BaseResolver):

    def __init__(self,upstream:list,timeout:float=5, dnsi_logger:logging=logging, local_ips:list=None):
        self.log = dnsi_logger

        self.resolvers = self.__loadResolvers(upstream)
        self.local_ips = local_ips
        self.local_networks = []
        self.known_hosts = []

        self.resolver_timeout = timeout/2   # We're making 2x DNS lookups for each request
        if self.resolver_timeout == 0:      # So make our timeout half
            self.resolver_timeout = 1       # Add one, just in case rounding ends up a zero.

        self.sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}", check_same_thread=False)
        self.sql_cursor = self.sql_connection.cursor()

        if len(self.local_networks) == 0: # Process the HA Config
            self.__loadnetworks()
            self.log.info('%s/%s local scopes loaded.', len(self.local_networks), len(self.local_ips))

    def __loadResolvers(self, resolvers:list):
        """
            Convert Messy List into List with Dicts
        """
        upstream_servers = []

        for r in resolvers:
            rs = r.split(':')
            rhost = rs[0]
            try:
                rport = int(rs[1])
            except (IndexError, ValueError):
                rport = 53
            upstream_servers.append({'ip':rhost, 'port':rport})

        self.log.debug('Resolvers -> %s', str(upstream_servers))
        return upstream_servers

    def getscope(self, scope_type, scope_ip):
        """
            Create netaddr scope object from Type/IP

            scope_type:str  -> host | network | range
            scope_ip:str    -> 192.168.0.1 | 192.168.1.0/24 | 192.168.2.1-192.168.2.2
        """
        scope = netaddr.IPSet() # <- Empty IP Set

        if scope_type == 'host':
            self.log.debug('%s is Host', scope_ip)
            scope = netaddr.IPSet([netaddr.IPAddress(scope_ip)])
        elif scope_type == 'network':
            self.log.debug('%s is Network', scope_ip)
            scope = netaddr.IPSet([netaddr.IPNetwork(scope_ip)])
        elif scope_type == 'range':
            self.log.debug('%s is Range', scope_ip)
            ip_range = str(scope_ip).strip().split('-')
            try:
                scope = netaddr.IPSet([netaddr.IPRange(ip_range[0], ip_range[1])])
            except Exception:
                self.log.error("Problem Reading Range -> %s", scope_ip)
                self.log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])

        else:
            self.log.critical('Unknown Scope type in DB -> {u}', u=scope_type)
        return scope

    def __loadnetworks(self):
        """
            Populate self.networks from HomeAssistant and SQL DB
        """
        for ha_config in self.local_ips:
            scope_config = str(ha_config).split(':')

            try:
                scope_type = scope_config[1]
            except IndexError:
                self.log.warning('[ASSUMING HOST] - No IP Type (Host/Network/Range) set for %s', str(ha_config))
                scope_type = 'host'

            if re.match(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', str(scope_config[0]).strip()):
                scope_ip = str(scope_config[0]).strip()
            else:
                self.log.warning('🚨 Skipping, %s is not an IPv4 Address 🚨', str(scope_config[0]).strip())
                continue

            scope = self.getscope(scope_type, scope_ip)
            scope_id = self.createID([scope_type, scope_ip])

            try:
                sql_rows = self.sql_cursor.execute(f'SELECT "id", "action", "created" FROM "{DB_T_NETWORKS}" WHERE id = ?', (scope_id,)).fetchall()
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

            if len(sql_rows) == 0:
                created = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')
                action = "learn"
                params = (
                    scope_id,
                    scope_ip,
                    scope_type,
                    action,
                    created,
                )
                self.log.debug(str(params))
                try:
                    self.sql_cursor.execute(                       # Create a new Row
                        f'INSERT INTO "{DB_T_NETWORKS}" ("id", "ip", "type", "action", "created") VALUES (?, ?, ?, ?, ?)',
                        params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            else:
                action = sql_rows[0][1]
                created = datetime.datetime.fromisoformat(sql_rows[0][2])
                now = datetime.datetime.now(datetime.UTC)
                delta = now - created
                self.log.debug('ID: %s | Action: %s | Created: %s | %s days old', sql_rows[0], action, created, delta.days)

                if delta.days >= LEARNING_DURATION and (action != "block"):
                    action = "block"
                    self.log.warning('🔥🔥 Learning Mode over for Scope %s Setting to detect new domains 🔥🔥', scope_id)
                    try:
                        self.sql_cursor.execute(   # Update the existing Row
                            f'UPDATE "{DB_T_NETWORKS}" SET "action" = ?, WHERE "id" = ?', (action, scope_id)
                        )
                    except Exception:
                        self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

            self.local_networks.append({'id': scope_id, 'scope':scope, 'action': action})

    def sqlKnownHosts(self, source_ip:str=None, scope_id:str=None):
        """
            Record Source IPs with their Scope ID so we can give them friendlt names later :)
        """

        try:
            sql_rows = self.sql_cursor.execute(f'SELECT "name" FROM "{DB_T_HOSTS}" WHERE ip = ?', (source_ip,)).fetchall()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

        if len(sql_rows) == 0:
            self.log.debug('Saving %s linked to %s', source_ip, scope_id)
            try:
                self.sql_cursor.execute(
                    f'INSERT INTO "{DB_T_HOSTS}" ("ip", "scope_id" ) VALUES (?, ?)', (source_ip, scope_id)
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
        else:
            self.log.debug('%s is known as %s', source_ip, str(sql_rows[0][0]))

        self.known_hosts.append(source_ip)


    def learningMode(self, source_ip):
        """
            Check if Source IP is in Learning More or Not

            # False => Block
            # True => Pass

        """
        self.log.debug("Source IP -> %s", source_ip)

        if len(self.local_networks) > 0:
            for scope in self.local_networks:
                if source_ip in scope['scope']:
                    learning_mode = bool(scope['action'] == 'learn')
                    self.log.debug("Source IP -> %s (%s) -> %s (%s)", source_ip, scope['id'], scope['action'], str(learning_mode))

                    if source_ip not in self.known_hosts:
                        self.sqlKnownHosts(source_ip, scope['id'])
                    return learning_mode, scope['id']

        self.log.debug("Source IP -> %s -> Uknown IP Action: %s", source_ip, UKNOWN_IP_PASS)
        return UKNOWN_IP_PASS, None

    def passThePacket(self, action:str):
        """
            ## Make a decision.
            ### Input
            1. action/block => False
            2. action/else (pass) => True
            ### Return
            # Bool

        """
        self.log.debug("SQL -> %s", action)
        if action == "block":
            return False

        return True

    def createID(self, input_array:list=None, some_salt:str=DB_ID_SALT):
        """
            ## Generate an "ID", well basically a hash, from a list
            ### Input:
            *   `input_array`: A list of things to mash together
            *   `some_salt`: This ensures that values are unique to this code
            ### Return:
            * `String`
        """
        if not isinstance(input_array, list):
            self.log.warning("Input is not a list %s", str(input_array))
            return "ERROR: Input not list"
        # https://www.pythoncentral.io/hashing-strings-with-python/
        hash_object = hashlib.sha256(some_salt.join(input_array).encode())
        hex_dig = hash_object.hexdigest()
        return str(hex_dig)

    def findSQLQueryID(self, query_id:str=None, learning_mode:bool=True):
        """
            ## Find the SQL Row ID for a query
            ### Input:
            * `query_id`: The Hash we're looking for...
            * `learning_mode` : True/False
            ### Return:
            * `tuple` (id:str=None, counter:int, sql_action:str)
        """
        sql_id = None
        sql_counter = 0
        domain_id = None

        if learning_mode:
            sql_action = 'pass'
        else:
            sql_action = 'block'

        try:
            sql_rows = self.sql_cursor.execute(f'SELECT "id", "counter", "action", "domain_id" FROM "{DB_T_QUERIES}" WHERE id = ?', (query_id,)).fetchall()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            return sql_id, sql_counter, sql_action, domain_id

        if len(sql_rows) == 0:
            return sql_id, sql_counter, sql_action, domain_id

        for row in sql_rows:
            if row[0] == query_id:
                sql_id = query_id
                sql_counter = int(row[1])
                sql_action = str(row[2]).strip()
                domain_id = str(row[3]).strip()
                self.log.debug('ROW: %s', str(row))

        self.log.debug('ID: %s => %s (%s)', sql_id, sql_action, sql_counter )
        return sql_id, sql_counter, sql_action, domain_id

    def sqlDNSquery(self, sql_data:list):
        """
            ## Update the SQL DNS for DNS Queries
            ### Input:
            * sql_data = List of things to do, with dicts inside!
            ### Return:
            * `tuple` (id:str=None, action:str='pass')
        """
        sql_id = None     # < Defaults for return later...
        sql_action = 'pass'

        for x in sql_data:
            if x['result'] is None and (x['action'] in ["pass" , "block"]):
                params = (
                            x['id'],
                            x['src'],
                            x['src_type'],
                            x['query'],
                            x['query_type'],
                            x['counter'],
                            x['action'],
                            x['last_seen'],
                            x['domain_id']
                        )
                self.log.debug(str(params))
                try:
                    self.sql_cursor.execute(
                        f'INSERT INTO "{DB_T_QUERIES}" ("id", "src", "src_type", "query", "query_type", "counter", "action", "last_seen", "domain_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            elif x['result'] is not None:
                x['counter'] +=1                     # Increment the counter
                params = (
                    x['counter'],
                    x['last_seen'],
                    x['id'],
                    )
                self.log.debug(str(params))
                try:
                    self.sql_cursor.execute(   # Update the existing Row
                        f'UPDATE "{DB_T_QUERIES}" SET "counter" = ?, "last_seen" = ? WHERE "id" = ?', params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

            try:
                self.sql_connection.commit()
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

            if x['src_type'] == "scope":
                sql_id = x['id']
                sql_action = x['action']

        return sql_id, sql_action

    def findDNSQuery(self, query_name:str=None, query_type:str=None, source_ip:str=None, scope_id:str=None, learning_mode:bool=True):
        """
            ## Find the SQL Row ID for a domain/ip pair
            ### Input:
            * `query_name`: DNS Query
            * `query_type`: DNS Query Type
            * `source_ip`: IP that made the request
            * `scope_id` : ID Assocaited with source_ip
            * `learning_mode` : True/False
            ### Return:
            * `tuple` (id:str=None, action:str='pass')
        """
        host_query_id = self.createID([source_ip, 'host', query_name, query_type])
        self.log.debug('[HOST] => SQLID: %s | Src IP: %s | Qname: %s | Qtype: %s', host_query_id, source_ip, query_name, query_type )
        r_host_query_id, host_counter, host_action, host_domain_id = self.findSQLQueryID(host_query_id, learning_mode)
        self.log.debug('[HOST] => SQL ID: %s | Counter: %s | Action: %s', r_host_query_id, host_counter, host_action)

        scope_query_id = self.createID([scope_id, 'scope', query_name, query_type])
        self.log.debug('[SCOPE] => SQLID: %s | Scope: %s | Qname: %s | Qtype: %s', scope_query_id, scope_id, query_name, query_type )
        r_scope_query_id, scope_counter, scope_sction, query_domain_id = self.findSQLQueryID(scope_query_id, learning_mode)
        self.log.debug('[SCOPE] => SQL ID: %s | Counter: %s | Action: %s', r_scope_query_id, scope_counter, scope_sction)

        last_seen = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')

        sql_things_to_do = [
            {'result': r_host_query_id, 'id': host_query_id, 'counter': host_counter, 'action': host_action, 'src_type':'host', 'src':source_ip, 'query':query_name, 'query_type':query_type, 'last_seen':last_seen, 'domain_id': host_domain_id},
            {'result': r_scope_query_id, 'id': scope_query_id, 'counter': scope_counter, 'action': scope_sction, 'src_type':'scope', 'src':scope_id, 'query':query_name, 'query_type':query_type, 'last_seen':last_seen, 'domain_id': query_domain_id},
        ]

        sql_id, sql_action = self.sqlDNSquery(sql_things_to_do)
        return sql_id, sql_action

    def findSQLDomainID(self, domain:str=None, scope_id:str=None, sql_action:str=None, learning_mode:bool=True):
        """
            ## Find the SQL Row ID for a domain/ip pair
            ### Input:
            * `domain`: Domain returned from SOA lookup
            * `source_ip`: IP that made the request
            * `sql_action` : 'block' or 'pass'
            * `learning_mode` : True/False
            ### Return:
            * `tuple` (id:str=None, counter:int)
        """
        sql_id = None
        sql_counter = 0

        try:
            sql_rows = self.sql_cursor.execute(f'SELECT "scope", "id", "counter", "action" FROM "{DB_T_DOMAINS}" WHERE domain = ? AND scope = ?', (domain,scope_id,)).fetchall()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            return sql_id, sql_counter, sql_action

        if len(sql_rows) == 0:
            if learning_mode:
                sql_action = 'pass'
            else:
                sql_action = 'block'
            return sql_id, sql_counter, sql_action

        for row in sql_rows:
            if row[0] == scope_id:
                sql_id = str(row[1]).strip()
                sql_counter = int(row[2])
                sql_action = str(row[3]).strip()
                self.log.debug('ROW: %s', str(row))

        self.log.debug('🌍 For %s & Scope %s => ID: %s (%s/%s)', domain, scope_id, sql_id, sql_counter, sql_action)
        return sql_id, sql_counter, sql_action

    def sqlDomains(self, domain:str=None, scope_id:str=None, action:str=None, learning_mode:bool=True):
        """
            ## Update the SQL DB
            ### Input:
            * domain => Thing we are recording
            * source_ip => From where
            ### Return:
            * tuple( sql_action:str, sql_id:str )
        """
        self.log.debug('Domain: %s | Scope: %s | Action: %s', domain, scope_id, action)
        last_seen = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')
        sql_id, sql_counter, sql_action = self.findSQLDomainID(scope_id=scope_id, domain=domain, sql_action=action, learning_mode=learning_mode)
        self.log.debug('SQL ID: %s | Counter: %s | Action: %s', sql_id, sql_counter, action)
        if sql_id is None and (sql_action in ["pass" , "block"]):
            sql_id = self.createID([domain, scope_id])    # Create a new ID
            params = (
                        sql_id,
                        domain,
                        sql_counter,
                        scope_id,
                        sql_action,
                        last_seen,
                    )
            self.log.debug(str(params))
            try:
                self.sql_cursor.execute(                       # Create a new Row
                    f'INSERT INTO "{DB_T_DOMAINS}" ("id", "domain", "counter", "scope", "action", "last_seen") VALUES (?, ?, ?, ?, ?, ?)',
                    params
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
        elif sql_id is not None:
            sql_counter +=1                     # Increment the counter
            params = (
                  sql_counter,
                  last_seen,
                  sql_id,
                )
            self.log.debug(str(params))
            try:
                self.sql_cursor.execute(   # Update the existing Row
                    f'UPDATE "{DB_T_DOMAINS}" SET "counter" = ?, "last_seen" = ? WHERE "id" = ?', params
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

        try:
            self.sql_connection.commit()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

        return sql_action, sql_id

    def linkSQLs(self, source_ip:str=None, scope_id:str=None, query_name:str=None, query_type:str=None, the_domain_id:str=None):
        """
            Link a Query to a Domain
        """
        self.log.debug('%s (%s) -> %s (%s) => %s', source_ip, scope_id, query_name, query_type, the_domain_id)
        the_ids = [
            self.createID([source_ip, 'host', query_name, query_type]),
            self.createID([scope_id, 'scope', query_name, query_type])
        ]

        for sql_id in the_ids:
            self.log.debug('Updating %s with %s', sql_id, the_domain_id)
            try:
                self.sql_cursor.execute(   # Update the existing Row
                    f'UPDATE "{DB_T_QUERIES}" SET "domain_id" = ? WHERE "id" = ?', (the_domain_id, sql_id)
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

            try:
                self.sql_connection.commit()
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

    def sendSOArequest(self, soa_query:DNSRecord, index:int=0, tcp:bool=False):
        """
            ## Send a SOA DNS Request to resolver
            ### Input:
            * soa_query => Pre-formarred SOA DNS Record
            * index => Resolver Index, 0, 1 or more
            * tcp => send TCP or UDP request upstream?
            ### Return:
            * DNS Packet
        """
        a_pkt = None
        self.log.debug("SOA -> %s (Resolver: %s | Timout:%s | TCP: %s)",str(self.resolvers[index]), index, self.resolver_timeout, str(tcp))
        try:
            a_pkt = soa_query.send(self.resolvers[index]['ip'],self.resolvers[index]['port'],tcp=tcp, timeout=self.resolver_timeout)
        except TimeoutError:
            self.log.error("SOA/TIMEOUT -> %s (Resolver: %s | Timout:%s)",str(self.resolvers[index]), index, self.resolver_timeout)
            self.log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        except Exception:
            self.log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])

        return a_pkt

    def findDomain(self, domain_query:str, scope_id:str, learning_mode:bool):
        """
            ## From the query, send a new DNS Request (SOA) to find the domain name of the host/domainname.
            REF: https://github.com/paulc/dnslib/blob/master/dnslib/client.py
            ### Input:
            * domainname => Host or Domainname to find the authorative domain
            ### Return:
            * the domain:str ... or None for failed.
        """

        result = None
        result_id = None
        result_action = SOA_FAIL_ACTION

        q = DNSRecord(q=DNSQuestion(domain_query,getattr(QTYPE,'SOA')))

        counter=0
        while counter < len(self.resolvers):
            a_pkt = self.sendSOArequest(q,counter)
            if a_pkt is None:
                counter+=1
            else:
                break

        try:
            a = DNSRecord.parse(a_pkt)

            if q.header.id != a.header.id:
                raise DNSError('Response transaction id does not match query transaction id')

            if a.header.tc == False:    # Truncated - retry in TCP mode
                self.log.debug('Retrying in TCP...')
                a_pkt = self.sendSOArequest(q,counter,tcp=True)
                a = DNSRecord.parse(a_pkt)

            self.log.debug("SHORT --> %s", a.short)
            self.log.debug("LONG --> %s", a)
            self.log.debug('RR: -----> %s', len(a.rr))
            try:
                result = str(a.auth[0].get_rname())
                self.log.debug("AUTHY >--> %s", a.auth)
            except IndexError:
                self.log.debug("AUTHY >=> %s", a.auth)
                for ab in a.rr:
                    if QTYPE[ab.rtype] == 'SOA':
                        self.log.debug(ab.rname)
                        self.log.debug(QTYPE[ab.rtype])
                        result = str(ab.rname)

            self.log.debug("🥰 Found Domain -> %s ", result)
        except DNSError:
            self.log.error("DNSERROR Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        except Exception:
            self.log.error("General Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])

        if result is not None:
            result_action, result_id = self.sqlDomains(domain=result,scope_id=scope_id,learning_mode=learning_mode)
        return result, result_action, result_id

    def resolve(self,request,handler):
        """
            Hook into the DNS Resolve request from the client.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        src_ip = handler.client_address[0]

        learning_mode, scope_id = self.learningMode(src_ip)

        if scope_id is None and learning_mode: # Uknown IP Ignore
            self.log.info("%s -> %s [Type: %s]", src_ip, qname, qtype)
            log_qu = ""
            log_ans = ""
        elif scope_id is None and not learning_mode: # Uknonw IP Block
            self.log.info("⛔️⛔️ DNS BLOCKED %s for Uknown IP %s ⛔️⛔️", qname, src_ip)
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')
            return reply
        else:
            self.log.info("✨ %s -> %s [Type: %s]", src_ip, qname, qtype)
            log_qu = "❓"   # Add icons for things in learning Mode... (Question)
            log_ans = "✅"  # (Answer)

            the_query_id, the_query_action = self.findDNSQuery(str(qname), str(qtype), str(src_ip), scope_id, learning_mode)
            self.log.debug('Query => %s [%s]', the_query_id, the_query_action)

            the_domain, the_domain_action, the_domain_id = self.findDomain(qname, scope_id, learning_mode)
            if the_domain is None:
                self.log.error('😫 Failed to lookup domain for %s', qname)
            else:
                self.linkSQLs(str(src_ip), scope_id, str(qname), str(qtype), the_domain_id)

            if not self.passThePacket(the_domain_action):
                self.log.warning("🔥 New Authority DOMAIN %s Detected for Request %s 🔥", the_domain, qname)
                if the_domain_id is None:
                    self.sqlDomains(the_domain,scope_id,'block')
                if DNS_FIREWALL_ON:
                    self.log.info("🔥🔥 DOMAIN BLOCKED %s 🔥🔥", the_domain)
                    reply.header.rcode = getattr(RCODE,'NXDOMAIN')
                    return reply

            if DNS_DETECT_ON_HOST and not self.passThePacket(the_query_action):
                self.log.warning("🔥 New QUERY %s Detected for %s (%s) 🔥", qname, src_ip, scope_id)
                if DNS_FIREWALL_ON:
                    self.log.info("🔥🔥 QUERY BLOCKED %s 🔥🔥", the_domain)
                    reply.header.rcode = getattr(RCODE,'NXDOMAIN')
                    return reply

        resolver_counter = 0
        resolver_reply = False
        while (resolver_counter < len(self.resolvers)):
            self.log.debug("%s %s -> %s", log_qu, qname, str(self.resolvers[resolver_counter]))
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.resolvers[resolver_counter]['ip'],self.resolvers[resolver_counter]['port'],timeout=self.resolver_timeout)
                else:
                    proxy_r = request.send(self.resolvers[resolver_counter]['ip'],self.resolvers[resolver_counter]['port'],timeout=self.resolver_timeout,tcp=True)
                reply = DNSRecord.parse(proxy_r)
                resolver_reply = True
            except socket.timeout:
                reply.header.rcode = getattr(RCODE,'SERVFAIL')
                self.log.error('TIMEOUT %s -> %s', str(self.resolvers[resolver_counter]), qname)

            if resolver_reply:
                self.log.debug('%s [%s]: %s', log_ans, str(self.resolvers[resolver_counter]), str(reply.rr))
                return reply
            resolver_counter+=1

        return reply

def bootstrap(log:logging=logging):
    """
        ## Let's get ready to rumble!
        ### Input
        * log ==> Logging object
        ### Return
        * bool ==> True is Ready.
    """
    status = True
    try:
        connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}")
    except Exception:
        log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        status = False
    else:
        log.info('Connected to SQLite DB %s/%s', CONFIG_DB_PATH, CONFIG_DB_NAME)

    for table in DB_SCHEMA:
        try:
            connection.execute(table[1])
        except sqlite3.OperationalError:
            if re.search(f"table \"{table[0]}\" already exists", str(sys.exc_info()[1]), re.IGNORECASE):
                log.debug('DB Schema - Nothing to do')
                status = True
            else:
                log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
                status = False
        except Exception:
            log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
            status = False
        else:
            log.info('DB %s SCHEMA Created', table[0])

    connection.commit()
    connection.close() # Ok, all good, it's close.
    return status

def readResolveConf(resolvers, log:logging=logging):
    """
        Try to get DNS servers from resolve.conf
        Fall back to google+cloudflare.
    """

    try:
        with open("/etc/resolv.conf", encoding='utf-8') as resolvconf:
            for line in resolvconf.readlines():
                ns = re.search(r'^[\s]*nameserver\s((?:[0-9]{1,3}\.){3}[0-9]{1,3})', str(line).strip(), re.IGNORECASE)
                log.debug("Searching resolve.conf (%s)", ns)
                if ns and ns[1] is not None:
                    resolvers.append(str(ns[1]))
    except Exception:
        log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])

    return resolvers


def getResolvers(log:logging=logging):
    """
        Get Resolvers from HomeAssistant or Local
    """
    resolvers = []

    if len(UPSTREAM_RESOLVERS) == 0:
        resolvers = readResolveConf(resolvers, log)
    else:
        for r in UPSTREAM_RESOLVERS:
            if re.match(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', r):
                resolvers.append(r)
            else:
                log.warning('🚨 Skipping, %s is not an IPv4 Address 🚨', r)

    if len(resolvers) == 0:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    log.info('Using Resolvers -> %s', str(resolvers))
    return resolvers

def main(dnsi_logger):
    """
    Run the server - https://github.com/paulc/dnslib/blob/master/dnslib/intercept.py
    """
    resolver = DNSInterceptor(
        upstream=getResolvers(log=dnsi_logger),
        dnsi_logger=dnsi_logger,
        local_ips=LOCAL_NETWORKS
        )

    if DEBUG_MODE:
        LOG_HOOKS = "request,reply,truncated,error"
    else:
        LOG_HOOKS = "truncated,error"

    LOG_PREFIX = True
    dns_logger = DNSLogger(LOG_HOOKS,LOG_PREFIX)

    udp_server = DNSServer(resolver,
                        address="",
                        port=10053,
                        logger=dns_logger)
    udp_server.start_thread()

    tcp_server = DNSServer(resolver,
                        address="",
                        port=10053,
                        logger=dns_logger,
                        tcp=True)
    tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

if __name__ == "__main__":
    main_logger = logging.getLogger("DNSInterceptor")
    main_logger.addHandler(log_handler)
    if DEBUG_MODE:
        main_logger.setLevel(logging.DEBUG)
    else:
        main_logger.setLevel(logging.INFO)

    if not bootstrap(main_logger):
        main_logger.critical('bootstrap failed, exiting...')
        sys.exit(1)

    main(main_logger)
