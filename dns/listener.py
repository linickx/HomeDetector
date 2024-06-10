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
import traceback
import threading
from multiprocessing import Process

logger = logging.getLogger("HomeAssistant")
log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s:%(funcName)s] %(levelname)s: %(message)s ', datefmt="%Y-%m-%d %H:%M:%S")) # (%(thread)d %(threadName)s)
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

try:
    from dnslib.dns import DNSError, DNSQuestion, RR, A
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

try:
    import requests
except ModuleNotFoundError:
    logger.error('requests not Installed - try pip install requests')
    WEBHOOKER = False
else:
    WEBHOOKER = True

# Some Configurable Options
try:
    with open('/data/options.json', "r", encoding="utf8") as file:
        options_f = file.read()
except Exception:
    logger.info('🚨🚨 Unable to -> FIND <- Home Assistant Options, will use DEFAULTS 🚨🚨')
else:
    try:
        OPTIONS_DATA = json.loads(options_f)
    except Exception:
        logger.error('🚨🚨 Unable to ==> LOAD <== Home Assistant Options, will use DEFAULTS 🚨🚨')
        logger.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        OPTIONS_DATA = {}

DEBUG_MODE = True      # Default => INFO
try:
    DEBUG_MODE = bool(OPTIONS_DATA['debug'])
except Exception:
    pass
finally:
    logger.info('🫥  debug => %s', DEBUG_MODE)
    if DEBUG_MODE:
        logger.setLevel(logging.DEBUG)

UKNOWN_IP_PASS = True # Should default IPs learn? (True => Yes, False => Block)
try:
    if OPTIONS_DATA['unknown_ip_action'] in ['ignore', 'block']:
        if OPTIONS_DATA['unknown_ip_action'] == 'ignore':
            UKNOWN_IP_PASS = True
        if OPTIONS_DATA['unknown_ip_action'] == 'block':
            UKNOWN_IP_PASS = False
except Exception:
    pass
logger.info('🫥  unknown_ip_action => %s',  UKNOWN_IP_PASS)

SOA_FAIL_ACTION = "ignore" # what to do if SOA lookup fails.
try:
    if OPTIONS_DATA['soa_failure_action'] in ['ignore', 'block']:
        SOA_FAIL_ACTION = OPTIONS_DATA['soa_failure_action']
except Exception:
    pass
finally:
    logger.debug('🫥  soa_failure_action => %s',  SOA_FAIL_ACTION)

DNS_DETECT_ON_HOST = False      # Default => Detect on Domain (SOA) Changes
try:
    DNS_DETECT_ON_HOST = bool(OPTIONS_DATA['detect_on_host_query'])
except Exception:
    pass
finally:
    logger.info('🫥  detect_on_host_query => %s', DNS_DETECT_ON_HOST)

DNS_FIREWALL_ON = False      # Default => notify (detect) mode only
try:
    DNS_FIREWALL_ON = bool(OPTIONS_DATA['dns_blocking_mode'])
except Exception:
    pass
finally:
    logger.info('🫥  dns_blocking_mode => %s', DNS_FIREWALL_ON)

LOCAL_NETWORKS = [] # LAN / IoT Network
try:
    LOCAL_NETWORKS = OPTIONS_DATA['networks']
except Exception:
    LOCAL_NETWORKS.append({'address':'127.0.0.1', 'type':'host'}) # Local Host for Testing :)
finally:
    logger.debug('🫥  Loading Networks => %s', str(LOCAL_NETWORKS))

LOCAL_NETWORKS_TTL = 3600
try:
    LOCAL_NETWORKS_TTL = int(OPTIONS_DATA['networks_ttl'])
except Exception:
    pass
finally:
    logger.debug('🫥  networks_ttl => %s seconds', str(LOCAL_NETWORKS_TTL))

LEARNING_DURATION = 30
try:
    LEARNING_DURATION = int(OPTIONS_DATA['learning_duration'])
except Exception:
    pass
finally:
    logger.info('🫥  learning_duration => %s days', str(LEARNING_DURATION))

UPSTREAM_RESOLVERS = [] # DNS Servers
try:
    UPSTREAM_RESOLVERS = OPTIONS_DATA['resolvers']
except Exception:
    pass
finally:
    logger.debug('🫥  Custom Resolvers => %s', str(UPSTREAM_RESOLVERS))

FAKE_A_RECORDS = {} # Custom A Record DNS replies
try:
    custom_host_records = OPTIONS_DATA['custom_host_records']
except Exception:
    custom_host_records = []
if len(custom_host_records) > 0:
    for host_record in custom_host_records:
        try:
            FAKE_A_RECORDS[host_record['name']] = host_record['address']
        except Exception:
            logger.error('Failed to Setup Custom Host %s', str(host_record))

    logger.info('🫥  %s Custom Hosts Loaded', len(FAKE_A_RECORDS))
    logger.debug('Custom Host Records -> %s', str(FAKE_A_RECORDS))

# Some Internal VARS
DB_T_DOMAINS = "domains"
DB_SCHEMA_T_DOMAINS = f'CREATE TABLE "{DB_T_DOMAINS}" ("id" TEXT, "domain" TEXT, "counter" INTEGER,"scope" TEXT, "action" TEXT,"last_seen" TEXT)'
DB_T_QUERIES = "queries"
DB_SCHEMA_T_QUERIES = f'CREATE TABLE "{DB_T_QUERIES}" ("id" TEXT, "src" TEXT,"scope_id" TEXT, "query" TEXT, "query_type", "counter" INTEGER, "action" TEXT, "last_seen" TEXT, "domain_id" TEXT)'
DB_T_NETWORKS = "networks"
DB_SCHEMA_T_NETWORKS = f'CREATE TABLE "{DB_T_NETWORKS}" ("id" TEXT, "ip" TEXT,"type" TEXT, "action" TEXT,"created" TEXT, "name" TEXT)'
DB_T_HOSTS = "hosts"
DB_SCHEMA_T_HOSTS = f'CREATE TABLE "{DB_T_HOSTS}" ("id" TEXT, "ip" TEXT, "scope_id" TEXT, "name" TEXT)'

DB_ID_SALT = 'This is not for security, it is for uniqueness'
DB_SCHEMA = [
    (DB_T_DOMAINS, DB_SCHEMA_T_DOMAINS),
    (DB_T_NETWORKS, DB_SCHEMA_T_NETWORKS),
    (DB_T_QUERIES, DB_SCHEMA_T_QUERIES),
    (DB_T_HOSTS, DB_SCHEMA_T_HOSTS)
]

# Initial Config vars.
if os.path.exists("/share/"):           # <- Should be addon_configs .
    CONFIG_DB_PATH = "/share/"
else:
    CONFIG_DB_PATH = "./"               # Make config option

CONFIG_DB_NAME = "hd.db"        # Later, this should be user config

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

        self.lock = threading.Lock()
        self.sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}", check_same_thread=False)

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
            scope_address = str(ha_config['address']).strip()

            try:
                scope_type = str(ha_config['type']).strip()
            except KeyError:
                self.log.warning('[ASSUMING HOST] - No IP Type (Host/Network/Range) set for %s', str(ha_config))
                scope_type = 'host'

            if re.match(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', scope_address):
                scope_ip = scope_address
            else:
                self.log.warning('🚨 Skipping, %s is not an IPv4 Address 🚨', scope_address)
                continue

            scope = self.getscope(scope_type, scope_ip)
            scope_id = self.createID([scope_type, scope_ip])

            with self.lock:
                sql_cursor = self.sql_connection.cursor()
                try:
                    sql_rows = sql_cursor.execute(f'SELECT "id", "action", "created" FROM "{DB_T_NETWORKS}" WHERE id = ?', (scope_id,)).fetchall()
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())
                sql_cursor.close()

            if len(sql_rows) == 0:
                created = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')
                ttl = datetime.datetime.now(datetime.UTC)
                action = "learn"
                params = (
                    scope_id,
                    scope_ip,
                    scope_type,
                    action,
                    created,
                )
                self.log.debug(str(params))
                with self.lock:
                    sql_cursor = self.sql_connection.cursor()
                    try:
                        sql_cursor.execute(                       # Create a new Row
                            f'INSERT INTO "{DB_T_NETWORKS}" ("id", "ip", "type", "action", "created") VALUES (?, ?, ?, ?, ?)',
                            params
                        )
                    except Exception:
                        self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                        self.log.error(traceback.format_exc())
                    self.sql_connection.commit()
                    sql_cursor.close()
            else:
                action = sql_rows[0][1]
                created = datetime.datetime.fromisoformat(sql_rows[0][2])
                action, ttl = self.learningModeReValidation(scope_id,action, created)

            self.local_networks.append({'id': scope_id, 'scope':scope, 'action': action, 'created':created, 'ttl':ttl})

    def learningModeReValidation(self, scope_id, current_action, created, ttl=None):
        """
            Periodically ReValidate the status of a Network Against the DB/
        """
        action = current_action
        now = datetime.datetime.now(datetime.UTC)

        if isinstance(created, str): # Did this come from the DB or Python 🤷🏻‍♂️
            created = datetime.datetime.fromisoformat(created)

        delta = now - created
        self.log.debug('ID: %s | Action: %s | Created: %s | %s days old | TTL: %s', scope_id, current_action, created, delta.days, str(ttl))

        # See if the Learning Duration has expired
        if delta.days >= LEARNING_DURATION and (current_action != "block"):
            action = "block"
            self.log.warning('🔥🔥 Learning Mode over for Scope %s Setting to detect new domains 🔥🔥', scope_id)
            with self.lock:
                sql_cursor = self.sql_connection.cursor()
                try:
                    sql_cursor.execute(   # Update the existing Row
                        f'UPDATE "{DB_T_NETWORKS}" SET "action" = ?, WHERE "id" = ?', (action, scope_id)
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())
                sql_cursor.close()

        if ttl is None:
            ttl = now
            return action, ttl  # Exit early as this is a load.

        # See if the perodic refresh has kicked in?
        delta_force = now - ttl
        if delta_force.seconds >= LOCAL_NETWORKS_TTL:
            self.log.debug('ID %s | TTL Expired -> %s', scope_id, delta_force.seconds)
            with self.lock:
                sql_cursor = self.sql_connection.cursor()
                try:
                    sql_rows = sql_cursor.execute(f'SELECT "action" FROM "{DB_T_NETWORKS}" WHERE id = ?', (scope_id,)).fetchall()
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())
                sql_cursor.close()

            if len(sql_rows) > 0:
                action = sql_rows[0][0]
            ttl = now
        else:
            ttl = None # Returning no TTL as it doesn't need to change

        if action != current_action:
            self.log.warning('SCOPE ID %s has been updated from %s to %s', scope_id, current_action, action)
        return action, ttl

    def sqlKnownHosts(self, source_ip:str=None, scope_id:str=None):
        """
            Record Source IPs with their Scope ID so we can give them friendlt names later :)
        """

        with self.lock:
            sql_cursor = self.sql_connection.cursor()
            try:
                sql_rows = sql_cursor.execute(f'SELECT "name" FROM "{DB_T_HOSTS}" WHERE ip = ?', (source_ip,)).fetchall()
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                self.log.error(traceback.format_exc())

        if len(sql_rows) == 0:
            source_id = self.createID([source_ip])
            self.log.debug('Saving %s linked to %s', source_ip, scope_id)
            with self.lock:
                try:
                    sql_cursor.execute(
                        f'INSERT INTO "{DB_T_HOSTS}" ("id", "ip", "scope_id" ) VALUES (?, ?, ?)', (source_id, source_ip, scope_id)
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())
        else:
            self.log.debug('%s is known as %s', source_ip, str(sql_rows[0][0]))

        self.known_hosts.append(source_ip)
        sql_cursor.close()


    def learningMode(self, source_ip):
        """
            Check if Source IP is in Learning More or Not

            # False => Block
            # True => Pass

        """
        self.log.debug("Source IP -> %s", source_ip)
        counter = 0

        if len(self.local_networks) > 0:
            for scope in self.local_networks:
                if source_ip in scope['scope']:
                    action,ttl = self.learningModeReValidation(scope['id'], scope['action'], scope['created'], scope['ttl'])
                    learning_mode = bool(action == 'learn')
                    self.log.debug("Source IP -> %s (%s) -> %s (%s) [TTL: %s]", source_ip, scope['id'], scope['action'], str(learning_mode), ttl)
                    if ttl is not None:
                        self.log.debug('Scope %s replacing TTL %s -> %s', scope['id'], str(scope['ttl']), str(ttl))
                        del self.local_networks[counter]    # Delete & replace list entry... to update TTL
                        self.local_networks.append({'id': scope['id'], 'scope':scope['scope'], 'action': scope['action'], 'created':scope['created'], 'ttl':ttl})

                    if source_ip not in self.known_hosts:
                        self.sqlKnownHosts(source_ip, scope['id'])
                    return learning_mode, scope['id']
                counter+=1

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
        sql_counter = 1
        domain_id = None

        if learning_mode:
            sql_action = 'pass'
        else:
            sql_action = 'block'

        with self.lock:
            sql_cursor = self.sql_connection.cursor()
            try:
                sql_rows = sql_cursor.execute(f'SELECT "id", "counter", "action", "domain_id" FROM "{DB_T_QUERIES}" WHERE id = ?', (query_id,)).fetchall()
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                self.log.error(traceback.format_exc())
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

        sql_cursor.close()
        self.log.debug('ID: %s => %s (%s)', sql_id, sql_action, sql_counter )
        return sql_id, sql_counter, sql_action, domain_id

    def sqlDNSquery(self, x:dict):
        """
            ## Update the SQL DNS for DNS Queries
            ### Input:
            * sql_data = List of things to do, with dicts inside!
            ### Return:
            * `tuple` (id:str=None, action:str='pass')
        """
        sql_id = None     # < Defaults for return later...
        sql_action = 'pass'
        sql_cursor = self.sql_connection.cursor()

        if x['result'] is None and (x['action'] in ["pass" , "block"]):
            params = (
                        x['id'],
                        x['src'],
                        x['scope_id'],
                        x['query'],
                        x['query_type'],
                        x['counter'],
                        x['action'],
                        x['last_seen'],
                        x['domain_id']
                    )
            self.log.debug(str(params))
            with self.lock:
                try:
                    sql_cursor.execute(
                        f'INSERT INTO "{DB_T_QUERIES}" ("id", "src", "scope_id", "query", "query_type", "counter", "action", "last_seen", "domain_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())
        elif x['result'] is not None:
            x['counter'] +=1                     # Increment the counter
            params = (
                x['counter'],
                x['last_seen'],
                x['id'],
                )
            self.log.debug(str(params))
            with self.lock:
                try:
                    sql_cursor.execute(   # Update the existing Row
                        f'UPDATE "{DB_T_QUERIES}" SET "counter" = ?, "last_seen" = ? WHERE "id" = ?', params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())

        sql_cursor.close()
        try:
            self.sql_connection.commit()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

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
        host_query_id = self.createID([source_ip, query_name, query_type])
        self.log.debug('[HOST] => SQLID: %s | Src IP: %s | Qname: %s | Qtype: %s', host_query_id, source_ip, query_name, query_type )

        r_host_query_id, host_counter, host_action, host_domain_id = self.findSQLQueryID(host_query_id, learning_mode)
        self.log.debug('[HOST] => SQL ID: %s | Counter: %s | Action: %s', r_host_query_id, host_counter, host_action)

        last_seen = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')

        sql_id, sql_action = self.sqlDNSquery(
            {'result': r_host_query_id, 'id': host_query_id, 'counter': host_counter, 'action': host_action, 'scope_id':scope_id, 'src':source_ip, 'query':query_name, 'query_type':query_type, 'last_seen':last_seen, 'domain_id': host_domain_id}
        )
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
        sql_counter = 1

        with self.lock:
            sql_cursor = self.sql_connection.cursor()
            try:
                sql_rows = sql_cursor.execute(f'SELECT "scope", "id", "counter", "action" FROM "{DB_T_DOMAINS}" WHERE domain = ? AND scope = ?', (domain,scope_id,)).fetchall()
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                self.log.error(traceback.format_exc())
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

        sql_cursor.close()
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
        sql_cursor = self.sql_connection.cursor()
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
            with self.lock:
                try:
                    sql_cursor.execute(                       # Create a new Row
                        f'INSERT INTO "{DB_T_DOMAINS}" ("id", "domain", "counter", "scope", "action", "last_seen") VALUES (?, ?, ?, ?, ?, ?)',
                        params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())
        elif sql_id is not None:
            sql_counter +=1                     # Increment the counter
            params = (
                  sql_counter,
                  last_seen,
                  sql_id,
                )
            self.log.debug(str(params))
            with self.lock:
                try:
                    sql_cursor.execute(   # Update the existing Row
                        f'UPDATE "{DB_T_DOMAINS}" SET "counter" = ?, "last_seen" = ? WHERE "id" = ?', params
                    )
                except Exception:
                    self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                    self.log.error(traceback.format_exc())

        sql_cursor.close()
        try:
            self.sql_connection.commit()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            self.log.error(traceback.format_exc())

        return sql_action, sql_id

    def linkSQLs(self, source_ip:str=None, scope_id:str=None, query_name:str=None, query_type:str=None, the_domain_id:str=None):
        """
            Link a Query to a Domain
        """
        self.log.debug('%s (%s) -> %s (%s) => %s', source_ip, scope_id, query_name, query_type, the_domain_id)

        sql_id = self.createID([source_ip, query_name, query_type])
        self.log.debug('Updating %s with %s', sql_id, the_domain_id)
        with self.lock:
            sql_cursor = self.sql_connection.cursor()
            try:
                sql_cursor.execute(   # Update the existing Row
                    f'UPDATE "{DB_T_QUERIES}" SET "domain_id" = ? WHERE "id" = ?', (the_domain_id, sql_id)
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                self.log.error(traceback.format_exc())

        sql_cursor.close()
        try:
            self.sql_connection.commit()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            self.log.error(traceback.format_exc())

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

        the_host = str(qname).strip('.')    # Return our custom responses early
        if the_host in FAKE_A_RECORDS:
            self.log.info("👻 %s -> %s [FAKE] -> %s", src_ip, the_host, FAKE_A_RECORDS[the_host])
            reply.add_answer(RR(the_host,QTYPE.A,rdata=A(FAKE_A_RECORDS[the_host]),ttl=60))
            return reply

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
            self.log.debug("✨ %s -> %s [Type: %s]", src_ip, qname, qtype)
            log_qu = "❓"   # Add icons for things in learning Mode... (Question)
            log_ans = "✅"  # (Answer)

            the_query_id, the_query_action = self.findDNSQuery(str(qname), str(qtype), str(src_ip), scope_id, learning_mode)
            self.log.debug('Query => %s [%s]', the_query_id, the_query_action)

            the_domain, the_domain_action, the_domain_id = self.findDomain(qname, scope_id, learning_mode)
            if the_domain is None:
                self.log.error('😫 Failed to lookup domain for %s', qname)
            else:
                self.linkSQLs(str(src_ip), scope_id, str(qname), str(qtype), the_domain_id)

            self.log.info("✨ %s -> %s [Type: %s] => %s", src_ip, qname, qtype, the_domain)
            if not self.passThePacket(the_domain_action):
                self.log.warning("🔥 New Authority DOMAIN %s Detected for Request %s 🔥", the_domain, qname)
                if the_domain_id is None:
                    the_domain_action, the_domain_id = self.sqlDomains(the_domain,scope_id,'block')
                if WEBHOOKER:
                    data = {
                        'type':'dns',
                        'alert_type': 'dns-domain',
                        'timestamp': datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds'),
                        'src_ip': src_ip,
                        'scope_id': scope_id,
                        'domain_id': the_domain_id,
                        'domain': str(the_domain),
                        'query': str(qname)
                    }
                    post_process_domain = Process(target=postwebhook, args=(data, self.log)) # Start a new process to avoid DNS latency
                    post_process_domain.start()
                if DNS_FIREWALL_ON:
                    self.log.info("🔥🔥 DOMAIN BLOCKED %s 🔥🔥", the_domain)
                    reply.header.rcode = getattr(RCODE,'NXDOMAIN')
                    return reply

            if DNS_DETECT_ON_HOST and not self.passThePacket(the_query_action):
                self.log.warning("🔥 New QUERY %s Detected for %s (%s) 🔥", qname, src_ip, scope_id)
                if WEBHOOKER:
                    data = {
                        'type':'dns',
                        'alert_type': 'dns-query',
                        'timestamp': datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds'),
                        'src_ip': src_ip,
                        'scope_id': scope_id,
                        'domain_id': the_domain_id,
                        'domain': str(the_domain),
                        'query': str(qname)
                    }
                    post_process_query = Process(target=postwebhook, args=(data, self.log))
                    post_process_query.start()
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
            except (socket.timeout, AttributeError):
                reply.header.rcode = getattr(RCODE,'SERVFAIL')
                self.log.error('TIMEOUT %s -> %s', str(self.resolvers[resolver_counter]), qname)

            if resolver_reply:
                self.log.debug('%s [%s]: %s', log_ans, str(self.resolvers[resolver_counter]), str(reply.rr))
                return reply
            resolver_counter+=1

        return reply

def postwebhook(data=None, log:logging=logging, url='http://localhost:8099/notify'):
    """
        Post to our webhook
    """
    status = True
    try:
        r = requests.post(url=url, json=data, timeout=10)
    except Exception:
        log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        status = False
    else:
        if r.status_code != 200:
            status = False
            log.error("Status: %s -> %s", r.status_code, r.content)
        elif DEBUG_MODE:
            log.info("Post Hook Status: %s -> %s", r.status_code, r.content)

    return status

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
            log.error(traceback.format_exc())
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
            try:
                port = int(r['port'])
            except (KeyError, ValueError):
                port = 53

            if re.match(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', r['server']):
                resolvers.append(f"{r['server']}:{port}")
            else:

                # Homeassistant Add-Ons have a name, look for them...
                server_env = str(r['server']).replace('-', '')
                log.debug('Looking for %s', server_env)

                try:
                    server = os.environ[server_env]
                except KeyError:
                    server = None

                if server is not None:
                    log.info('Loaded %s from Env %s', server, r['server'])
                    resolvers.append(f"{server}:{port}")
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

    if udp_server.isAlive():
        postwebhook({'type':'dns', 'logdata':{'msg':'UDP DNS Server Started'}})

    if tcp_server.isAlive():
        postwebhook({'type':'dns', 'logdata':{'msg':'TCP DNS Server Started'}})

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
