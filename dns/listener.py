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

# Some Internal VARS
DB_T_DOMAINS = "domains"
DB_SCHEMA_T_DOMAINS = f'CREATE TABLE "{DB_T_DOMAINS}" ("id" TEXT, "domain" TEXT,"domain_type" TEXT,"counter" INTEGER,"scope" TEXT, "action" TEXT,"last_seen" TEXT)'
DB_T_NETWORKS = "networks"
DB_SCHEMA_T_NETWORKS = f'CREATE TABLE "{DB_T_NETWORKS}" ("id" TEXT, "ip" TEXT,"type" TEXT, "action" TEXT,"created" TEXT)'
DB_ID_SALT = 'This is not for security, it is for uniqueness'

DB_SCHEMA = [
    (DB_T_DOMAINS, DB_SCHEMA_T_DOMAINS),
    (DB_T_NETWORKS, DB_SCHEMA_T_NETWORKS)
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
        self.resolvers = upstream
        self.local_ips = local_ips
        self.local_networks = []

        self.resolver_timeout = timeout/2   # We're making 2x DNS lookups for each request
        if self.resolver_timeout == 0:      # So make our timeout half
            self.resolver_timeout = 1       # Add one, just in case rounding ends up a zero.

        self.log = dnsi_logger
        self.sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}", check_same_thread=False)
        self.sql_cursor = self.sql_connection.cursor()

    def learningMode(self, source_ip):
        """
            Check if Source IP is in Learning More or Not

            # False => Block
            # True => Pass

        """
        self.log.debug("Source IP -> %s", source_ip)

        if len(self.local_networks) == 0: # Process the HA Config

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
                        continue
                else:
                    self.log.critical('Unknown Scope type in DB -> {u}', u=scope_type)
                    scope = netaddr.IPSet() # <- Empty IP Set

                scope_id = self.create_id([scope_type, scope_ip])

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
                    created = sql_rows[0][2]
                    self.log.debug('ID: %s | Action: %s | Created: %s', sql_rows[0], action, created)

                self.local_networks.append({'id': scope_id, 'scope':scope, 'action': action})

            self.log.info('%s/%s local scopes loaded.', len(self.local_networks), len(self.local_ips))

        if len(self.local_networks) > 0:
            for scope in self.local_networks:
                if source_ip in scope['scope']:
                    learning_mode = bool(scope['action'] == 'learn')
                    self.log.debug("Source IP -> %s (%s) -> %s (%s)", source_ip, scope['id'], scope['action'], str(learning_mode))
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

    def create_id(self, input_array:list=None, some_salt:str=DB_ID_SALT):
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

    def findSQLid(self, domain:str=None, scope_id:str=None, sql_action:str=None, learning_mode:bool=True):
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
                self.log.info('ROW: %s', str(row))

        self.log.debug('🌍 For %s & Scope %s => ID: %s (%s/%s)', domain, scope_id, sql_id, sql_counter, sql_action)
        return sql_id, sql_counter, sql_action

    def updatesql(self, domain:str=None, scope_id:str=None, action:str=None, learning_mode:bool=True):
        """
            ## Update the SQL DB
            ### Input:
            * domain => Thing we are recording
            * source_ip => From where
            ### Return:
            * N/A
        """
        self.log.debug('Domain: %s | Scope: %s | Action: %s', domain, scope_id, action)
        last_seen = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')
        sql_id, sql_counter, sql_action = self.findSQLid(scope_id=scope_id, domain=domain, sql_action=action, learning_mode=learning_mode)
        self.log.debug('SQL ID: %s | Counter: %s | Action: %s', sql_id, sql_counter, action)
        if sql_id is None and (sql_action in ["pass" , "block"]):
            sql_id = self.create_id([domain, scope_id])    # Create a new ID
            params = (
                        sql_id,
                        domain,
                        "learn",
                        sql_counter,
                        scope_id,
                        sql_action,
                        last_seen,
                    )
            self.log.debug(str(params))
            try:
                self.sql_cursor.execute(                       # Create a new Row
                    f'INSERT INTO "{DB_T_DOMAINS}" ("id", "domain", "domain_type", "counter", "scope", "action", "last_seen") VALUES (?, ?, ?, ?, ?, ?, ?)',
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
        self.log.debug("SOA -> %s (Resolver: %s | Timout:%s | TCP: %s)",self.resolvers[index], index, self.resolver_timeout, str(tcp))
        try:
            a_pkt = soa_query.send(self.resolvers[index],53,tcp=tcp, timeout=self.resolver_timeout)
        except TimeoutError:
            self.log.error("SOA/TIMEOUT -> %s (Resolver: %s | Timout:%s)",self.resolvers[index], index, self.resolver_timeout)
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
            self.log.debug("AUTHY >--> %s", a.auth)
            result = str(a.auth[0].get_rname())
            self.log.info("🥰 Found Domain -> %s ", result)
        except DNSError:
            self.log.error("DNSERROR Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        except Exception:
            self.log.error("General Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])

        if result is not None:
            result_action, result_id = self.updatesql(domain=result,scope_id=scope_id,learning_mode=learning_mode)
        return result, result_action, result_id

    def resolve(self,request,handler):
        """
            Hook into the DNS Resolve request from the client.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        src_ip = handler.client_address[0]

        self.log.info("✨ %s -> %s [Type: %s]", src_ip, qname, qtype)
        learning_mode, scope_id = self.learningMode(src_ip)

        if scope_id is None and learning_mode: # Uknown IP Ignore
            log_qu = ""
            log_ans = ""
        elif scope_id is None and not learning_mode: # Uknonw IP Block
            self.log.info("⛔️⛔️ DNS BLOCKED %s for Uknown IP %s ⛔️⛔️", qname, src_ip)
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')
            return reply
        else:
            log_qu = "❓"   # Add icons for things in learning Mode... (Question)
            log_ans = "✅"  # (Answer)
            the_domain, the_domain_action, the_domain_id = self.findDomain(qname, scope_id, learning_mode)
            if the_domain is None:
                self.log.error('😫 Failed to lookup domain for %s', qname)

            if not self.passThePacket(the_domain_action):
                self.log.warning("🔥 New Authority Domain %s Detected for Request %s 🔥", the_domain, qname)
                if the_domain_id is None:
                    self.updatesql(the_domain,scope_id,'block')
                if DNS_FIREWALL_ON:
                    self.log.info("🔥🔥 DOMAIN BLOCKED %s 🔥🔥", the_domain)
                    reply.header.rcode = getattr(RCODE,'NXDOMAIN')
                    return reply

        resolver_counter = 0
        resolver_reply = False
        while (resolver_counter < len(self.resolvers)):
            self.log.info("%s %s -> %s", log_qu, qname, self.resolvers[resolver_counter])
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.resolvers[resolver_counter],int(53),timeout=self.resolver_timeout)
                else:
                    proxy_r = request.send(self.resolvers[resolver_counter],int(53),timeout=self.resolver_timeout,tcp=True)
                reply = DNSRecord.parse(proxy_r)
                resolver_reply = True
            except socket.timeout:
                reply.header.rcode = getattr(RCODE,'SERVFAIL')
                self.log.error('TIMEOUT %s -> %s', self.resolvers[resolver_counter], qname)

            if resolver_reply:
                self.log.info('%s [%s]: %s', log_ans, self.resolvers[resolver_counter], str(reply.rr))
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

def get_resolvers(log:logging=logging):
    """
        Try to get DNS servers from resolve.conf
        Fall back to google+cloudflare.
    """
    resolvers = []
    try:
        with open("/etc/resolv.conf", encoding='utf-8') as resolvconf:
            for line in resolvconf.readlines():
                ns = re.search(r'^[\s]*nameserver\s((?:[0-9]{1,3}\.){3}[0-9]{1,3})', str(line).strip(), re.IGNORECASE)
                log.debug("Searching resolve.conf (%s)", ns)
                if ns and ns[1] is not None:
                    resolvers.append(str(ns[1]))
    except Exception:
        log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        resolvers = ["8.8.8.8", "1.1.1.1"]
    log.info('Using Resolvers -> %s', str(resolvers))
    return resolvers

def main(dnsi_logger):
    """
    Run the server - https://github.com/paulc/dnslib/blob/master/dnslib/intercept.py
    """
    resolver = DNSInterceptor(
        upstream=get_resolvers(log=dnsi_logger),
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
