#!/usr/bin/env python3
# pylint: disable=W0718
import sys
import logging
import time
import socket
import re
import sqlite3
import datetime
import hashlib

try:
    from dnslib.dns import DNSError, DNSQuestion
    from dnslib import DNSRecord,QTYPE,RCODE
    from dnslib.server import DNSServer,BaseResolver,DNSLogger
except ModuleNotFoundError:
    print('Dnslib not Installed - try pip install dnslib')
    sys.exit(1)

try:
    import netaddr
except ModuleNotFoundError:
    print('netaddr not Installed - try pip install netaddr')
    sys.exit(1)

# Some VARS
DB_SCHEMA = 'CREATE TABLE "dns-fw" ("id" TEXT, "domain" TEXT,"domain_type" TEXT,"counter" INTEGER,"scope" TEXT, "scope_type" TEXT, "action" TEXT,"last_seen" TEXT)'
DB_ID_SALT = 'This is not for security, it is for uniqueness'

# Initial Config vars.
CONFIG_DB_PATH = "./"               # Make config option
CONFIG_DB_NAME = "dns-fw.db"        # Later, this should be user config

# CLasses & Functions...
class DNSServerFirewall(BaseResolver):

    def __init__(self,upstream:list,timeout:float=5, dnsfw_logger:logging=logging):
        self.resolvers = upstream

        self.resolver_timeout = timeout/2   # We're making 2x DNS lookups for each request
        if self.resolver_timeout == 0:      # So make our timeout half
            self.resolver_timeout = 1       # Add one, just in case rounding ends up a zero.

        self.log = dnsfw_logger
        self.sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}", check_same_thread=False)
        self.sql_cursor = self.sql_connection.cursor()

    def learningMode(self, source_ip):
        """
            Check if Source IP is in Learning More or Not
        """
        self.log.debug("Source IP -> %s", source_ip)
        return True # Default True in development

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

    def findSQLid(self, domain:str=None, source_ip:str=None):
        """
            ## Find the SQL Row ID for a domain/ip pair
            ### Input:
            * `domain`: Domain returned from SOA lookup
            * `source_ip`: IP that made the request
            ### Return:
            * `tuple` (id:str=None, counter:int)
        """
        sql_id = None
        sql_counter = 0

        try:
            sql_rows = self.sql_cursor.execute('SELECT "scope_type", "scope", "id", "counter" FROM "dns-fw" WHERE domain = ?', (domain,)).fetchall()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            return sql_id, sql_counter

        for row in sql_rows:

            scope_type = row[0].strip()

            if scope_type == 'host':
                scope = netaddr.IPSet([netaddr.IPAddress(str(row[1]).strip())])
            elif scope_type == 'network':
                scope = netaddr.IPSet([netaddr.IPNetwork(str(row[1]).strip())])
            elif scope_type == 'range':
                ip_range = str(row[1]).strip().split('-')
                scope = netaddr.IPSet([netaddr.IPRange(ip_range[0], ip_range[1])])
            else:
                self.log.critical('Unknown Scope type in DB -> {u}', u=scope_type)
                scope = netaddr.IPSet() # <- Empty IP Set

            if source_ip in scope:
                sql_id = str(row[2]).strip()
                sql_counter = int(row[3])

        self.log.info('🌍 For %s, IP %s => ID: %s (%s)', domain, source_ip, sql_id, sql_counter)
        return sql_id, sql_counter

    def updatesql(self, domain:str, source_ip:str):
        """
            ## Update the SQL DB
            ### Input:
            * domain => Thing we are recording
            * source_ip => From where
            ### Return:
            * N/A
        """
        last_seen = datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')
        sql_id, sql_counter = self.findSQLid(source_ip=source_ip, domain=domain)
        if sql_id is None:
            sql_id = self.create_id([domain, source_ip, 'host'])    # Create a new ID
            params = (
                        sql_id,
                        domain,
                        "learn",
                        sql_counter,
                        source_ip,
                        "host",
                        "pass",
                        last_seen,
                    )
            self.log.debug(str(params))
            try:
                self.sql_cursor.execute(                       # Create a new Row
                    'INSERT INTO "dns-fw" ("id", "domain", "domain_type", "counter", "scope", "scope_type", "action", "last_seen") VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    params
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
        else:
            sql_counter +=1                     # Increment the counter
            params = (
                  sql_counter,
                  last_seen,
                  sql_id,
                )
            self.log.debug(str(params))
            try:
                self.sql_cursor.execute(   # Update the existing Row
                    'UPDATE "dns-fw" SET "counter" = ?, "last_seen" = ? WHERE "id" = ?', params
                )
            except Exception:
                self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
        try:
            self.sql_connection.commit()
        except Exception:
            self.log.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

        return # Not Implemented Yet

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

    def findDomain(self, domainname:str):
        """
            ## From the query, send a new DNS Request (SOA) to find the domain name of the host/domainname.
            REF: https://github.com/paulc/dnslib/blob/master/dnslib/client.py
            ### Input:
            * domainname => Host or Domainname to find the authorative domain
            ### Return:
            * the domain:str ... or None for failed.
        """

        result = None

        q = DNSRecord(q=DNSQuestion(domainname,getattr(QTYPE,'SOA')))

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
            self.log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        except Exception:
            self.log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        return result

    def resolve(self,request,handler):
        """
            Hook into the DNS Resolve request from the client.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        src_ip = handler.client_address[0]

        self.log.info("✨ %s -> %s [Type: %s]", src_ip, qname, qtype)

        the_domain = self.findDomain(qname)
        if the_domain is None:
            self.log.error('😫 Failed to lookup domain for %s', qname)
        else:
            self.updatesql(the_domain,src_ip)

        if re.search("awsglobalaccelerator", str(the_domain), re.IGNORECASE):
            self.log.warning("🔥 Blocked Authority Domain %s for Request %s", the_domain, qname)
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')
            return reply

        resolver_counter = 0
        resolver_reply = False
        while (resolver_counter < len(self.resolvers)):
            self.log.info("Trying %s for %s", self.resolvers[resolver_counter], qname)
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
                self.log.info('%s found %s', self.resolvers[resolver_counter], str(reply.rr))
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

    #cursor = connection.cursor()
    try:
        connection.execute(DB_SCHEMA)
    except sqlite3.OperationalError:
        if re.search("table \"dns-fw\" already exists", str(sys.exc_info()[1]), re.IGNORECASE):
            log.debug('DB Schema - Nothing to do')
            status = True
        else:
            log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
            status = False
    except Exception:
        log.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        status = False
    else:
        log.info('DB SCHEMA Created')

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

def main(dnsfw_logger):
    """
    Run the server - https://github.com/paulc/dnslib/blob/master/dnslib/intercept.py
    """
    resolver = DNSServerFirewall(upstream=get_resolvers(log=dnsfw_logger), dnsfw_logger=dnsfw_logger)

    LOG_HOOKS = "truncated,error" #LOG_HOOKS = "request,reply,truncated,error"
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
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s:%(funcName)s] %(levelname)s: %(message)s ', datefmt="%Y-%m-%d %H:%M:%S")) # (%(thread)d %(threadName)s)
    fw_logger = logging.getLogger("DNSServerFirewall")
    fw_logger.addHandler(log_handler)
    fw_logger.setLevel(logging.INFO)

    if not bootstrap(fw_logger):
        fw_logger.critical('bootstrap failed, exiting...')
        sys.exit(1)

    main(fw_logger)
