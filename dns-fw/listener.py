#!/usr/bin/env python3
# pylint: disable=no-member # <- Weird Reactor Error 🤷🏻‍♂️
# pylint: disable=W0718
import sys
import re
import sqlite3
import netaddr
import hashlib
import datetime

try: # https://twisted.org
    from twisted.internet import reactor, defer
    from twisted.names import client, dns, server
except ModuleNotFoundError:
    print('Twisted not Installed - try pip install twisted')
    sys.exit(1)

# setup Twisted Logging. https://stackoverflow.com/a/49111089
from twisted.logger import Logger, LogLevel, LogLevelFilterPredicate, FilteringLogObserver, textFileLogObserver, globalLogPublisher
observer = FilteringLogObserver(textFileLogObserver(sys.stdout), [LogLevelFilterPredicate(defaultLogLevel=LogLevel.info)])
globalLogPublisher.addObserver(observer)

# Some VARS
DB_SCHEMA = 'CREATE TABLE "dns-fw" ("id" TEXT, "domain" TEXT,"domain_type" TEXT,"counter" INTEGER,"scope" TEXT, "scope_type" TEXT, "action" TEXT,"last_seen" TEXT)'
DB_ID_SALT = 'This is not for security, it is for uniqueness'

# Initial Config vars.
CONFIG_DB_PATH = "./"               # Make config option
CONFIG_DB_NAME = "dns-fw.db"        # Later, this should be user config

# CLasses & Functions...
class DNSServerFirewall(server.DNSServerFactory):
    log = Logger()
    sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}")
    sql_cursor = sql_connection.cursor()


    def learningMode(self, source_ip):
        """
            Check if Source IP is in Learning More or Not
        """
        self.log.debug("Source IP -> {ip}", ip=source_ip)
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
            self.log.warn("Input is not a list {i}", i=str(input_array))
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

        sql_rows = self.sql_cursor.execute('SELECT "scope_type", "scope", "id", "counter" FROM "dns-fw" WHERE domain = ?', (domain,)).fetchall()
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

        self.log.info('🌍 For {domain}, IP {ip} => ID: {id} ({c})', domain=domain, ip=source_ip, id=sql_id, c=sql_counter)
        return sql_id, sql_counter

    def updatesql(self, results, query, source_ip):
        """
            Do SQL Updates...
        """
        self.log.info("Source IP -> {ip}", ip=source_ip)
        self.log.info("RESULTS ---> {d}", d=str(results))
        self.log.info("QUERY ---> {d}", d=str(query))
        domain = results[0][0]
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
                self.log.error("Exception: {s1} - {s2}", s1=str(sys.exc_info()[0]), s2=str(sys.exc_info()[1]))
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
                self.log.error("Exception: {s1} - {s2}", s1=str(sys.exc_info()[0]), s2=str(sys.exc_info()[1]))
        self.sql_connection.commit()


        return # Not Implemented Yet

    def findDomain(self, records):
        """
            Takes DNS Lookup (Records) and finds domain it belongs to via SOA.
        """
        the_domain = None
        the_type = None

        self.log.debug("RECORDS IN --> {r}", r=str(records))
        for rec in records:
            self.log.debug("⏺️ : r= {r}", r=str(rec))

            if len(rec) > 0:                            # Some Responses are empty
                r_type = dns.QUERY_TYPES[rec[0].type]   # Convert number type to human readable
                r_name = rec[0].name                    # Record Name
                self.log.debug("⏺️ --> name: {n}, type {t}", n=str(r_name), t=str(r_type))
                if r_type == "SOA":                     # Yes! We wan This
                    the_domain = str(r_name)            # This the the Domain name for the query!
                    the_type = r_type
        if the_type is not None:
            self.log.info("🥰 Found Domain -> {d} ", d=the_domain)
        return the_domain, the_type

    def newRequest(self, domainname, source_ip):
        """
            This sets up a new resolver client to perform our own SOA lookup
        """
        r = client
        d = defer.gatherResults([r.lookupAuthority(domainname).addCallback(self.findDomain)])   # Lookup & Find Domain Name
        d.addCallback(self.updatesql, domainname, source_ip)                                    # Send Domain Name to SQL
        return

    def allowQuery(self, message, protocol, address):
        """
            Called by DNSServerFactory.messageReceived to decide whether to process a received message or to reply with dns.EREFUSED.
            REF: https://docs.twistedmatrix.com/en/stable/api/twisted.names.server.DNSServerFactory.html#allowQuery
        """

        self.log.debug("[allowQuery] Connection from {addr}", addr=address)
        self.log.debug("m = {m}", m=message)
        self.log.debug("p = {p}", p=protocol)

        self.log.info("✨ {a} -> {q} [Type: {t}]", a=address[0], q=message.queries[0].name, t=dns.QUERY_TYPES[message.queries[0].type])

        if self.learningMode(address[0]):
            self.newRequest(str(message.queries[0].name), str(address[0]))

        if re.search("yahoo", str(message.queries[0].name), re.IGNORECASE):
            self.log.warn("🔥 Blocked {n}", n=message.queries[0].name)
            return False

        return True

def bootstrap():

    log = Logger()
    status = True
    try:
        connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}")
    except Exception:
        log.error("Exception: {s1} - {s2}", s1=str(sys.exc_info()[0]), s2=str(sys.exc_info()[1]))
        status = False
    else:
        log.info('Connected to SQLite DB {p}/{n}', p=CONFIG_DB_PATH, n=CONFIG_DB_NAME)

    cursor = connection.cursor()
    try:
        cursor.execute(DB_SCHEMA)
    except sqlite3.OperationalError:
        if re.search("table \"dns-fw\" already exists", str(sys.exc_info()[1]), re.IGNORECASE):
            log.debug('DB Schema - Nothing to do')
            status = True
        else:
            log.error("Exception: {s1} - {s2}", s1=str(sys.exc_info()[0]), s2=str(sys.exc_info()[1]))
            status = False
    except Exception:
        log.error("Exception: {s1} - {s2}", s1=str(sys.exc_info()[0]), s2=str(sys.exc_info()[1]))
        status = False
    else:
        log.info('DB SCHEMA Created')

    cursor.close() # Ok, all good, it's close.
    return status

def main():
    """
    Run the server - https://docs.twisted.org/en/stable/names/index.html
    """
    factory = DNSServerFirewall(
        clients=[client]
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(10053, protocol)
    reactor.listenTCP(10053, factory)
    reactor.run()


if __name__ == "__main__":
    if not bootstrap():
        print('bootstap failed, exiting...')
        sys.exit(1)
    raise SystemExit(main())
