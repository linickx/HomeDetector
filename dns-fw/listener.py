#!/usr/bin/env python3
# pylint: disable=no-member # <- Weird Reactor Error 🤷🏻‍♂️
# pylint: disable=W0718
import sys
import re

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

class DNSServerFirewall(server.DNSServerFactory):
    log = Logger()

    def learningMode(self, source_ip):
        """
            Check if Source IP is in Learning More or Not
        """
        self.log.debug("Source IP -> {ip}", ip=source_ip)
        return True # Default True in development

    def updatesql(self, results, query):
        """
            Do SQL Updates...
        """
        self.log.debug("RESULTS ---> {d}", d=str(results))
        self.log.debug("QUERY ---> {d}", d=str(query))
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

    def newRequest(self, domainname):
        """
            This sets up a new resolver client to perform our own SOA lookup
        """
        r = client
        d = defer.gatherResults([r.lookupAuthority(domainname).addCallback(self.findDomain)])   # Lookup & Find Domain Name
        d.addCallback(self.updatesql, domainname)                                               # Send Domain Name to SQL
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
            self.newRequest(str(message.queries[0].name))

        if re.search("yahoo", str(message.queries[0].name), re.IGNORECASE):
            self.log.warn("🔥 Blocked {n}", n=message.queries[0].name)
            return False

        return True

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
    raise SystemExit(main())
