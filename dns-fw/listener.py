#!/usr/bin/env python3
# pylint: disable=no-member # <- Weird Reactor Error 🤷🏻‍♂️
import sys
import re

# https://twisted.org
from twisted.internet import reactor
from twisted.names import client, dns, server

# https://stackoverflow.com/a/49111089
from twisted.logger import Logger, LogLevel, LogLevelFilterPredicate, FilteringLogObserver, textFileLogObserver, globalLogPublisher
observer = FilteringLogObserver(textFileLogObserver(sys.stdout), [LogLevelFilterPredicate(defaultLogLevel=LogLevel.info)])
globalLogPublisher.addObserver(observer)


class DNSServerFirewall(server.DNSServerFactory):
    log = Logger()

    def allowQuery(self, message, protocol, address):
        """
            Called by DNSServerFactory.messageReceived to decide whether to process a received message or to reply with dns.EREFUSED.
            REF: https://docs.twistedmatrix.com/en/stable/api/twisted.names.server.DNSServerFactory.html#allowQuery
        """

        self.log.debug("[allowQuery] Connection from {addr}", addr=address)
        self.log.debug("m = {m}", m=message)
        self.log.debug("p = {p}", p=protocol)

        self.log.info("✨ {a} -> {q} [Type: {t}]", a=address[0], q=message.queries[0].name, t=dns.QUERY_TYPES[message.queries[0].type])

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
