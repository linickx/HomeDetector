#!/usr/bin/env python3
# pylint: disable=W0718
import os
import sys
import logging

logger = logging.getLogger("HomeAssistant")
log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s:%(funcName)s] %(levelname)s: %(message)s ', datefmt="%Y-%m-%d %H:%M:%S"))
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

try:
    from twisted.internet import reactor, endpoints
    from twisted.web.server import Site
    from twisted.web.static import File
    from twisted.web.resource import Resource
    from twisted.python import log
except ModuleNotFoundError:
    logger.critical('Twisted Not Installed')
    sys.exit(1)

class WebRoot(Resource):
    def render_GET(self, request):
        return (
            b"<!DOCTYPE html><html lang='en' data-bs-theme='auto'><head>"
            b"<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            b"<link href='/static/bootstrap.min.css' rel='stylesheet' integrity='sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH' crossorigin='anonymous'>"
            b"<script src='/static/bootstrap-auto-dark-mode.js'></script>"
            b"<title>Home Detector</title>"
            b"</head><body>There is no spoon</body></html>"
            )

class AdminPage(Resource):
    isLeaf = True
    def render_GET(self, request):
        return (
            b"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Home Detector Administration</title></head><body>Admin</body></html>"
            )

class Webhook(Resource):
    isLeaf = True
    def render_GET(self, request):
        return (b"<!DOCTYPE html><html><head><meta charset='utf-8'><title>WebHook</title></head><body>Hook!</body></html>")

# Static Files (CSS, images, etc)
if os.path.isdir('/app/admin/static'):  # <- Container
    STATIC_FILES = '/app/admin/static'
else:
    STATIC_FILES = './admin/static'     # <- Local Testing

observer = log.PythonLoggingObserver(loggerName="HomeAssistant")
observer.start()

root = Resource()
root.putChild(b"", WebRoot())
root.putChild(b"static", File(STATIC_FILES))
root.putChild(b"admin", AdminPage())
root.putChild(b"notify", Webhook())
factory = Site(root)
endpoint = endpoints.TCP4ServerEndpoint(reactor, 8099)
endpoint.listen(factory)
reactor.run() # pylint: disable=E1101
