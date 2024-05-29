#!/usr/bin/env python3
# pylint: disable=W0718
import os
import sys
import logging
import json
import traceback
import sqlite3
import threading
import re
import datetime
import hashlib

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

try:
    from jinja2 import Environment, FileSystemLoader
except ModuleNotFoundError:
    logger.critical('Jinja2 Not Installed')
    sys.exit(1)

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

DEBUG_MODE = False      # Default => INFO
try:
    DEBUG_MODE = bool(OPTIONS_DATA['debug'])
except Exception:
    pass
finally:
    logger.info('🫥  debug => %s', DEBUG_MODE)
    if DEBUG_MODE:
        logger.setLevel(logging.DEBUG)

HA_WEBHOOK = None
try:
    HA_WEBHOOK = OPTIONS_DATA['ha_webhook_id']
except Exception:
    pass
else:
    logger.info('💌  Home Assistant WebHook ID => %s', HA_WEBHOOK)

if HA_WEBHOOK is not None:
    try:
        import requests
    except ModuleNotFoundError:
        logger.critical('Disabling Webhook, requests is missing')
        HA_WEBHOOK = None

# Initial Config vars.
if os.path.exists("/share/"):           # <- Revert addon_configs when done.
    CONFIG_DB_PATH = "/share/"
else:
    CONFIG_DB_PATH = "./"               # Make config option

CONFIG_DB_NAME = "hd.db"        # Later, this should be user config

DB_T_DOMAINS = "domains"        # Tables created by DNS Listener
DB_T_QUERIES = "queries"
DB_T_NETWORKS = "networks"
DB_T_HOSTS = "hosts"

DB_T_ALERTS = "alerts"
DB_SCHEMA_T_ALERTS = f'CREATE TABLE "{DB_T_ALERTS}" ("id" TEXT, "timestamp" TEXT, "type" TEXT, "src_ip" TEXT, "message" TEXT)'

DB_V_DOMAINS = "v_domains"
DB_SCHEMA_V_DOMAINS = f'CREATE VIEW "{DB_V_DOMAINS}" AS SELECT "{DB_T_DOMAINS}".id, "{DB_T_DOMAINS}".last_seen, "{DB_T_DOMAINS}".domain, "{DB_T_DOMAINS}".counter, "{DB_T_DOMAINS}".action, "{DB_T_NETWORKS}".ip as scope FROM "{DB_T_DOMAINS}"  LEFT JOIN "{DB_T_NETWORKS}" ON "{DB_T_DOMAINS}".scope = "{DB_T_NETWORKS}".id'
DB_V_QUERIES = "v_queries"
DB_SCHEMA_V_QUERIES = f'CREATE VIEW "{DB_V_QUERIES}" AS SELECT "{DB_T_QUERIES}".id, "{DB_T_QUERIES}".last_seen, "{DB_T_QUERIES}".query, "{DB_T_DOMAINS}".domain, "{DB_T_QUERIES}".query_type, "{DB_T_QUERIES}".src, "{DB_T_NETWORKS}".ip as scope, "{DB_T_QUERIES}".counter, "{DB_T_QUERIES}".action FROM "{DB_T_QUERIES}"  LEFT JOIN "{DB_T_NETWORKS}" ON "{DB_T_QUERIES}".scope_id = "{DB_T_NETWORKS}".id LEFT JOIN "{DB_T_DOMAINS}" ON "{DB_T_QUERIES}".domain_id = "{DB_T_DOMAINS}".id'

DB_ID_SALT = 'This is not for security, it is for uniqueness'
DB_SCHEMA = [
    (DB_T_ALERTS, DB_SCHEMA_T_ALERTS),
    (DB_V_DOMAINS, DB_SCHEMA_V_DOMAINS),
    (DB_V_QUERIES, DB_SCHEMA_V_QUERIES)
]

# Stuff for the webserver.
if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)

if os.path.isdir('/app'):  # <- Container
    FILE_ROOT = '/app'
else:
    FILE_ROOT = "./admin" # <- Local Testing

STATIC_FILES = f'{FILE_ROOT}/static'            # Static Files (CSS, images, etc)
TEMPLATE_FILES = f'{FILE_ROOT}/templates'       # Jinja2 Templates

logger.debug('Serving Static from %s', STATIC_FILES)
logger.debug(os.listdir(STATIC_FILES))

try:
    J2_ENV = Environment(loader=FileSystemLoader(TEMPLATE_FILES))
except Exception:
    logger.critical("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
    logger.error(traceback.format_exc())
    sys.exit(1)
else:
    logger.debug('Reading Templates from %s', TEMPLATE_FILES)
    logger.debug(os.listdir(TEMPLATE_FILES))

# To class children!
class WebRootPage(Resource):
    def render_GET(self, request): # pylint: disable=W0613
        return (
            b"<!DOCTYPE html><html lang='en' data-bs-theme='auto'><head>"
            b"<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            b"<link href='static/bootstrap.min.css' rel='stylesheet' integrity='sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH' crossorigin='anonymous'>"
            b"<script src='static/bootstrap-auto-dark-mode.js'></script>"
            b"<title>Home Detector</title>"
            b"</head><body>There is no spoon</body></html>"
            )

class WebRoot(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return WebRootPage()

class AdminPage(Resource):
    def render_GET(self, request):
        host_url = get_host_url(request, "admin")
        admin_template = J2_ENV.get_template('admin.j2')
        output = admin_template.render(title="Alerts", active="alerts", haurl=host_url)
        return (
            #b"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Home Detector Administration</title></head><body>Admin</body></html>"
            output.encode('utf-8')
            )

class DNSPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return DNSPage()

    def render_GET(self, request):
        host_url = get_host_url(request, "admin")
        admin_template = J2_ENV.get_template('dns.j2')
        output = admin_template.render(title="DNS", active="dns", haurl=host_url)
        return (output.encode('utf-8'))

class TuningPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return TuningPage()

    def render_GET(self, request):
        host_url = get_host_url(request, "admin")
        admin_template = J2_ENV.get_template('tuning.j2')
        output = admin_template.render(title="Tuning", active="tuning", haurl=host_url)
        return (output.encode('utf-8'))

class AdminRoot(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        path_str = path.decode('utf-8')
        logger.debug("Admin Path -> %s", path_str)
        if path_str == "data":
            return DataRoot()
        if path_str == "dns":
            return DNSPage()
        if path_str == "tuning":
            return TuningPage()

        # Default
        return AdminPage()

    def render_GET(self, request):
        # no child.
        return AdminPage().render_GET(request)

class DataAlertsPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return DataAlertsPage()

    def render_GET(self, request):
        # Sanitise our Inputs...
        limit, offset = get_limit_offset(request)
        sort, order = get_sort_n_order(request, "timestamp", ['id', 'timestamp', 'type', 'src_ip', 'message'])

        # SQL Injection away!
        data = sql_action(f"WITH CTE as (SELECT count(*) total FROM {DB_T_ALERTS}) SELECT id,timestamp,type,src_ip,message,(SELECT total FROM CTE) total FROM {DB_T_ALERTS} ORDER BY {sort} {order} LIMIT ? OFFSET ?", (limit, offset))
        rows = []
        for row in data:
            rows.append(
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'type': row[2],
                    'src_ip': row[3],
                    'message': row[4],
                }
            )
            total = row[5]
        response = {
            "data":"alerts",
            "total": total,
            "rows": rows
        }
        request.setHeader('Content-Type', 'application/json')
        #response = {"data":"alerts", "total":1, "rows":[{"timestamp":"abc", "type":"hd", "src_ip":"127.0.0.1", "message":"Hello World"}]}
        return json.dumps(response).encode('utf-8')

class DataDNSDomainsPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return DataDNSDomainsPage()

    def render_GET(self, request):
        limit, offset = get_limit_offset(request)
        sort, order = get_sort_n_order(request, "last_seen", ['domain', 'counter', 'action', 'scope'])
        data = sql_action(f"WITH CTE as (SELECT count(*) total FROM {DB_V_DOMAINS}) SELECT id,last_seen,domain,counter,action,scope,(SELECT total FROM CTE) total FROM {DB_V_DOMAINS} ORDER BY {sort} {order} LIMIT ? OFFSET ?", (limit, offset))
        rows = []
        for row in data:
            rows.append(
                {
                    'id': row[0],
                    'last_seen': row[1],
                    'domain': row[2],
                    'counter': row[3],
                    'action': row[4],
                    'scope': row[5]
                }
            )
            total = row[6]
        response = {
            "data":"dns-domains",
            "total": total,
            "rows": rows
        }
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(response).encode('utf-8')

class DataDNSQueriesPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return DataDNSQueriesPage()

    def render_GET(self, request):
        limit, offset = get_limit_offset(request)
        sort, order = get_sort_n_order(request, "last_seen", ['domain_id', 'query', 'query_type', 'src', 'counter', 'action', 'scope', 'domain'])
        data = sql_action(f"WITH CTE as (SELECT count(*) total FROM {DB_V_QUERIES}) SELECT id,last_seen,domain,query,query_type,src,counter,action,scope,(SELECT total FROM CTE) total FROM {DB_V_QUERIES} ORDER BY {sort} {order} LIMIT ? OFFSET ?", (limit, offset))
        rows = []
        for row in data:
            rows.append(
                {
                    'id': row[0],
                    'last_seen': row[1],
                    'domain': row[2],
                    'query': row[3],
                    'query_type': row[4],
                    'src': row[5],
                    'counter': row[6],
                    'action': row[7],
                    'scope': row[8],
                }
            )
            total = row[9]
        response = {
            "data":"dns-queries",
            "total": total,
            "rows": rows
        }
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(response).encode('utf-8')

class DataDNSRoot(Resource):
    def getChild(self, path, request):
        path_str = path.decode('utf-8')
        logger.debug("Data/DNS Path -> %s with => %s", path_str, request.args)
        if path_str == "domains":
            return DataDNSDomainsPage()
        if path_str == "queries":
            return DataDNSQueriesPage()

        return DataDNSRoot()

    def render_GET(self, request):
        request.setHeader('Content-Type', 'application/json')
        return (b'{"data":"dns"}')

class DataTuningHostPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return DataTuningHostPage()

    def render_GET(self, request):
        limit, offset = get_limit_offset(request)
        sort, order = get_sort_n_order(request, "name", ['ip'])
        data = sql_action(f"WITH CTE as (SELECT count(*) total FROM {DB_T_HOSTS}) SELECT name,ip,(SELECT total FROM CTE) total FROM {DB_T_HOSTS} ORDER BY {sort} {order} LIMIT ? OFFSET ?", (limit, offset))
        rows = []
        for row in data:
            rows.append(
                {
                    'name': row[0],
                    'ip': row[1],
                }
            )
            total = row[2]
        response = {
            "data":"tuning-host",
            "total": total,
            "rows": rows
        }
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(response).encode('utf-8')

class DataTuningNetworkPage(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        return DataTuningNetworkPage()

    def render_GET(self, request):
        limit, offset = get_limit_offset(request)
        sort, order = get_sort_n_order(request, "created", ['ip', 'type', 'action'])
        data = sql_action(f"WITH CTE as (SELECT count(*) total FROM {DB_T_NETWORKS}) SELECT id,created,ip,type,action,(SELECT total FROM CTE) total FROM {DB_T_NETWORKS} ORDER BY {sort} {order} LIMIT ? OFFSET ?", (limit, offset))
        rows = []
        for row in data:
            rows.append(
                {
                    'id': row[0],
                    'created': row[1],
                    'ip': row[2],
                    'type': row[3],
                    'action': row[4],
                }
            )
            total = row[5]
        response = {
            "data":"tuning-network",
            "total": total,
            "rows": rows
        }
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(response).encode('utf-8')

class DataTuningRoot(Resource):
    def getChild(self, path, request):
        path_str = path.decode('utf-8')
        logger.debug("Data/Tuning Path -> %s with => %s", path_str, request.args)
        if path_str == "networks":
            return DataTuningNetworkPage()
        if path_str == "hosts":
            return DataTuningHostPage()
        return DataTuningRoot()

    def render_GET(self, request):
        request.setHeader('Content-Type', 'application/json')
        return (b'{"data":"tuning"}')

class DataRoot(Resource):
    def getChild(self, path, request): # pylint: disable=W0613
        path_str = path.decode('utf-8')
        logger.debug("Data Path -> %s with => %s", path_str, request.args)
        if path_str == "alerts":
            return DataAlertsPage()
        if path_str == "dns":
            return DataDNSRoot()
        if path_str == "tuning":
            return DataTuningRoot()

        # Default
        return DataRoot()

    def render_GET(self, request):
        # no child.
        request.setHeader('Content-Type', 'application/json')
        return (b'{"data":"root"}')


class Webhook(Resource):
    """
        /notify webhook for recieving DNS & Honeypot Alerts
    """
    isLeaf = True

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
            logger.warning("Input is not a list %s", str(input_array))
            return "ERROR: Input not list"
        # https://www.pythoncentral.io/hashing-strings-with-python/
        hash_object = hashlib.sha256(some_salt.join(input_array).encode())
        hex_dig = hash_object.hexdigest()
        return str(hex_dig)

    def __sqlSave(self, alert:dict=None):
        """
            Insert into DB
        """
        logger.debug(alert)
        logger.info("🔥🔥 %s 🔥🔥", alert['message'])
        status = sql_action(f'INSERT INTO "{DB_T_ALERTS}" ("id", "timestamp", "type", "src_ip", "message" ) VALUES (?, ?, ?, ?, ?)', (alert['id'], alert['timestamp'], alert['type'], alert['src_ip'], alert['message'],))
        if HA_WEBHOOK is not None:
            if not post_to_ha(alert):
                logger.warning('Sending Alert to Webhook Failed.')
        return status

    def __process_dns(self, alert:dict=None):
        logger.debug(alert)
        return b"ok \n"

    def __process_canary(self, alert:dict=None):
        """
            Convert what we got into standard format..
        """
        logger.info(alert)
        status = b"Failed \n"

        try:
            logdata_msg = alert['logdata']['msg']
        except Exception:
            pass
        else:
            logger.info("🍯 -> %s", str(logdata_msg))
            return b"ok \n"

        try:
            canary_utc_time = datetime.datetime.fromisoformat(alert['utc_time']) # Input is a timezone-less string
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return status

        canary_utc_time = canary_utc_time.replace(tzinfo=datetime.UTC)  # Add Timezone
        timestamp = canary_utc_time.isoformat(timespec='seconds')       # Standardise to my format

        try:
            alert_type = f"canary-p{alert['dst_port']}"
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return status

        try:
            src_ip = alert['src_host']
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return status

        record_id = self.createID([timestamp, alert_type, src_ip])

        poos_like_honey = ""
        try:
            if alert['honeycred']:
                poos_like_honey = "Honey "
        except KeyError:
            pass # Honey Cred not set, use blank.

        try:
            user_agent = alert['logdata']['USERAGENT']
        except KeyError:
            web_agent = ""
        else:
            web_agent = f" by {user_agent}"

        try:
            username = alert['logdata']['USERNAME']
        except KeyError:
            username = ""

        try:
            password = alert['logdata']['PASSWORD']
        except KeyError:
            password = ""

        try:
            message = f"HoneyPot Login from {src_ip}{web_agent} with {poos_like_honey}Credentials {username} & {password} on port {alert['dst_port']}"
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return status

        sql_data = {
            'id':record_id,
            'timestamp':timestamp,
            'type': alert_type,
            'src_ip': src_ip,
            'message': message,
        }

        if self.__sqlSave(sql_data):
            status = b"ok \n"

        return status

    def render_POST(self, request):
        request_src_ip = request.transport.getPeer().host
        logger.debug('Source IP -> %s ', request_src_ip)

        try:
            args = request.content.getvalue().decode('utf8')
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return (b"Args Failed ")

        logger.debug("POST String -> %s", args)

        try:
            data = json.loads(args)
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return (b"Decode Failed ")

        logger.debug("Post JSON/DICT -> %s", data)

        if data['type'] == "opencanary":
            return self.__process_canary(json.loads(data['message']))

        if data['type'] == "dns":
            return self.__process_dns(data)

        if DEBUG_MODE:
            return ( b"-> " + args.encode('utf-8') + "\n".encode('utf-8'))

        return ( b"echo reply \n")


    def render_GET(self, request):
        request_src_ip = request.transport.getPeer().host
        logger.debug('Source IP -> %s ', request_src_ip)
        return (
            b"<!DOCTYPE html><html lang='en' data-bs-theme='auto'><head>"
            b"<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            b"<link href='static/bootstrap.min.css' rel='stylesheet' integrity='sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH' crossorigin='anonymous'>"
            b"<script src='static/bootstrap-auto-dark-mode.js'></script>"
            b"<title>Home Detector</title>"
            b"</head><body>Kill All Humans!</body></html>"
            )

# Global Functions
def bootstrap():
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
        logger.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
        status = False
    else:
        logger.info('Connected to SQLite DB %s/%s', CONFIG_DB_PATH, CONFIG_DB_NAME)

    for table in DB_SCHEMA:
        try:
            connection.execute(table[1])
        except sqlite3.OperationalError:
            if re.search(f"\"{table[0]}\" already exists", str(sys.exc_info()[1]), re.IGNORECASE):
                logger.debug('DB Schema - Nothing to do')
                status = True
            else:
                logger.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
                status = False
        except Exception:
            logger.error("Exception: %s - %s", sys.exc_info()[0], sys.exc_info()[1])
            logger.error(traceback.format_exc())
            status = False
        else:
            logger.info('DB %s SCHEMA Created', table[0])

    connection.commit()
    connection.close() # Ok, all good, it's close.
    return status

def post_to_ha(data:dict=None, webhook_id:str=HA_WEBHOOK):
    """
        Post data to Home Assistant WebHook
    """
    url = f'http://supervisor/core/api/webhook/{webhook_id}'
    logger.debug('Sending %s to %s', str(data), url)
    status = False
    headers = {}

    try:
        token = os.environ['SUPERVISOR_TOKEN']
    except Exception:
        logger.error('Failed to Read Home Assistant Auth Token')
    else:
        headers['Authorization'] = f"Bearer {token}"

    try:
        r = requests.post(json=data, url=url, headers=headers, timeout=30)
    except Exception:
        logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
        logger.error(traceback.format_exc())
        status_code = 1000
    else:
        status_code = r.status_code

    logger.debug('Hook Status Code: %s', status_code)
    if status_code == 200:
        status = True

    if DEBUG_MODE:
        try:
            logger.info("Hook Content -> %s", str(r.content))
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

    return status

def get_host_url(request, path=None):
    """
        Try to suss-out the Absolute URL for Statics
    """
    if request.getHeader('X-Ingress-Path') is None: # <- Home Assistant Ingress
        urlpath = str(request.URLPath())            # <- Everything else
        reggy = re.match(r"(.*)\/("+ path + r"\/?)", urlpath)
        logger.debug(reggy)
        if not reggy:
            return ""
        host_url = reggy[1]
        logger.debug("%s on %s", path, host_url)
        return host_url + "/"
    return str(request.getHeader('X-Ingress-Path')) + "/"

def get_limit_offset(request):
    """
        Parse Args, return ints
    """
    try:
        limit = int(request.args[b'limit'][0].decode('utf-8')) # <- Whatever it is submitted, is rendered an INT :)
    except Exception:
        limit = 10

    try:
        offset = int(request.args[b'offset'][0].decode('utf-8'))
    except Exception:
        offset = 0

    return limit, offset

def get_sort_n_order(request, default_sort, allow_list):
    """
    """
    sort = default_sort
    try:
        danger_sort = request.args[b'sort'][0].decode('utf-8')  # <- Compare against expected strings below
    except Exception:
        pass
    else:
        if danger_sort in allow_list:
            sort = danger_sort

    order = "DESC"
    try:
        danger_order = request.args[b'order'][0].decode('utf-8')
    except Exception:
        pass
    else:
        if danger_order in ['asc', 'desc']:
            order = danger_order
    return sort, order

def sql_action(sql_str, sql_param):

    lock = threading.Lock()
    try:
        sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}", check_same_thread=False)
        sql_cursor = sql_connection.cursor()
    except Exception:
        logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
        logger.error(traceback.format_exc())
        return False

    with lock:
        try:
            if re.search('SELECT', sql_str, re.IGNORECASE):
                result = sql_cursor.execute(sql_str, sql_param).fetchall()
            else:
                result = sql_cursor.execute(sql_str, sql_param)
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())
            return False

    with lock:
        try:
            sql_connection.commit()
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            return False

    sql_connection.close()
    return result

# Main!
if __name__ == "__main__":
    if not bootstrap():
        logger.critical('bootstrap failed, exiting...')
        sys.exit(1)

    if DEBUG_MODE:
        observer = log.PythonLoggingObserver(loggerName="HomeAssistant")
        observer.start()

    root = WebRoot()
    root.putChild(b"static", File(STATIC_FILES))
    root.putChild(b"admin", AdminRoot())
    root.putChild(b"notify", Webhook())
    factory = Site(root)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 8099)
    endpoint.listen(factory)
    reactor.run() # pylint: disable=E1101
