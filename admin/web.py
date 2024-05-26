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

CONFIG_DB_NAME = "alerts.db"        # Later, this should be user config

DB_T_ALERTS = "alerts"
DB_SCHEMA_T_ALERTS = f'CREATE TABLE "{DB_T_ALERTS}" ("id" TEXT, "timestamp" TEXT, "type" TEXT, "src_ip" TEXT, "message" TEXT)'

DB_ID_SALT = 'This is not for security, it is for uniqueness'
DB_SCHEMA = [
    (DB_T_ALERTS, DB_SCHEMA_T_ALERTS)
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
    isLeaf = True
    def render_GET(self, request):
        logger.debug('request.path -> %s', request.path)
        admin_template = J2_ENV.get_template('admin.j2')
        output = admin_template.render()
        return (
            #b"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Home Detector Administration</title></head><body>Admin</body></html>"
            output.encode('utf-8')
            )

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
        status = False

        lock = threading.Lock()
        try:
            sql_connection = sqlite3.connect(f"{CONFIG_DB_PATH}/{CONFIG_DB_NAME}", check_same_thread=False)
            sql_cursor = sql_connection.cursor()
        except Exception:
            logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
            logger.error(traceback.format_exc())

        with lock:
            try:
                sql_cursor.execute(
                    f'INSERT INTO "{DB_T_ALERTS}" ("id", "timestamp", "type", "src_ip", "message" ) VALUES (?, ?, ?, ?, ?)', (alert['id'], alert['timestamp'], alert['type'], alert['src_ip'], alert['message'],)
                )
            except Exception:
                logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                logger.error(traceback.format_exc())

        with lock:
            try:
                sql_connection.commit()
            except Exception:
                logger.error("Exception: %s - %s", str(sys.exc_info()[0]), str(sys.exc_info()[1]))

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

        if alert['honeycred']:
            poos_like_honey = "Honey "
        else:
            poos_like_honey = ""

        try:
            message = f"HoneyPot Login from {src_ip} with {poos_like_honey}Credentials {alert['logdata']['USERNAME']} & {alert['logdata']['PASSWORD']} on port {alert['dst_port']}"
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
            if re.search(f"table \"{table[0]}\" already exists", str(sys.exc_info()[1]), re.IGNORECASE):
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
    root.putChild(b"admin", AdminPage())
    root.putChild(b"notify", Webhook())
    factory = Site(root)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 8099)
    endpoint.listen(factory)
    reactor.run() # pylint: disable=E1101
