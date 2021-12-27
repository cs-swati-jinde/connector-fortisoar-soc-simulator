from connectors.core.connector import get_logger, ConnectorError
from integrations.requests_auth import get_requests_auth
from cshmac.requests import HmacAuth
from django.conf import settings
import requests, argparse, textwrap, json, random, time, os, csv, re
from .constants import CONNECTOR_VERSION

logger = get_logger('soc_scenario')  
  
  
supported_operations = {}

def set_config_job(scenario_path,scenario_title):
    file_path=scenario_path
    file_iri= _upload_file(file_path,scenario_title=scenario_title.title())
    _create_import_job(file_iri)
    
    
def _upload_file(data_path,scenario_title):
    file = open(data_path, 'rb')
    file_name = scenario_title
    multipart_headers = {'Expire': 0}
    request_headers = {}
    extra_fields = {}
    files = {'file': (file_name, file, 'application/json', multipart_headers)}
    url = "/api/3/files"
    response = make_request(url, 'POST', files=files)
    response = response.json()
    return response.get('@id')
  
def _create_import_job(file_iri):
    # payload = {"file" : {"@id":file_iri},"status":"Draft","options":{}}
    payload = {"file": file_iri, "status": "Draft", "options": {}}
    url = "/api/3/import_jobs"
    response = make_request(url, 'POST', body=payload)
    response = response.json()
    job_id = response.get('@id').split("/")[-1]
    return job_id

def load_threat():
    #These URLs require review
    threat_data = [{
        "name": "bad_ip",
        "url": "https://malsilo.gitlab.io/feeds/dumps/ip_list.txt",
        "filename": "malicious_ips"
    }, {
        "name": "bad_hashes",
        "url": "https://cybercrime-tracker.net/ccamlist.php",
        "filename": "malware_hashes"
    },
    {
        "name": "bad_domains",
        "url": "https://malsilo.gitlab.io/feeds/dumps/domain_list.txt",
        "filename": "malicious_domains"
    }, {
        "name": "bad_urls",
        "url": "https://openphish.com/feed.txt",
        "filename": "malicious_urls"
    }
    ]
    threat_intel_dir = "{}/threat_intelligence/".format(os.path.dirname(__file__))
    for item in threat_data:
        lines=''
        try:
            response = requests.get(url=item.get('url'))
            file_path = "{}{}.txt".format(threat_intel_dir, item.get('filename'))

            if item.get('name') == "bad_ip" or item.get('name') == "bad_domains":
                decoded_content = response.content.decode('utf-8')
                cr = csv.reader(decoded_content.splitlines(), delimiter=',')
                for skip in range(16):
                    next(cr)
                bad_list = list(cr)
                if item.get('name') == 'bad_domains':
                    for row in bad_list:
                        lines+=row[2]+'\n'
                elif item.get('name') == 'bad_ip':
                    for row in bad_list:
                        lines+=row[2].split(':')[0]+'\n'

                with open(file_path, 'w+') as f:
                    f.write(lines)

            elif item.get('name') == "bad_hashes" or item.get('name') == "bad_urls":
                with open(file_path, 'wb') as f:
                    f.write(response.content)

        except Exception as e:
            logger.error( "Error downloading threat intelligence data : {}".format(e) )
            raise ConnectorError( "Error downloading threat intelligence data : {}".format(e) )




def make_request(url, method, body=None,files=None, *args, **kwargs):
    """
    This function facilitates using the crud hub api.
    It is for general purpose requests, but takes care of authentication
    automatically.
   :param str collection: An IRI that points to the location of the \
       crud hub collection (E.g. /api/3/events)
   :param str method: HTTP method
   :param dict body: An object to json encode and send to crud hub
   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict/bytes
    """
    # ctrl c/v
    # get rid of the body on GET/HEAD requests
    bodyless_methods = ['head', 'get']
    if method.lower() in bodyless_methods:
        body = None

    if type(body) == str:
        try:
            body = ast.literal_eval(body)
        except Exception:
            pass

    url = settings.CRUD_HUB_URL + url
    logger.info('Starting request: %s , %s', method, url)
    env = kwargs.get('env', {})
    # for default if no env HMAC method
    if not env or not env.get('auth_info', False):
        env['auth_info'] = {"auth_method": "CS HMAC"}

    # for public and private key in env
    if env.get('public_key', False) and env.get('private_key', False):
        env['auth_info'] = {"auth_method": "CS HMAC"}
        public_key = env.get('public_key')
        private_key = env.get('private_key')
    else:
        public_key = settings.APPLIANCE_PUBLIC_KEY
        private_key = settings.APPLIANCE_PRIVATE_KEY
    auth_info = env.get('auth_info')
    auth = get_requests_auth(auth_info, url, method,
                             public_key,
                             private_key,
                             json.dumps(body), *args, **kwargs)
    if files:
        auth = HmacAuth(url, method, public_key, private_key,public_key.encode('utf-8'))
        response = requests.request(method, url, auth=auth, files=files, verify=False)
        return response
    else:
        response = requests.request(method, url, auth=auth, json=body, verify=False)
        return response