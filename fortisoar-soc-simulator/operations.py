import json, requests, os, random, re, arrow
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('FortiSOARSocSimulator')

def __threatdata_from_file(filename , params):
    file_path = "{}/threat_intelligence/{}.dot".format(os.path.dirname(__file__), filename)
    lines = open(file_path).read().splitlines()
    if params.get('random'):
        return(random.choice(lines))
    else:
        return lines[0]

def bad_ip(params):
    return __threatdata_from_file('malicious_ips', params)

def bad_url(params):
    return __threatdata_from_file('malicious_urls', params)

def bad_filehash(params):
    return __threatdata_from_file('malware_hashes', params)

def bad_domain(params):
    return __threatdata_from_file('malicious_domains', params)

def replace_variables(params):

    if isinstance(params.get('variables'), dict):
        input_string = json.dumps(params.get('variables'))
    else:
        input_string = params.get('variables')

    for key in function_dictionary:
        if ( len(re.findall(key, input_string)) > 0 ):
            input_string = input_string.replace( '{'+key+'}', str(function_dictionary[key](params)) )

    if isinstance(params.get('variables'), dict):
        return json.loads(input_string)
    else:
        return input_string

def get_fg_mgmt_ip(params):
    return "10.200.3.1"

def get_fg_dev_name(params):
    return "FortiGate-Edge"

def get_asset_ip(params=None):
    return "10.200.3."+str(random.randint(2, 24))

def get_random_integer(params):
    return random.randint(start, end)

def get_my_public_ip(params):
    try:
        response = requests.get(url='https://api.ipify.org/?format=txt')
        if response.status_code != 200:
            logger.error('Public IP lookup Failed')
            raise ConnectorError('Public IP lookup Failed')
        public_ip=str(response.content, 'utf-8')
        return '.'.join(public_ip.split('.')[:-1])+'.'+str(random.randint(2, 253))

    except requests.ConnectionError:
        logger.error("Public IP Lookup - Connection error")
        raise ConnectorError("Public IP Lookup - Connection error")
    except requests.ConnectTimeout:
        logger.error("Public IP Lookup - Connection timeout")
        raise ConnectorError("Public IP Lookup - Connection timeout")

def get_username(params):
    usernames=['Sun.Tzu','Albert.Einstein','Isaac.Newton','Leonardo.Da.Vinci','Aristotle','Galileo.Galilei','Alexander.the.Great','Charles.Darwin','Plato','William.Shakespeare','Martin.Luther.Kin','Socrates','Mahatma.Gandhi','Abraham.Lincoln','George.Washington','Mose','Nikola.Tesla','Gautama.Buddha','Julius.Ceasar','Karl.Marx','Martin.Luther','Napoleon.Bonaparte','Johannes.Gutenberg']
    return random.choices(usernames)[0]

def get_time_now(params):
    return arrow.utcnow().format('YYYY-MM-DD HH:mm')

def get_time_past(params):
    return arrow.utcnow().shift(hours=-(random.randint(86400, 172800))).format('YYYY-MM-DD HH:mm')

def get_time_minus_one(params):
    return arrow.utcnow().shift(minutes=-(random.randint(3400, 3800))).format('YYYY-MM-DD HH:mm')

def get_time_minus_two(params):
    return arrow.utcnow().shift(minutes=-(random.randint(7200, 86400))).format('YYYY-MM-DD HH:mm')

def get_time_minus_three(params):
    return arrow.utcnow().shift(minutes=-(random.randint(10800, 11000))).format('YYYY-MM-DD HH:mm')

def get_time_minus_four(params):
    return arrow.utcnow().shift(minutes=-(random.randint(14400, 14600))).format('YYYY-MM-DD HH:mm')

def get_time_minus_five(params):
    return arrow.utcnow().shift(minutes=-(random.randint(18000, 18300))).format('YYYY-MM-DD HH:mm')

def get_time_minus_six(params):
    return arrow.utcnow().shift(minutes=-(random.randint(21600, 21900))).format('YYYY-MM-DD HH:mm')

def _check_health():
    return True

operations = {
    'bad_ip': bad_ip,
    'bad_url': bad_url,
    'bad_filehash': bad_filehash,
    'bad_domain': bad_domain,
    'replace_variables': replace_variables
}
function_dictionary={
    "TR_MALICIOUS_IP": bad_ip,
    "TR_MALICIOUS_DOMAIN": bad_domain,
    "TR_MALICIOUS_URL": bad_url,
    "TR_MALICIOUS_HASH": bad_filehash,
    "TR_FG_MGMT_IP": get_fg_mgmt_ip,
    "TR_FG_DEV_NAME": get_fg_dev_name,
    "TR_ASSET_IP": get_asset_ip,
    "TR_RANDOM_INTEGER": get_random_integer,
    "TR_PUBLIC_IP": get_my_public_ip,
    "TR_USERNAME": get_username,
    "TR_NOW": get_time_now,
    "TR_PAST": get_time_past,
    "TR_T-1": get_time_minus_one,
    "TR_T-2": get_time_minus_two,
    "TR_T-3": get_time_minus_three,
    "TR_T-4": get_time_minus_four,
    "TR_T-5": get_time_minus_five,
    "TR_T-6": get_time_minus_six
}
