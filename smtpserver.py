#!/root/smtpserver/bin/python3
"""A SMTP Server intended to process outbound alert
    from vROps Standard Email Plug-In"""
import argparse
import asyncio
import base64
import collections
import configparser
import email
import json
import locale
import logging
from logging.handlers import RotatingFileHandler
import quopri
import re
import time
from ast import literal_eval
from aiosmtpd.controller import Controller
from bs4 import BeautifulSoup
from requests.packages import urllib3
import requests

# Parse arguments
ARGPARSER = argparse.ArgumentParser()
ARGPARSER.add_argument('--loglevel', choices=('DEBUG', 'INFO'), default='INFO', help='Set a logging level')
ARGS = ARGPARSER.parse_args()

# Setup logging
logger = logging.getLogger('smtpserver')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(module)s %(message)s')
rfh = RotatingFileHandler('smtpserver.log', mode='a', maxBytes=10240000, backupCount=5, encoding='utf8', delay=False)
rfh.setLevel(ARGS.loglevel)
rfh.setFormatter(formatter)
logger.addHandler(rfh)
sh = logging.StreamHandler()
sh.setLevel(ARGS.loglevel)
sh.setFormatter(formatter)
logger.addHandler(sh)

# Reading configuration file
SMTPSERVER_CFG = configparser.ConfigParser()
SMTPSERVER_CFG.read('smtpserver.cfg', encoding='utf8')
logger.info('SMTPServer configuration file loaded: %s', 'smtpserver.cfg')

# Reading localization resource file if needed
LOCALIZE = True \
    if SMTPSERVER_CFG['Parser']['LANGUAGE'] in ('zh-TW', 'zh-CN', 'ko', 'ja', 'fr', 'de', 'es') \
    else False

if LOCALIZE is True:
    LOCALIZATION_RESOURCE_FILE = 'resources_%s.cfg' % SMTPSERVER_CFG['Parser']['LANGUAGE']
    LOCALIZATION_RESOURCE = configparser.ConfigParser()
    LOCALIZATION_RESOURCE.read(LOCALIZATION_RESOURCE_FILE, encoding='utf8')
    logger.info('Localization resource file loaded: %s', LOCALIZATION_RESOURCE_FILE)

# Define constants
RESOURCE_STATE = {'0.0': 'None', '1.0': 'Information', '2.0': 'Warning', '3.0': 'Immediate', '4.0': 'Critical'}
CRITICALITY = {'None': 0, 'Information': 1, 'Warning': 2, 'Immediate': 3, 'Critical': 4}
CRITICALITY_COLOR = {
    'None': '#cecece',
    'Information': '#cecece',
    'Warning': '#e5c446',
    'Immediate': '#e17600',
    'Critical': '#bb1e24'
}
STATE = {'Generated': '0', 'Updated': '0', 'Canceled': '1'}
COMPANY_PREFIX = '^%s' % literal_eval(SMTPSERVER_CFG['Parser']['COMPANY_PREFIX'])
VROPS_API_ENDPOINT = SMTPSERVER_CFG['vROps']['API_ENDPOINT']
VROPS_VERIFY_CERT = SMTPSERVER_CFG.getboolean('vROps', 'VERIFY_CERT')
VROPS_REQUEST_TIMEOUT = SMTPSERVER_CFG.getint('vROps', 'REQUEST_TIMEOUT')
SLACK_VERIFY_CERT = SMTPSERVER_CFG.getboolean('Slack', 'VERIFY_CERT')
SLACK_REQUEST_TIMEOUT = SMTPSERVER_CFG.getint('Slack', 'REQUEST_TIMEOUT')

# Disable insecure request warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_vrops_auth_token():
    """Get vROps REST API authorization otken"""
    url = VROPS_API_ENDPOINT + '/auth/token/acquire'
    request_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Accept-Language': SMTPSERVER_CFG['Parser']['LANGUAGE'],
        'X-vRealizeOps-API-use-unsupported': 'True'
    }
    data = {
        'username': SMTPSERVER_CFG['vROps']['API_USER'],
        'authSource': 'local',
        'password': SMTPSERVER_CFG['vROps']['API_PASSWORD'],
        'others': None,
        'otherAttributes': {}
    }

    logger.debug('get_vrops_auth_token() Getting vROps authorization token from: %s', url)
    req = requests.post(
        url,
        data=json.dumps(data),
        headers=request_headers,
        verify=VROPS_VERIFY_CERT,
        timeout=VROPS_REQUEST_TIMEOUT
    )
    auth_token = req.json()
    logger.debug('get_vrops_auth_token() Authorization token: %s', auth_token)

    if req.status_code == 200:
        return auth_token


TOKEN = get_vrops_auth_token()


def call_vrops_rest_api(request_url, request_type, data=None):
    """Execute vROps REST API call"""

    global TOKEN

    # Check if authorization token is valid
    if time.time() > (TOKEN['validity'] / 1000):
        TOKEN = get_vrops_auth_token()

    request_headers = {
        'Accept': 'application/json',
        'Accept-Language': SMTPSERVER_CFG['Parser']['LANGUAGE'],
        'X-vRealizeOps-API-use-unsupported': 'True',
        'Authorization': 'vRealizeOpsToken ' + TOKEN['token']
    }

    # Send a HTTP request
    if request_type == 'get':
        req = requests.get(
            request_url,
            headers=request_headers,
            verify=VROPS_VERIFY_CERT,
            timeout=VROPS_REQUEST_TIMEOUT
        )
    elif request_type == 'post':
        request_headers['Content-Type'] = 'application/json'
        req = requests.post(
            request_url,
            headers=request_headers,
            data=json.dumps(data),
            verify=VROPS_VERIFY_CERT,
            timeout=VROPS_REQUEST_TIMEOUT
        )
    elif request_type == 'put':
        request_headers['Content-Type'] = 'application/json'
        req = requests.put(
            request_url,
            headers=request_headers,
            data=json.dumps(data),
            verify=VROPS_VERIFY_CERT,
            timeout=VROPS_REQUEST_TIMEOUT
        )

    if req.status_code == 200:
        return req


def get_localized_str(field_name, src_string, is_raw=False):
    """Localize given string referring to the configuration file (translation.cfg)"""

    if LOCALIZE is True:
        try:
            return LOCALIZATION_RESOURCE.get(field_name, src_string, raw=is_raw)
        except configparser.NoOptionError as exception:
            logger.debug('get_localized_str() configparser.NoOptionError in get_localized_str: %s', exception)
            return src_string
    else:
        return src_string


def get_symptom_definition_summary(alert_id):
    """Get symptom definitions consist an alert to find out the criticality for each of anomalies"""

    # Get a vROps alert definition using an alert ID
    url = VROPS_API_ENDPOINT + '/alerts/' + alert_id
    logger.debug('get_symptom_definition_summary() Fetching alert detail from: %s', url)
    req = call_vrops_rest_api(url, 'get')
    alert_definition_id = req.json()['alertDefinitionId']
    logger.debug('get_symptom_definition_summary() alert_definition_id: %s', alert_definition_id)

    url = VROPS_API_ENDPOINT + '/alertdefinitions/' + alert_definition_id
    logger.debug('get_symptom_definition_summary() Fetching alert definition from: %s', url)
    req = call_vrops_rest_api(url, 'get')
    alert_definition = req.json()
    logger.debug('get_symptom_definition_summary() alert_definition:\n%s\n', alert_definition)

    # Create a list of symptom definitions from the alert definition
    if alert_definition['states'][0]['base-symptom-set']['type'] == 'SYMPTOM_SET':
        symptom_sets = [alert_definition['states'][0]['base-symptom-set']]
    elif alert_definition['states'][0]['base-symptom-set']['type'] == 'SYMPTOM_SET_COMPOSITE':
        symptom_sets = alert_definition['states'][0]['base-symptom-set']['symptom-sets']
    logger.debug('get_symptom_definition_summary() symptom_sets:\n%s\n', symptom_sets)

    symptom_definition_ids = [
        re.sub('^!', '', symptom_definition_id) for symptom_set in symptom_sets
        for symptom_definition_id in symptom_set['symptomDefinitionIds']
    ]  # 'does not have' symptoms
    symptom_definition_ids = sorted(set(symptom_definition_ids))
    logger.debug('get_symptom_definition_summary() symptom_definition_ids:\n%s\n', symptom_definition_ids)

    url = VROPS_API_ENDPOINT + '/symptomdefinitions/' + '?id=' + '&id='.join(symptom_definition_ids)
    req = call_vrops_rest_api(url, 'get')
    symptom_definitions = req.json()['symptomDefinitions']
    logger.debug('get_symptom_definition_summary() symptom_definitions:\n%s\n', symptom_definitions)

    # Create symptom definition summary using symptom type/name/severity/key fields
    symptom_definition_summary = []
    for symptom_definition in symptom_definitions:
        condition_type = symptom_definition['state']['condition']['type']
        if condition_type in ('CONDITION_HT', 'CONDITION_HT_SUPER', 'CONDITION_DT', 'CONDITION_DT_SUPER'):
            symptom_definition_summary.append({
                "name": symptom_definition['name'],
                "adapterKindKey": symptom_definition['adapterKindKey'],
                "resourceKindKey": symptom_definition['resourceKindKey'],
                "severity": symptom_definition['state']['severity'],
                "type": condition_type,
                "key": symptom_definition['state']['condition']['key'],
                "instanced": symptom_definition['state']['condition']['instanced']})
        elif condition_type in ('CONDITION_PROPERTY_STRING', 'CONDITION_PROPERTY_NUMERIC'):
            symptom_definition_summary.append({
                "name": symptom_definition['name'],
                "adapterKindKey": symptom_definition['adapterKindKey'],
                "resourceKindKey": symptom_definition['resourceKindKey'],
                "severity": symptom_definition['state']['severity'],
                "type": condition_type,
                "key": symptom_definition['state']['condition']['key'],
                "instanced": None})
        elif condition_type in ('CONDITION_MESSAGE_EVENT', 'CONDITION_FAULT'):
            symptom_definition_summary.append({
                "name": symptom_definition['name'],
                "adapterKindKey": symptom_definition['adapterKindKey'],
                "resourceKindKey": symptom_definition['resourceKindKey'],
                "severity": symptom_definition['state']['severity'],
                "type": condition_type,
                "key": None,
                "instanced": None})

    logger.debug('get_symptom_definition_summary() symptom_definition_summary:\n%s\n', symptom_definition_summary)

    return symptom_definition_summary


def get_localized_metric(metric, symptom_def):
    """Returns 1. localized metric name and 2. statkey which can be used to fetch resource statistics"""

    if metric is not None:
        # Non-instanced metric
        if symptom_def['instanced'] is False:
            localized_metric = get_localized_str('METRIC', metric, is_raw=True)
            statkey = symptom_def['key']
        # Instanced metric
        else:
            # Search for the instance name and the location
            index = 0
            for item in metric.split('|'):
                instance = re.findall(r':(.*?)$', item)
                if len(instance) is not 0:
                    instance_name = instance[0]
                    instance_index = index
                    break
                index += 1

            stripped_metric = re.sub(r':.*?(?=\|)', '', metric)  # Strip instance name from the metric
            localized_metric = get_localized_str('METRIC', stripped_metric, is_raw=True)
            localized_metric = re.sub(r'\|InstanceName\|', '|%s|' % instance_name, localized_metric)
            statkey_list = symptom_def['key'].split('|')
            statkey_list[instance_index] = '%s:%s' % (statkey_list[instance_index], instance_name)
            statkey = '|'.join(statkey_list)
    else:
        localized_metric = get_localized_str('METRIC', 'None', is_raw=True)
        statkey = symptom_def['key']

    logger.debug('get_localized_metric() Localized metric: %s => %s', metric, localized_metric)
    logger.debug('get_localized_metric() statkey: %s', statkey)
    return {'localized_metric': localized_metric, 'statkey': statkey}


def guess_str_length(string):
    """Guess length of a unicode string (treat non-ascii characters in unicode as 2)"""

    length = 0
    for char in string:
        length = length + 2 if len(char.encode('utf8')) == 3 else length + 1
    return length


class MyHandler:
    """SMTP Server Class"""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """RCPT Handler which accepts mails from a specific domain only"""

        if not address.endswith('@%s' % SMTPSERVER_CFG['Server']['ACCEPTED_SENDER_DOMAIN']):
            logger.warning('Relay denied to %s', address)
            return '550 not relaying to that domain'
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        """Implementation of the DATA Handler"""

        # Ignore messages if the server is running in SINKHOLE mode
        if SMTPSERVER_CFG['Server'].getboolean('SINKHOLE') is True:
            logger.info('Message Dropped: Running in sinkhole mode')
            return '250 Message accepted for delivery'

        # Decode E-Mail body
        msg = email.message_from_bytes(envelope.content)
        content_transfer_encoding = msg.get('Content-Transfer-Encoding')
        msg_payload = msg.get_payload()
        if content_transfer_encoding == 'base64':
            content = base64.b64decode(msg_payload).decode('utf8')
        elif content_transfer_encoding == 'quoted-printable':
            content = quopri.decodestring(msg_payload).decode('utf8')

        # Ignore messages if their FILTER_RULE_NAME are not configured (OUTBOUND_ALERT_RULE_NAME)
        if content.find('FILTER_RULE_NAME: %s' % SMTPSERVER_CFG['Server']['OUTBOUND_ALERT_RULE_NAME']) == -1:
            logger.info('Message Dropped: OUTBOUND_ALERT_RULE does not match')
            return '250 Message accepted for delivery'

        logger.debug('Email Message (RAW):\n%s\n', msg)
        logger.debug('Email Content (Decoded):\n%s\n', content)

        # Parse HTML body of E-Mail and extract alert details
        soup = BeautifulSoup(content, 'html.parser')
        spans = soup.find_all(SMTPSERVER_CFG['Parser']['DELIMITER_TAG'])

        # alert = {}
        alert = collections.OrderedDict()
        alert['ALERT_STATUS'] = (spans[0].text.split(': '))[1]
        alert['ALERT_IMPACT'] = (spans[1].text.split(': '))[1]
        alert['ALERT_CRITICALITY'] = (spans[2].text.split(': '))[2]
        alert['ALERT_DEFINITION_NAME'] = re.sub(COMPANY_PREFIX, '', (spans[3].text.split(': '))[1])
        alert['ALERT_ID'] = (spans[4].text.split(': '))[1]
        alert['ALERT_OWNER'] = (spans[5].text.split(': '))[1]
        alert['ALERT_DEFINITION_DESC'] = (spans[6].text.split(': '))[1]
        alert['AFFECTED_RESOURCE_NAME'] = (spans[7].text.split(': '))[1]
        alert['AFFECTED_RESOURCE_KIND'] = (spans[8].text.split(': '))[1]
        alert['ALERT_GENERATE_TIME'] = (spans[9].text.split(': '))[1]
        alert['ALERT_UPDATE_TIME'] = (spans[10].text.split(': '))[1]
        alert['ALERT_CANCEL_TIME'] = (spans[11].text.split(': '))[1]
        alert['ANOMALIES'] = spans[12]
        alert['ALERT_TYPE'] = (spans[13].text.split(': '))[1]
        alert['ALERT_SUBTYPE'] = (spans[14].text.split(': '))[1]
        alert['CHILDREN_HEALTH'] = (spans[15].text.split(': '))[1]
        alert['PARENT_HEALTH'] = (spans[16].text.split(': '))[1]
        alert['FILTER_RULE_NAME'] = (spans[17].text.split(': '))[1]
        alert['FILTER_RULE_DESC'] = (spans[18].text.split(': '))[1]
        alert['ALERT_SUMMARY_LINK'] = (spans[19].text.split(': '))[1]
        alert['ALERT_RECOMMENDATION'] = spans[20]
        alert['RESOURCE_HEALTH_STATE'] = (spans[21].text.split(': '))[1]
        alert['RESOURCE_RISK_STATE'] = (spans[22].text.split(': '))[1]
        alert['RESOURCE_EFFICIENCY_STATE'] = (spans[23].text.split(': '))[1]

        # Translate alert details
        alert['ALERT_STATUS_TR'] = get_localized_str('ALERT_STATUS', alert['ALERT_STATUS'])
        alert['ALERT_IMPACT_TR'] = get_localized_str('ALERT_IMPACT', alert['ALERT_IMPACT'])
        alert['ALERT_CRITICALITY_TR'] = get_localized_str('ALERT_CRITICALITY', alert['ALERT_CRITICALITY'])
        alert['ALERT_OWNER_TR'] = alert['ALERT_OWNER'] if alert['ALERT_OWNER'] != 'Unable to retrieve value' else get_localized_str('ALERT_OWNER', 'None')
        alert['AFFECTED_RESOURCE_KIND_TR'] = get_localized_str('AFFECTED_RESOURCE_KIND', alert['AFFECTED_RESOURCE_KIND'])

        locale.setlocale(0, '')  # Windows Python 3 time.strftime() bug workaround
        if alert['ALERT_STATUS'] == 'Generated':
            alert['ALERT_GENERATE_TIME_TR'] = time.strftime(
                '%m-%d %H:%M %Z',
                time.localtime(time.mktime(email.utils.parsedate(alert['ALERT_GENERATE_TIME'])))
            )
            alert['ALERT_UPDATE_TIME_TR'] = '-'
            alert['ALERT_CANCEL_TIME_TR'] = '-'

        if alert['ALERT_STATUS'] == 'Updated':
            alert['ALERT_GENERATE_TIME_TR'] = time.strftime(
                '%m-%d %H:%M %Z',
                time.localtime(time.mktime(email.utils.parsedate(alert['ALERT_GENERATE_TIME'])))
            )
            alert['ALERT_UPDATE_TIME_TR'] = time.strftime(
                '%m-%d %H:%M %Z',
                time.localtime(time.mktime(email.utils.parsedate(alert['ALERT_UPDATE_TIME'])))
            )
            alert['ALERT_CANCEL_TIME_TR'] = '-'

        if alert['ALERT_STATUS'] == 'Canceled':
            alert['ALERT_GENERATE_TIME_TR'] = time.strftime(
                '%m-%d %H:%M %Z',
                time.localtime(time.mktime(email.utils.parsedate(alert['ALERT_GENERATE_TIME'])))
            )
            if alert['ALERT_UPDATE_TIME'] == alert['ALERT_GENERATE_TIME']:
                alert['ALERT_UPDATE_TIME_TR'] = '-'
            else:
                alert['ALERT_UPDATE_TIME_TR'] = time.strftime(
                    '%m-%d %H:%M %Z',
                    time.localtime(time.mktime(email.utils.parsedate(alert['ALERT_UPDATE_TIME'])))
                )
            alert['ALERT_CANCEL_TIME_TR'] = time.strftime(
                '%m-%d %H:%M %Z',
                time.localtime(time.mktime(email.utils.parsedate(alert['ALERT_CANCEL_TIME'])))
            )

        alert['ALERT_TYPE_TR'] = get_localized_str('ALERT_TYPE', alert['ALERT_TYPE'])
        alert['ALERT_SUBTYPE_TR'] = get_localized_str('ALERT_SUBTYPE', alert['ALERT_SUBTYPE'])
        alert['RESOURCE_HEALTH_STATE_TR'] = get_localized_str('ALERT_CRITICALITY', RESOURCE_STATE[alert['RESOURCE_HEALTH_STATE']])
        alert['RESOURCE_RISK_STATE_TR'] = get_localized_str('ALERT_CRITICALITY', RESOURCE_STATE[alert['RESOURCE_RISK_STATE']])
        alert['RESOURCE_EFFICIENCY_STATE_TR'] = get_localized_str('ALERT_CRITICALITY', RESOURCE_STATE[alert['RESOURCE_EFFICIENCY_STATE']])

        # Anomalies
        # Convert anomalies from HTML tables to an array of dicts
        anomalies = []
        for symptom_index, table in enumerate(alert['ANOMALIES'].find_all('table'), 1):
            relation = re.findall(r'^(ANOMALIES: )?SYMPTOM SET - (.*)$', table.previous.previous)
            relation = relation[0][1] if relation else 'Error'
            headers = [header.string for header in table.find_all('th')]
            symptom_subindex = 1
            for row in table.find_all('tr'):
                anomaly = {'Relation': relation, 'Symptom Index': '%d-%d' % (symptom_index, symptom_subindex)}
                for header_index, td_cell in enumerate(row.find_all('td')):
                    anomaly[headers[header_index]] = td_cell.string
                anomalies.append(anomaly)
                symptom_subindex += 1
        logger.debug('Anomalies:\n%s\n', anomalies)

        # Translate metric name and add symptom criticality, metric key for each anomalies
        symptom_definition_summary = get_symptom_definition_summary(alert['ALERT_ID'])
        anomalies_tr = []
        for anomaly in anomalies:
            # Search for a symptom definition which has the same 'name' as 'Symptom Name' of each anomaly
            is_matching_symptom_name_found = False
            for symptom_definition in symptom_definition_summary:
                if anomaly['Symptom Name'] == symptom_definition['name']:
                    is_matching_symptom_name_found = True
                    metric = get_localized_metric(anomaly['Metric'], symptom_definition)
                    anomaly['Metric'] = metric['localized_metric']
                    anomaly['StatKey'] = metric['statkey']
                    anomaly['Criticality'] = symptom_definition['severity'].capitalize() \
                        if symptom_definition['severity'] != 'AUTO' else alert['ALERT_CRITICALITY']
                    break
            if is_matching_symptom_name_found is False:  # For All Adapter/Object Types related vROps outbound adapter bug
                anomaly['StatKey'] = anomaly['Metric']  # Cannot determine valid statkey in this case
                anomaly['Metric'] = get_localized_str('METRIC', anomaly['Metric'], is_raw=True)
                anomaly['Criticality'] = alert['ALERT_CRITICALITY']  # Cannot determine valid criticality, too

            anomaly['Symptom Name'] = re.sub(COMPANY_PREFIX, '', anomaly['Symptom Name'])

            if anomalies_tr.count(anomaly) == 0:  # Deduplication of anomalies
                anomalies_tr.append(anomaly)

        alert['ANOMALIES_TR'] = anomalies_tr

        # Recommendations
        # Convert recommendations to an array of strings
        recommendations = []
        if alert['ALERT_RECOMMENDATION'] == '':
            recommendations.append(get_localized_str('LABEL', 'No Recommendations'))
        else:
            recommendations_strings = alert['ALERT_RECOMMENDATION'].find_all(string=True)
            recommendations_strings.remove('ALERT_RECOMMENDATION: ')
            for recommendation in recommendations_strings:
                if re.match('^- ', recommendation):
                    recommendations.append(re.sub(r'^- ', '', recommendation))
                else:
                    recommendations[-1] += '\n%s' % recommendation
        alert['ALERT_RECOMMENDATION_TR'] = recommendations

        alert_log = ''
        for item in alert:
            alert_log += '%s: %s\n' % (item, alert[item])
        logger.debug('Parsed Alert:\n%s\n', alert_log)

        # Generating JSON Payload for Slack
        # Alert Summary
        slack_msg = {}
        if alert['ALERT_STATUS'] != 'Canceled':
            slack_msg['text'] = '[ %s ⁞ %s ] %s ‒ %s' % (alert['ALERT_STATUS_TR'], alert['ALERT_CRITICALITY_TR'], alert['AFFECTED_RESOURCE_NAME'], alert['ALERT_DEFINITION_NAME'])
        else:
            slack_msg['text'] = '[ %s ] %s ‒ %s' % (alert['ALERT_STATUS_TR'], alert['AFFECTED_RESOURCE_NAME'], alert['ALERT_DEFINITION_NAME'])
        slack_msg['icon_url'] = SMTPSERVER_CFG['Slack']['ICON_URL']
        slack_msg['username'] = SMTPSERVER_CFG['Slack']['MSG_USERNAME']
        slack_msg['mrkdown'] = True
        slack_msg['attachments'] = []
        slack_msg['attachments'].append({
            'color': CRITICALITY_COLOR[alert['ALERT_CRITICALITY']] if alert['ALERT_STATUS'] != 'Canceled' else CRITICALITY_COLOR['None'],
            'text': alert['ALERT_DEFINITION_DESC'],
            'mrkdwn_in': ['title', 'text', 'pretext'],
            'thumb_url': '%s/images/alert/square_75x75_%s_%s.png' % (SMTPSERVER_CFG['Slack']['IMAGE_HOST'], alert['ALERT_IMPACT'].lower(), CRITICALITY[alert['ALERT_CRITICALITY']] if alert['ALERT_STATUS'] != 'Canceled' else CRITICALITY['None'])
        })

        # Alert Details
        slack_msg['attachments'].append({
            'author_name': '%s ‒ %s' % (get_localized_str('LABEL', 'Status'), alert['ALERT_STATUS_TR']),
            'author_link': '',
            'author_icon': '%s/images/alertstatuses/alertStatus_%s.png' % (SMTPSERVER_CFG['Slack']['IMAGE_HOST'], STATE[alert['ALERT_STATUS']]),
            'mrkdwn_in': ['title', 'text', 'pretext'],
            'fields': [
                {'title': alert['AFFECTED_RESOURCE_NAME'], 'value': '(%s)' % alert['AFFECTED_RESOURCE_KIND_TR'], 'short': False},
                {'title': '', 'value': '', 'short': False},
                {'title': '» %s' % get_localized_str('LABEL', 'Alert Type'), 'value': (' %s' % alert['ALERT_TYPE_TR']), 'short': True},
                {'title': '» %s' % get_localized_str('LABEL', 'Start Time'), 'value': (' %s' % alert['ALERT_GENERATE_TIME_TR']), 'short': True},
                {'title': '» %s' % get_localized_str('LABEL', 'Alert Subtype'), 'value': (' %s' % alert['ALERT_SUBTYPE_TR']), 'short': True},
                {'title': '» %s' % get_localized_str('LABEL', 'Update Time'), 'value': (' %s' % alert['ALERT_UPDATE_TIME_TR']), 'short': True},
                {'title': '» %s' % get_localized_str('LABEL', 'Assigned To'), 'value': (' %s' % alert['ALERT_OWNER_TR']), 'short': True},
                {'title': '» %s' % get_localized_str('LABEL', 'Cancel Time'), 'value': (' %s' % alert['ALERT_CANCEL_TIME_TR']), 'short': True}
            ],
            'footer': 'ID ‒ %s' % alert['ALERT_ID']
        })

        # Symptoms
        for anomaly in alert['ANOMALIES_TR']:
            # Process Message Info
            message_info = anomaly['Message Info'].split(' ')
            if len(message_info) == 3 and \
                (re.match(r'^\d+\.\d+$', message_info[0]) or re.match(r'^\d+\.\d+E\d+$', message_info[0])) and \
                (re.match(r'^\d+\.\d+$', message_info[2]) or re.match(r'^\d+\.\d+E\D+$', message_info[2])):
                for i in (0, 2):
                    if re.match(r'^\d+\.\d+E\d+$', message_info[i]):
                        value = message_info[i].split('E')
                        message_info[i] = float(value[0]) * pow(10, int(value[1]))
                        if message_info[i] > 999999:
                            message_info[i] = '∞'
                    else:
                        message_info[i] = '{:.2f}'.format(float(message_info[i]))
                message_info[1] = re.sub('^<=$', '≤', message_info[1])
                message_info[1] = re.sub('^>=$', '≥', message_info[1])
                message_info[1] = re.sub('^above$', 'ᴰᵀꜛ', message_info[1])
                message_info[1] = re.sub('^below$', 'ᴰᵀꜜ', message_info[1])
                message_info[1] = re.sub('^abnormal$', 'ᴰᵀꜝ', message_info[1])
            message_info = ' '.join(message_info)

            object_name = '[SELF]' if anomaly['Relation'] == 'self' \
                else '%s [%s]' % (anomaly['Object Name'], anomaly['Relation'])

            is_message_info_short = False if (guess_str_length(object_name) > 20) or (guess_str_length(message_info) > 20) \
                else True

            slack_msg['attachments'].append({
                'author_name': '%s' % anomaly['Metric'],
                'author_link': '%s/quickstat/%s' % (SMTPSERVER_CFG['Slack']['EXTERNAL_URL'], anomaly['Object ID']),
                'author_icon': '%s/images/criticalityLevel/criticalityLevel_%s.png' % (SMTPSERVER_CFG['Slack']['IMAGE_HOST'], CRITICALITY[anomaly['Criticality']]),
                'title': '*%s%s* %s' % (get_localized_str('LABEL', 'Symptoms'), anomaly['Symptom Index'], anomaly['Symptom Name']),
                'mrkdwn_in': ['title', 'text', 'pretext'],
                'fields': [
                    {
                        'title': '» %s' % get_localized_str('LABEL', 'Triggered On'),
                        'value': ' _%s_' % object_name,
                        'short': is_message_info_short
                    },
                    {
                        'title': '» %s' % get_localized_str('LABEL', 'Message'),
                        'value': ' %s' % message_info,
                        'short': is_message_info_short
                    },
                ]
            })

        # Recommendations
        if alert['ALERT_STATUS'] != 'Canceled':
            if recommendations:
                fields = [{'title': '', 'value': '∙ %s' % recommendation, 'short': False} for recommendation in recommendations]
            else:
                fields = [{'title': '', 'value': get_localized_str('LABEL', 'No Recommendations'), 'short': False}]

            slack_msg['attachments'].append({
                'title': '%s' % get_localized_str('LABEL', 'Recommendations'),
                'fields': fields
            })

        req = requests.post(
            SMTPSERVER_CFG['Slack']['WEBHOOK_URL'],
            data=json.dumps(slack_msg, ensure_ascii=False).encode('utf-8'),
            headers={'Accept': 'application/json'},
            verify=SLACK_VERIFY_CERT,
            timeout=SLACK_REQUEST_TIMEOUT
        )

        if req.status_code == 200:
            return '250 Message accepted for delivery'


async def amain(loop):
    """Instantiate a controller which runs the SMTP server in a separate thread with a dedicated event loop"""

    controller = Controller(MyHandler(), hostname=SMTPSERVER_CFG['Server']['BINDADDR'], port=SMTPSERVER_CFG['Server']['BINDPORT'])
    controller.start()

if __name__ == '__main__':
    EVENT_LOOP = asyncio.get_event_loop()
    logger.info('Listening vROps alert messages on %s', (SMTPSERVER_CFG['Server']['BINDADDR'] + ':' + SMTPSERVER_CFG['Server']['BINDPORT']))
    EVENT_LOOP.create_task(amain(loop=EVENT_LOOP))

    try:
        EVENT_LOOP.run_forever()
    except KeyboardInterrupt:
        pass
