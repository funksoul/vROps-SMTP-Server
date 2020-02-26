from ast import literal_eval
import configparser
import argparse
import re
import requests
from requests.packages import urllib3

SMTPSERVER_CFG = configparser.ConfigParser()
SMTPSERVER_CFG.read('smtpserver.cfg', encoding='utf8')
VROPS_REQUEST_HEADERS = literal_eval(SMTPSERVER_CFG['vROps']['REQUEST_HEADERS'])

INSTANCED_METRICS_CFG = configparser.RawConfigParser()
INSTANCED_METRICS_CFG.optionxform = lambda option: option
INSTANCED_METRICS_CONFIG_FILE = SMTPSERVER_CFG['Parser']['INSTANCED_METRICS_CONFIG_FILE']

# Disable insecure request warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get vROps adapter kinds
req = requests.get(SMTPSERVER_CFG['vROps']['API_ENDPOINT'] + '/adapterkinds', auth=(SMTPSERVER_CFG['vROps']['API_USER'], SMTPSERVER_CFG['vROps']['API_PASSWORD']), verify=False, headers=VROPS_REQUEST_HEADERS, timeout=int(SMTPSERVER_CFG['vROps']['REQUEST_TIMEOUT']))
adapter_kinds = req.json()

# Get vROps resource kinds of each adapter kinds
for adapter_kind in adapter_kinds['adapter-kind']:
    # And get the first resource of each resource kinds
    for resource_kind in adapter_kind['resourceKinds']:
        req = requests.get(SMTPSERVER_CFG['vROps']['API_ENDPOINT'] + '/adapterkinds/' + adapter_kind['key'] + '/resourcekinds/' + resource_kind + '/resources?pageSize=1&page=0', auth=(SMTPSERVER_CFG['vROps']['API_USER'], SMTPSERVER_CFG['vROps']['API_PASSWORD']), verify=False, headers=VROPS_REQUEST_HEADERS, timeout=int(SMTPSERVER_CFG['vROps']['REQUEST_TIMEOUT']))
        resources = req.json()
        # Get stat keys of the resource
        if resources['pageInfo']['totalCount'] > 0:
            for link in resources['resourceList'][0]['links']:
                if link['name'] == 'statKeysOfResource':
                    req = requests.get(re.sub(r'/suite-api/api$', '', SMTPSERVER_CFG['vROps']['API_ENDPOINT']) + link['href'], auth=(SMTPSERVER_CFG['vROps']['API_USER'], SMTPSERVER_CFG['vROps']['API_PASSWORD']), verify=False, headers=VROPS_REQUEST_HEADERS, timeout=int(SMTPSERVER_CFG['vROps']['REQUEST_TIMEOUT']))
                    stat_keys = req.json()
                    # Build a list of the instanced metrics
                    instanced_metrics = []
                    for stat_key in stat_keys['stat-key']:
                        is_instanced_metric = False
                        key = stat_key['key'].split('|')
                        for index in range(0, len(key)):
                            if key[index].find(':') > 0: # Instanced metrics contain ':instance_name' in their name
                                key[index] = re.sub(r':.*$', '', key[index]) # remove :instance_name to get pure stat key
                                is_instanced_metric = True
                        if is_instanced_metric is True:
                            instanced_metrics.append('|'.join(key))
                    instanced_metrics = sorted(set(instanced_metrics))
                    if instanced_metrics != []:
                        try:
                            INSTANCED_METRICS_CFG[adapter_kind['key']][resource_kind] = str(instanced_metrics)
                        except KeyError:
                            INSTANCED_METRICS_CFG[adapter_kind['key']] = {}
                            INSTANCED_METRICS_CFG[adapter_kind['key']][resource_kind] = str(instanced_metrics)

with open(INSTANCED_METRICS_CONFIG_FILE, 'w') as configfile:
    INSTANCED_METRICS_CFG.write(configfile)
