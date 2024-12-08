"""This module enables discovering local overrides and configurations on Panorama-managed
firewalls
usage: palo_override_finder.py [-h] [-v] [-c] [-r MAX_OPEN] [-k API_KEY] [-b BEARER_TOKEN] [-i IGNORE_XPATH]
                               [-t TARGET] [-d] [-o FILE_PATH]
                               [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}] panorama_or_scm"""
import sys
import re
import logging
import time
import argparse
import configparser
import os
import json
from threading import Thread
from datetime import datetime
from pathlib import Path
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from lxml import etree

SHOW_TEMPLATE = 'pushed-template'
SHOW_RUNNING = 'running'
XPATH_REGEX = re.compile(r'(^.*)(entry|member)(\[\d+])?(/.*|$)')
XPATH_SERIAL = '/response/result/devices/entry/serial/text()'
XPATH_HOSTNAME = '/response/result/devices/entry/hostname/text()'
XPATH_MGMT_IP = '/response/result/devices/entry/ip-address/text()'
CFG_FILENAME = 'palo_override_finder.cfg'
CONN_TIMEOUT = 30
SCM_KEYWORD = 'scm'  # Magic argument to switch to SCM mode
logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def resolve_xpath(xpa, tre):
    """Takes an input xpath string and specifies the name attribute where there are multiple
    elements with the same name based on a regex. The substitution is performed until the regex
    finds no matches.
    Input: /path/to/entry[1]/member[5]
    Output: /path/to/entry[@name='foo']/member[5]
    """
    resolved_xpath = xpa
    logging.debug('Expanding xpath %s', resolved_xpath)
    while True:
        entries = re.findall(XPATH_REGEX, resolved_xpath)
        logging.debug('Regex matches: %s', entries)
        if not entries:
            logging.debug('Done expanding xpath %s into %s', xpa, resolved_xpath)
            return resolved_xpath
        try:
            name_attribute = tre.xpath(str(entries[0][0]) + str(entries[0][1]) + str(entries[0][2]) + '/@name')
            logging.debug('Filling %s into xpath %s', name_attribute, xpa)
            if name_attribute:
                resolved_xpath = str(entries[0][0]) + str(entries[0][1]) + "[@name='" +\
                                 name_attribute[0] + "']" + str(entries[0][3])
            else:
                # Found "entry" element with no "name" attribute so add [not(@name)] so
                # that the regex skips it next time
                resolved_xpath = str(entries[0][0]) + str(entries[0][1]) + '[not(@name)]' +\
                                 str(entries[0][3])
        except IndexError:
            logging.critical('Regex found wrong number of matches.\nRegex: %s\nStarting Xpath: %s\n'
                             'Xpath: %s\nMatches: %s', XPATH_REGEX, xpa, resolved_xpath, entries)
            raise


def connected_fw_list(endpoint, session):
    """Queries Panorama/SCM and outputs a dictionary in the format
    {'fw_serial': ('mgmt_ip', 'hostname')}"""
    try:
        logging.info('Getting fw list from Panorama/SCM %s', endpoint)
        if USE_SCM:
            response = session.get(f'https://{endpoint}/config/setup/v1/devices', timeout=CONN_TIMEOUT)
        else:
            response = session.get(f'https://{endpoint}/api/?type=op&cmd=<show><devices><connected>'
                                   f'</connected></devices></show>', timeout=CONN_TIMEOUT)
        logging.debug('Got response from Panorama/SCM with code %s:\n%s', response.status_code,
                      response.text)
        response.raise_for_status()
        if USE_SCM:
            scm_response = json.loads(response.text)
            serials = [a['id'] for a in scm_response['data'] if a['is_connected']]
            mgmt_ips = [a['ip_address'] for a in scm_response['data'] if a['is_connected']]
            hostnames = [a['hostname'] for a in scm_response['data'] if a['is_connected']]
        else:
            fw_xml = etree.ElementTree(etree.fromstring(response.text))
            serials = fw_xml.xpath(XPATH_SERIAL)
            mgmt_ips = fw_xml.xpath(XPATH_MGMT_IP)
            hostnames = fw_xml.xpath(XPATH_HOSTNAME)
        if not serials:
            logger.critical('Retrieved empty firewall list from Panorama/SCM')
            raise ValueError('Retrieved empty firewall list from Panorama/SCM')
        if not len(serials) == len(mgmt_ips) == len(hostnames):
            logger.critical('Retrieved serial list is not equal to the number of '
                            'firewalls/hostnames')
            raise ValueError('Retrieved serial list is not equal to the number of '
                             'firewalls/hostnames')
        logging.warning('Found %s firewalls connected to Panorama/SCM', len(serials))
        ip_name_tuple = tuple(zip(mgmt_ips, hostnames))
        found_fw_dict = dict(zip(serials, ip_name_tuple))
        logging.debug('Built firewall dictionary:\n%s', found_fw_dict)
        return found_fw_dict
    except etree.XMLSyntaxError as err:
        logger.critical('Panorama response is malformed: %s', err)
        raise
    except requests.exceptions.HTTPError:
        logger.critical('Received HTTP code %s while querying Panorama/SCM at %s', response.status_code,
                        endpoint)
        raise
    except requests.exceptions.RequestException as err:
        logger.critical('Error querying Panorama/SCM: %s', err)
        raise


def get_fw_config(fw_ip, session, cfg_type, panorama=None, fw_sn=None):
    """Queries the firewall to retrieve xml configs of the specified type
    (running|effective-running|merged|pushed-template). Can optionally proxy the query through the
    Panorama."""
    logging.info('Retrieving info of type %s from %s with sn %s using session %s and proxy is %s',
                 cfg_type, fw_ip, fw_sn, session, panorama)
    try:
        host = panorama if panorama else fw_ip
        target = f'&target={fw_sn}' if panorama else ''
        show_config_url = f'https://{host}/api/?type=op&cmd=<show><config><{cfg_type}>' \
                          f'</{cfg_type}></config></show>{target}'
        logging.debug('[%s] GETting %s', session, show_config_url)
        response = session.get(show_config_url, timeout=CONN_TIMEOUT)
        logging.debug('[%s] Got response with code %s:\n%s', session, response.status_code,
                      response.text)
        response.raise_for_status()
        response_xml = etree.ElementTree(etree.fromstring(response.text))
        # Strip API tags
        if cfg_type == 'pushed-template':
            config_xml = response_xml.getroot().xpath('/response/result/template/config')
        else:
            config_xml = response_xml.getroot().xpath('/response/result/*')
        if not config_xml:
            logging.critical('[%s] No node found under /response/result for firewall %s',
                             session, fw_sn)
            raise ValueError(f'No config node found in /response/result for firewall {fw_sn}')
        return etree.ElementTree(config_xml[0])
    except requests.exceptions.HTTPError:
        logger.critical('[%s] Received HTTP %s while querying firewall %s and proxy panorama is %s',
                        session, response.status_code, fw_ip, panorama)
        raise
    except etree.XMLSyntaxError as err:
        logger.critical('[%s] Panorama response is malformed: %s', session, err)
        raise
    except requests.exceptions.RequestException as err:
        logger.critical('[%s] Error querying Firewall: %s', session, err)
        raise


def detect_overrides(template_tree, running_tree, ignore_overrides_list):
    """Search for the template xpaths in the running config of the firewall to detect overrides"""
    template_xpath_list = []
    overrides_list = []
    overrides_exception_list = []
    for xpath in ignore_overrides_list:
        logging.debug('Analysing overrides ignore list xpath %s', xpath)
        for element in running_tree.xpath(xpath):
            if not len(element):
                logging.debug('Overrides ignore list xpath %s identifies running xpath %s', xpath,
                              running_tree.getpath(element))
                # We have to resolve_xpath() both the exception list and the detected overrides, since one comes from
                # the running config and the other one comes from the template config and so the elements can be ordered
                # differently etc.
                overrides_exception_list.append(resolve_xpath(running_tree.getpath(element), running_tree))
    for tag in template_tree.iter():
        # Search only in terminal nodes to avoid false positives. To compare the strings we convert
        # for example "entry[1]" into "entry[@name='foo'] to make it more deterministic
        logging.debug('Checking tag %s', tag)
        if not len(tag):
            tag_xpath = template_tree.getpath(tag)
            if '/config/shared/content-preview/' in tag_xpath:
                logging.debug('Skipping content preview xpath')
                continue
            logging.debug('%s is a terminal node, appending to xpath list', tag_xpath)
            template_xpath_list.append(resolve_xpath(tag_xpath, template_tree))
    for xpath in template_xpath_list:
        logging.debug('Looking in the running config for xpath %s', xpath)
        tpl_run_match = running_tree.xpath(xpath)
        if tpl_run_match:
            # There is a match but could be a self-closing tag, e.g. <group-mapping/>. These exist
            # By default in the config
            logging.debug('Found xpath %s one or more times in running config. Checking that it is not empty', xpath)
            for match in tpl_run_match:
                if match.text or match.attrib:
                    if xpath in overrides_exception_list:
                        logging.debug('Found override %s but skipping due to override ignore list', xpath)
                    else:
                        logging.debug('Found xpath in running config. Appending to override list %s',
                                      xpath)
                        overrides_list.append(xpath)
                else:
                    logging.debug('Xpath is empty in running config, ignoring... %s',
                                  running_tree.getpath(match))
        else:
            logging.debug('xpath %s not found in running config', xpath)
    return overrides_list


def detect_local_conf(running_tree, ignore_list):
    """Search for xpaths in the firewall's local config, ignoring paths such as the management IP
    and High Availability based on provided xpaths"""
    local_confs_list = []
    running_xpath_list = []
    exception_list = []
    # User Xpaths -> List of nodes without childs -> Xpaths of those nodes
    for xpath in ignore_list:
        logging.debug('Analysing ignore list xpath %s', xpath)
        for element in running_tree.xpath(xpath):
            if not len(element):
                logging.debug('Ignore list xpath %s identifies running xpath %s', xpath,
                              running_tree.getpath(element))
                exception_list.append(running_tree.getpath(element))
    # Ignore those Xpaths
    for tag in running_tree.iter():
        if not len(tag):
            # Tag has no childs but could be self-closing. Ignore if no text or attributes.
            if tag.text or tag.attrib:
                running_xpath_list.append(running_tree.getpath(tag))
    for xpath in running_xpath_list:
        logging.debug('Checking running xpath %s against ignore list %s', xpath, exception_list)
        if xpath not in exception_list:
            logging.info('Found un-ignored local config xpath %s', xpath)
            local_confs_list.append(resolve_xpath(xpath, running_tree).replace('[not(@name)]', ''))
        else:
            logging.debug('Ignoring xpath %s due to ignore list', xpath)
    return local_confs_list


def check_firewall(fw_ip_list, fw_sn_list, ignore_list, thread_session, ignore_overrides_list, panorama=None):
    """Thread that contacts a given list of firewalls with the provided requests.Session() to
    retrieve the running and template configs, then checks them for overrides and local configs.
    Updates global variable with the results in format {'sn': ['xpath1', 'xpath2', ...], ...}"""
    logging.info('Thread %s starting to check %s firewalls with %s serial numbers', thread_session,
                 len(fw_ip_list), len(fw_sn_list))
    if len(fw_ip_list) != len(fw_sn_list):
        logging.critical('The number of provided IPs is different from the number of serial numbers'
                         ' for session %s', thread_session)
        raise ValueError(f'The number of provided IPs is different from the number of serial '
                         f'numbers for session {thread_session}')
    with thread_session:  # Ensure the connection closes
        for fw_ip, fw_sn in zip(fw_ip_list, fw_sn_list):
            try:
                logging.debug('[%s] Retrieving template config for firewall %s %s using panorama '
                              '%s', thread_session, fw_ip, fw_sn, panorama)
                tpl_tree = get_fw_config(fw_ip, thread_session, SHOW_TEMPLATE, panorama, fw_sn)
            except etree.XMLSyntaxError as err:
                logging.critical('[%s] Error parsing template xml for firewall %s using panorama %s'
                                 ':\n%s', thread_session, fw_ip, panorama, err)
                raise
            try:
                logging.debug('[%s] Retrieving running config for firewall %s %s using panorama %s',
                              thread_session, fw_ip, fw_sn, panorama)
                run_tree = get_fw_config(fw_ip, thread_session, SHOW_RUNNING, panorama, fw_sn)
            except etree.XMLSyntaxError as err:
                logging.critical('[%s] Error parsing running config xml for firewall %s using '
                                 'panorama %s:\n%s', thread_session, fw_ip, panorama, err)
                raise
            if not panorama:
                # We are done with this destination IP
                logging.debug('[%s] Closing connection to %s because we are done with it',
                              thread_session, fw_ip)
                thread_session.close()
            logging.debug('[%s] Checking for overrides for fw %s', thread_session, fw_sn)
            found_overrides = detect_overrides(tpl_tree, run_tree, ignore_overrides_list)
            logging.debug('[%s] Checking for local configs for fw %s', thread_session, fw_sn)
            found_local_cfg = detect_local_conf(run_tree, ignore_list)
            if found_overrides:
                logging.info('[%s] Found overrides for fw %s, updating global object',
                             thread_session, fw_sn)
                # Global variable
                overrides_dict[fw_sn] = found_overrides
            if found_local_cfg:
                logging.info('[%s] Found local configs for fw %s, updating global object',
                             thread_session, fw_sn)
                # Global variable
                local_cfg_dict[fw_sn] = found_local_cfg


def file_maker(fw_sn, text, root):
    """Create text file with the specified contents in the specified folder"""
    if not os.path.isdir(root):
        logging.critical('The provided folder %s does not exist, unable to write files', root)
        raise ValueError(f'The provided folder {root} does not exist, unable to write files')
    Path(os.path.join(root, fw_sn)).mkdir(exist_ok=True)
    file_name = f'{fw_sn}-{datetime.today().strftime("%Y_%m_%d_%H_%M_%S")}.log'
    with open(os.path.join(root, fw_sn, file_name), 'w', encoding='utf-8') as out:
        out.write(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan for local configurations and overrides in Palo Alto Panorama and'
                                                 ' Strata Cloud Manager environments.')
    parser.add_argument('panorama_or_scm', type=str, help='Panorama IP address or hostname. Enter "scm" to use Strata '
                        'Cloud Manager instead.')
    parser.add_argument('-v', '--query-via-panorama', action='store_true',
                        help='Add this option to use Panorama as a proxy when querying the firewalls. Default: False')
    parser.add_argument('-c', '--ignore-certs', action='store_true',
                        help="Don't check for valid certificates when connecting. Does not affect connections to SCM."
                             'Default: Validate certificates')
    parser.add_argument('-r', '--max-open', action='store', default=10,
                        help='How many firewalls the script will query simultaneously. Default: 10')
    parser.add_argument('-k', '--api-key', action='store', type=str,
                        help='A valid firewall or Panorama API key with read privileges for the devices. '
                             f'Default: retrieve the key from {CFG_FILENAME} file')
    parser.add_argument('-b', '--bearer_token', action='store', type=str, help='A Strata Cloud Manager API Bearer Token'
                        f' with read privileges to List Devices. Default: retrieve the key from {CFG_FILENAME} file')
    parser.add_argument('-i', '--ignore-xpath', action='append',
                        help='Xpaths to ignore when checking for local firewall configurations. All'
                             ' the nodes identified by the given Xpaths will be ignored. Add '
                             'multiple Xpaths by passing the -i argument multiple times. This '
                             'ignore list is applied when checking for local configurations, NOT '
                             'when checking for overrides. Default: MGMT IP config, Panorama, and '
                             f'HA (see the {CFG_FILENAME} file)')
    parser.add_argument('-j', '--ignore-overrides-xpath', action='append', help='Xpaths to ignore when checking for '
                        'overrides. All the nodes identified by the given Xpaths will be ignored. Add multiple Xpaths '
                        'by passing the -j argument multiple times. Default: None')
    parser.add_argument('-t', '--target', action='append',
                        help='Limit analysis to the given serials.\nExample: -t 01230 -t 01231 -t '
                             '01232 -t 01233\nDefault: analyze all firewalls')
    parser.add_argument('-d', '--print-results', action='store_true',
                        help='Print details of the overrides to terminal instead of outputting to '
                             'file. Default: False')
    parser.add_argument('-o', '--file-path', action='store',
                        help='The base path in which to create the output files with the overrides.'
                             ' A folder will be created for every serial number, containing the '
                             'timestamped files for every run. Default: same folder as the script.')
    parser.add_argument('-x', '--debug-level', type=str, choices=['DEBUG', 'INFO', 'WARNING',
                                                                  'ERROR', 'CRITICAL'],
                        default='WARNING', help='Logging message verbosity. Default: WARNING')
    args = parser.parse_args()
    USE_SCM = True if args.panorama_or_scm == SCM_KEYWORD else False
    logging.basicConfig(level=args.debug_level, format='%(asctime)s [%(levelname)s] %(message)s')
    logging.info('Starting with args %s', args)
    config = configparser.ConfigParser()
    if not args.api_key:
        try:
            logging.info('Attempting to read API key from %s', CFG_FILENAME)
            config.read(CFG_FILENAME)
            key_section = config['API Key']
            API_KEY = str(key_section.get('API_KEY'))
            logging.info('Successfully retrieved API key')
        except configparser.Error as err:
            logging.critical('ERROR: unable to read config file %s with error %s\nPlease ensure the'
                             ' file exists or pass the API key / Bearer token via the --api-key argument.',
                             CFG_FILENAME, err)
            sys.exit(1)
    else:
        API_KEY = args.api_key
        logging.info('Successfully retrieved API key')
    if not args.ignore_xpath:
        try:
            IGNORE_LIST = []
            logging.info('Attempting to read ignore list from %s', CFG_FILENAME)
            config.read(CFG_FILENAME)
            key_section = config['Limits']
            if key_section.get('IGNORE_LIST'):
                for mem in key_section.get('IGNORE_LIST').split('\n'):
                    IGNORE_LIST.append(mem.replace(r'\\', '\\'))
                logging.info('Found ignore list %s', IGNORE_LIST)
            else:
                logging.info('Xpath ignore list not found.')
        except configparser.Error as err:
            logging.critical(
                'ERROR: unable to read config file %s with error %s\nPlease ensure the file exists '
                'or pass the Xpath list via the --ignore-xpath argument.', CFG_FILENAME, err)
            sys.exit(1)
    else:
        IGNORE_LIST = args.ignore_xpath
        logging.info('Found ignore list %s', IGNORE_LIST)
    if not args.ignore_overrides_xpath:
        try:
            IGNORE_OVERRIDES_LIST = []
            logging.info('Attempting to read overrides ignore list from %s', CFG_FILENAME)
            config.read(CFG_FILENAME)
            key_section = config['Limits']
            if key_section.get('IGNORE_OVERRIDES_LIST'):
                for mem in key_section.get('IGNORE_OVERRIDES_LIST').split('\n'):
                    IGNORE_OVERRIDES_LIST.append(mem.replace(r'\\', '\\'))
                logging.info('Found ignore list %s', IGNORE_OVERRIDES_LIST)
            else:
                logging.info('Xpath overrides ignore list not found.')
        except configparser.Error as err:
            logging.critical(
                'ERROR: unable to read config file %s with error %s\nPlease ensure the file exists '
                'or pass the Xpath list via the --ignore-overrides-xpath argument.', CFG_FILENAME, err)
            sys.exit(1)
    else:
        IGNORE_OVERRIDES_LIST = args.ignore_overrides_xpath
        logging.info('Found overrides ignore list %s', IGNORE_OVERRIDES_LIST)
    if not args.target:
        try:
            TARGETS = []
            logging.info('Attempting to read targets list from %s', CFG_FILENAME)
            config.read(CFG_FILENAME)
            key_section = config['Limits']
            if key_section.get('TARGETS'):
                for mem in key_section.get('TARGETS').split('\n'):
                    TARGETS.append(mem.replace(r'\\', '\\'))
                logging.info('Found target list %s', TARGETS)
            else:
                TARGETS = False
                logging.info('Target list not found. Scanning all firewalls.')
        except configparser.Error as err:
            logging.critical(
                'ERROR: unable to read config file %s with error %s\nPlease ensure the file exists '
                'or pass the target list via the --target-list argument.', CFG_FILENAME, err)
            sys.exit(1)
    else:
        TARGETS = args.target
        logging.info('Found targets list %s', TARGETS)
    if not args.file_path:
        try:
            logging.info('Attempting to read file path from %s', CFG_FILENAME)
            config.read(CFG_FILENAME)
            key_section = config['Output']
            FILE_PATH = key_section.get('FILE_PATH')
            if not FILE_PATH:
                logging.critical('File path %s in configuration is not valid', FILE_PATH)
                sys.exit(1)
            logging.info('Using file path %s', FILE_PATH)
        except configparser.Error as err:
            logging.critical(
                'ERROR: unable to read config file %s with error %s\nPlease ensure the file exists '
                'or pass the file path via the --file-path argument.', CFG_FILENAME, err)
            sys.exit(1)
    else:
        FILE_PATH = args.file_path
        logging.info('Found targets list %s', FILE_PATH)
    if USE_SCM:
        try:
            logging.info('Attempting to read SCM API endpoint from %s', CFG_FILENAME)
            config.read(CFG_FILENAME)
            key_section = config['SCM']
            SCM_FQDN = key_section.get('SCM_FQDN')
            if not SCM_FQDN:
                logging.critical('SCM FQDN %s in configuration is not valid', SCM_FQDN)
                sys.exit(1)
            logging.info('Using SCM API endpoint %s', SCM_FQDN)
        except configparser.Error as err:
            logging.critical(
                'ERROR: unable to read config file %s with error %s\nPlease ensure the file exists '
                'or pass the file path via the --file-path argument.', CFG_FILENAME, err)
            sys.exit(1)
        if not args.bearer_token:
            try:
                logging.info('Attempting to read Bearer token from %s', CFG_FILENAME)
                config.read(CFG_FILENAME)
                key_section = config['SCM']
                BEARER_TOKEN = str(key_section.get('BEARER_TOKEN'))
                logging.info('Successfully retrieved Bearer token')
            except configparser.Error as err:
                logging.critical('ERROR: unable to read config file %s with error %s\nPlease ensure the'
                                 ' file exists or pass the API key / Bearer token via the --api-key argument.',
                                 CFG_FILENAME, err)
                sys.exit(1)
        else:
            BEARER_TOKEN = args.bearer_token
            logging.info('Successfully retrieved API key or Bearer token')
        if args.query_via_panorama:
            logging.warning('Ignoring -v argument due to Strata Cloud Manager mode')
            args.query_via_panorama = False
        scm_req = requests.Session()
        logging.debug('Session to contact SCM is %s', scm_req)
        scm_req.headers.update({'Accept': 'application/json', 'Authorization': f'Bearer {BEARER_TOKEN}'})
        fw_dict = connected_fw_list(SCM_FQDN, scm_req)
    else:
        pra_req = requests.Session()
        logging.debug('Session to contact Panorama is %s', pra_req)
        pra_req.headers.update({'X-PAN-KEY': API_KEY})
        pra_req.verify = not args.ignore_certs
        try:
            fw_dict = connected_fw_list(args.panorama_or_scm, pra_req)
        except requests.exceptions.SSLError:
            logging.critical('The Panorama TLS certificate is untrusted. If this is expected, consider '
                             'running the script with the --ignore-certs argument. Exiting...')
            sys.exit(1)
    logging.info('Retrieved firewall list:\n%s', fw_dict)
    if TARGETS:
        logging.warning('Limiting analysis to %d of %d firewalls due to target list', len(TARGETS), len(fw_dict))
    # Prepare session pool
    thr_dict = {}
    for i in range(0, args.max_open):
        thr_dict[requests.Session()] = []
    logging.debug('Generated one session for each thread:\n%s', thr_dict)
    # Assign threads to firewalls in round-robin
    i = 0
    for firewall_sn in fw_dict:
        # Apply whitelist
        if TARGETS and firewall_sn not in TARGETS:
            logging.info('Skipping firewall %s due to targets list', firewall_sn)
            continue
        thr_dict[list(thr_dict.keys())[i]].append(firewall_sn)
        # { session1: [ sn_1, sn2, sn3 ], session2: [ sn_4, sn_5, sn_6 ] }
        i = i + 1 if i < (len(thr_dict) - 1) else 0
    logging.debug('Assigned firewalls to threads:\n%s', thr_dict)
    thr_list = []
    overrides_dict = {}
    local_cfg_dict = {}
    start_time = time.time()
    for thr_sess, sn_list in thr_dict.items():
        # Ignore excess threads if they are more than the firewalls
        if sn_list:
            thr_sess.headers.update({'X-PAN-KEY': API_KEY})
            thr_sess.verify = not args.ignore_certs
            # IP list, SN list, ignore list, session to use for all connections, optional
            # panorama IP
            fw_thread = Thread(target=check_firewall, args=([fw_dict[x][0] for x in sn_list],
                                                            sn_list, IGNORE_LIST, thr_sess, IGNORE_OVERRIDES_LIST,
                                                            args.panorama_or_scm if
                                                            args.query_via_panorama else None,))
            logging.info('Starting thread %s', fw_thread)
            fw_thread.start()
            thr_list.append(fw_thread)
        if time.time() - start_time > 5:
            logging.warning('Done %d out of %d firewalls...', len([x for x in thr_list
                                                                  if not x.is_alive()]),
                            len(fw_dict))
    logging.info('Done Starting threads. Joining threads...')
    time.sleep(3)
    while any(x.is_alive() for x in thr_list):
        logging.warning('Done %d out of %d firewalls...', len([x for x in thr_list if not x.is_alive()]), len(fw_dict))
        time.sleep(5)
    logging.warning('Done analyzing configurations.')
    # Greppable output
    if overrides_dict:
        print('!!! OVERRIDES DETECTED !!!')
    if local_cfg_dict:
        print('!!! LOCAL CONFIGURATIONS DETECTED !!!')
    # Print summary
    print(f'Found {len(overrides_dict)} firewalls with local overrides and {len(local_cfg_dict)} '
          f'firewalls with local configurations.\n')
    results_list = [['SN', 'HOSTNAME', 'IP', 'OVERRIDES', 'LOCAL']]
    skipped = 0
    for fw_sn, hostn_ip in fw_dict.items():
        if TARGETS and fw_sn not in TARGETS:
            skipped += 1
            continue
        try:
            override_amount = len(set(overrides_dict[fw_sn]))
        except KeyError:
            override_amount = 0
        try:
            local_cfg_amount = len(set(local_cfg_dict[fw_sn]))
        except KeyError:
            local_cfg_amount = 0
        if override_amount or local_cfg_amount:
            results_list.append([fw_sn, hostn_ip[1], hostn_ip[0], override_amount,
                                 local_cfg_amount])
    if len(results_list) > 1:
        for row in results_list:
            print('{: <20} {: <20} {: <20} {: <20} {: <20}'.format(*row))
    else:
        print('No overrides or local configurations found.')
    print('\nSee log files for details, or use argument "--print-results" to print to terminal.\n')
    for fw_sn, hostn_ip in fw_dict.items():
        if fw_sn in overrides_dict or fw_sn in local_cfg_dict:
            fw_text = ''
            fw_text += '#' * 50 + '\n'
            fw_text += f'DEVICE {fw_sn} {hostn_ip[1]} at {hostn_ip[0]}:\n'
            fw_text += '#' * 50 + '\n\n'
            if fw_sn in overrides_dict:
                fw_text += '\tOVERRIDES FOUND ON DEVICE:\n\n'
                for override in sorted(set(overrides_dict[fw_sn])):
                    fw_text += '\t\t' + str(override).replace('[not(@name)]', '') + '\n'
                fw_text += '\n'
            if fw_sn in local_cfg_dict:
                fw_text += '\tLOCAL CONFIGURATIONS FOUND ON DEVICE:\n\n'
                for local_bit in sorted(set(local_cfg_dict[fw_sn])):
                    fw_text += '\t\t' + str(local_bit).replace('[not(@name)]', '') + '\n'
            try:
                if args.print_results:
                    print(fw_text)
                else:
                    file_maker(fw_sn, fw_text, FILE_PATH)
            except OSError as err:
                logging.critical('Failure writing detail file for firewall %s:\n%s', fw_sn, err)
    if TARGETS:
        logging.warning('Skipped %d firewalls due to the targets list.', skipped)
    logging.warning('Finished')
