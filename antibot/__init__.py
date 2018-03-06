# -*- coding: utf-8 -*-

import os
import re
import csv
import socket
import argparse
import logging
from itertools import imap
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network


# traffic log format
LOG_FORMAT = ('timestamp', 'ip', 'user_agent')
TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'

# real users metrics
MAX_HITS_PER_HOUR = 20

# bots fingerprints
BOTS = {
    # * GOOD BOTS *
    # (well-known crawlers)

    # GOOGLE spider
    'googlebot': {
        'type': 'good',
        'domains': [
            'googlebot.com',
            'google.com',
        ],
        'user_agents': [
            'googlebot',
            'mediapartners-google',
            'adsbot-google',
        ],
    },

    # BING spider
    'bingbot': {
        'type': 'good',
        'domains': [
            'search.msn.com',
        ],
        'user_agents': [
            'bingbot',
            'msnbot',
            'adidxbot',
            'bingpreview',
        ],
    },

    # YAHOO spider
    'slurpbot': {
        'type': 'good',
        'user_agents': [
            'slurp',
        ],
    },

    # YANDEX spider
    'yandexbot': {
        'type': 'good',
        'domains': [
            'yandex.ru',
            'yandex.net',
            'yandex.com',
        ],
        'user_agents': [
            'yandexbot',
            'yandexaccessibilitybot',
            'yandexmobilebot',
            'yandexdirectdyn',
            'yandexscreenshotbot',
            'yandeximages',
            'yandexvideo',
            'yandexvideoparser',
            'yandexmedia',
            'yandexblogs',
            'yandexfavicons',
            'yandexwebmaster',
            'yandexpagechecker',
            'yandeximageresizer',
            'yadirectfetcher',
            'yandexcalendar',
            'yandexsitelinks',
            'yandexmetrika',
            'yandexantivirus',
            'yandexvertis',
        ],
    },

    # DUCKDUCKGO spider
    'duckduckbot': {
        'type': 'good',
        'ip_networks': [
            '72.94.249.0/24',
        ],
        'user_agents': [
            'duckduckbot',
        ],
    },

    # FACEBOOK spider
    'facebot': {
        'type': 'good',
        'user_agents': [
            'facebot',
            'facebookexternalhit',
        ],
    },

    # ALEXA spider
    'alexabot': {
        'type': 'good',
        'user_agents': [
            'ia_archiver',
        ],
    },

    # BAIDU spider
    'baidubot': {
        'type': 'good',
        'domains': [
            'baidu.com',
            'baidu.jp',
        ],
        'user_agents': [
            'baiduspider',
        ],
    },

    # * BAD BOTS *

    # SQL injection
    'sql_injection': {
        'type': 'bad',
        'user_agents': [
            'select',
        ],
    },

    # Script injection & XSS
    'script_injection': {
        'type': 'bad',
        'user_agents': [
            '&lt;',
        ],
    },

    # PhantomJS
    'phantomjs': {
        'type': 'bad',
        'user_agents': [
            'phantomjs',
        ],
    },

    # Zombie.js
    'zombie': {
        'type': 'bad',
        'user_agents': [
            'zombie',
        ],
    },

    # Python-written
    'python': {
        'type': 'bad',
        'user_agents': [
            'python',
        ],
    },

    # Go-written
    'go': {
        'type': 'bad',
        'user_agents': [
            'go-http-client',
        ],
    },

    # Apache Nutch
    'nutch': {
        'type': 'bad',
        'user_agents': [
            'nutch',
        ],
    },

    # PHPCrawl
    'phpcrawl': {
        'type': 'bad',
        'user_agents': [
            'phpcrawl',
        ],
    },

    # HTTrack
    'httrack': {
        'type': 'bad',
        'user_agents': [
            'httrack',
        ],
    },

    # Wget
    'wget': {
        'type': 'bad',
        'user_agents': [
            'wget',
        ],
    },

    # Curl
    'curl': {
        'type': 'bad',
        'user_agents': [
            'curl',
        ],
    },

    # Libwww
    'libwww': {
        'type': 'bad',
        'user_agents': [
            'libwww',
        ],
    },

    # HttpUnit
    'httpunit': {
        'type': 'bad',
        'user_agents': [
            'httpunit',
        ],
    },

    # Symfony PHP
    'symfony': {
        'type': 'bad',
        'user_agents': [
            'symfony',
        ],
    },

    # Geb (very groovy browser automation)
    'geb': {
        'type': 'bad',
        'user_agents': [
            'geb',
        ],
    },

}


BOTS_USER_AGENTS = {}
BOTS_IP_NETWORKS = {}
BOTS_DOMAINS = {}

RE_BOT_USER_AGENTS = []
RE_BOT_DOMAINS = []


for bot, cfg in BOTS.items():

    if 'user_agents' in cfg:
        for user_agent in filter(None, map(lambda _: _.strip().lower(), cfg['user_agents'])):
            BOTS_USER_AGENTS[user_agent] = bot
            RE_BOT_USER_AGENTS.append(user_agent)

    if 'ip_networks' in cfg:
        for network in filter(None, map(str.strip, cfg['ip_networks'])):
            BOTS_IP_NETWORKS[network] = bot

    if 'domains' in cfg:
        for domain in filter(None, map(lambda _: _.strip().lower(), cfg['domains'])):
            BOTS_DOMAINS[domain] = bot
            RE_BOT_DOMAINS.append(domain)


RE_BOT_USER_AGENTS = r'\b(%s)\b' % r'|'.join(RE_BOT_USER_AGENTS)
RE_BOT_DOMAINS = r'(%s)$' % r'|'.join(RE_BOT_DOMAINS)


# helpers

class AntibotError(Exception):
    """Base exception of this module"""


class RCache(dict):
    """
    a simple ~dict~ implementation of a cache layer with a fixed size,
    based on a "random replacement" algorithm: randomly selects a candidate item
    and discards it to make space when necessary; relies on the #popitem method,
    that "removes an arbitrary (key, value) pair" (not random though, but fast)
    """

    def __init__(self, size, *args, **kwargs):
        self._size = abs(int(size)) or 1
        super(RCache, self).__init__(self, *args, **kwargs)

    def __setitem__(self, key, val):
        if key not in self and len(self) >= self._size:
            self.popitem()
        super(RCache, self).__setitem__(key, val)


def parse_timestamp(timestamp, format=TIMESTAMP_FORMAT):
    """
    parse the timestamp to ~datetime~ object

    :param timestamp: timestamp {string}
    :param format: timestamp format {string}
    :return: ~datetime~ object
    """
    try:
        return datetime.strptime(timestamp, format)
    except Exception as e:
        raise AntibotError(
            'Unable to parse the timestamp [%s]: %s'
            % (str(timestamp), str(e))
        )


# IPv4

def get_ipv4(addr, _cache=RCache(1000)):
    """
    get the ~IPv4Address~ object from an IPv4 address

    :param addr: IPv4 address {string|integer}
    :return: ~IPv4Address~ object
    """
    try:
        if addr not in _cache:
            _cache[addr] = IPv4Address(unicode(addr))
        return _cache[addr]

    except Exception as e:
        raise AntibotError(
            'Unable to parse an IPv4 address [%s]: %s'
            % (str(addr), str(e))
        )

def get_ipv4_network(addr, _cache=RCache(1000)):
    """
    get the ~IPv4Network~ object from IPv4/mask string

    :param addr: IPv4/mask {string}
    :return: ~IPv4Network~ object
    """
    try:
        if addr not in _cache:
            _cache[addr] = IPv4Network(unicode(addr))
        return _cache[addr]

    except Exception as e:
        raise AntibotError(
            'Unable to parse an IPv4 address with mask [%s]: %s'
            % (str(addr), str(e))
        )

def ipv4_address_in_network(addr, network):
    """
    check if an IPv4 address belongs to a subnetwork

    :param addr: IPv4 address {string}
    :param network: IPv4/mask {string}
    :return: ~True|False~
    """
    if get_ipv4(addr) in get_ipv4_network(network):
        return True
    else:
        return False

# IPv6

def get_ipv6(addr, _cache=RCache(1000)):
    """
    get the ~IPv6Address~ object from an IPv6 address

    :param addr: IPv6 address {string|integer}
    :return: ~IPv6Address~ object
    """
    try:
        if addr not in _cache:
            _cache[addr] = IPv6Address(unicode(addr))
        return _cache[addr]

    except Exception as e:
        raise AntibotError(
            'Unable to parse an IPv6 address [%s]: %s'
            % (str(addr), str(e))
        )

def get_ipv6_network(addr, _cache=RCache(1000)):
    """
    get the ~IPv6Network~ object from IPv6/mask string

    :param addr: IPv6/mask {string}
    :return: ~IPv6Network~ object
    """
    try:
        if addr not in _cache:
            _cache[addr] = IPv6Network(unicode(addr))
        return _cache[addr]

    except Exception as e:
        raise AntibotError(
            'Unable to parse an IPv6 address with mask [%s]: %s'
            % (str(addr), str(e))
        )

def ipv6_address_in_network(addr, network):
    """
    check if an IPv6 address belongs to a subnetwork

    :param addr: IPv6 address {string}
    :param network: IPv6/mask {string}
    :return: ~True|False~
    """
    if get_ipv6(addr) in get_ipv6_network(network):
        return True
    else:
        return False


def get_host_by_ip(ip, _cache=RCache(1000**2)):
    """
    run a reverse DNS lookup on the IP address
    and return the host (domain name)

    :param ip: IP address {string}
    :return: host (domain name) {string} or ~None~ (in case of fail)
    """
    try:
        if ip not in _cache:
            _cache[ip] = socket.gethostbyaddr(ip)[0].strip('.')
        return _cache[ip]

    except socket.herror as e:
        return
    except Exception as e:
        raise AntibotError(
            'Unable to get the host from IP address: %s' % str(e)
        )

def get_ip_by_host(host, _cache=RCache(1000**2)):
    """
    run a forward DNS lookup on the host (domain name)
    and return the IP address

    :param host: host (domain name) {string}
    :return: IP address {string} or ~None~ (in case of fail)
    """
    try:
        if host not in _cache:
            _cache[host] = socket.gethostbyname(host)
        return _cache[host]

    except socket.herror as e:
        return
    except Exception as e:
        raise AntibotError(
            'Unable to get the IP address from host: %s' % str(e)
        )

def verify_dns(ip, host):
    """
    check if an IP address points to some host (domain) and vise versa:
    1. run a reverse DNS lookup on the IP address
    2. run a forward DNS lookup on the domain name retrieved in step 1
    3. verify results

    :param ip: IP address {string}
    :param host: host (domain name) {string}
    :return: ~True|False~
    """
    host_by_ip = get_host_by_ip(ip)

    if (
        host_by_ip and
        host_by_ip.endswith(host) and
        get_ip_by_host(host_by_ip) == ip
    ):
        return True

    return False


# detect bot

def detect_bot_by_ip(ip, limit=None):
    """
    detect if a given IP address is used by some known bot

    :param ip: IP address {string}
    :param limit: a list of bots to check {list}
    :return: bot name or ~None~ (unknown bot)
    """
    if not isinstance(ip, (str, int)):
        raise TypeError(
            ':ip must be string or integer representing the IP address'
        )

    try:
        get_ipv4(ip)
        test = ipv4_address_in_network
    except AntibotError:
        try:
            get_ipv6(ip)
            test = ipv6_address_in_network
        except AntibotError:
            raise AntibotError('Unsupported IP address: %s' % ip)

    # by IP network
    for network, bot in BOTS_IP_NETWORKS.iteritems():
        if limit and bot not in limit:
            continue
        try:
            if test(ip, network):
                return bot
        except AntibotError:
            continue

    # by DNS lookup
    host_by_ip = get_host_by_ip(ip)
    if host_by_ip:
        domain_match = re.search(RE_BOT_DOMAINS, host_by_ip, re.I)
        if domain_match:
            bot = BOTS_DOMAINS[domain_match.group().lower()]
            if (
                (not limit or bot in limit) and
                get_ip_by_host(host_by_ip) == ip
            ):
                return bot


def detect_bot_by_user_agent(user_agent, limit=None):
    """
    detect if a given User-Agent string is used by some known bot

    :param user_agent: User-Agent {string}
    :param limit: a list of bots to check {list}
    :return: bot name or ~None~ (unknown bot)
    """
    if not isinstance(user_agent, str):
        raise TypeError(':user_agent must be string')

    ua_match = re.search(RE_BOT_USER_AGENTS, user_agent, re.I)
    if ua_match:
        bot = BOTS_USER_AGENTS[ua_match.group().lower()]
        if not limit or bot in limit:
            return bot


# detect real users

def detect_real_user_by_user_agent(user_agent):
    """
    detect if a given User-Agent string is used by a real user

    :param user_agent: User-Agent {string}
    :return: ~True|False~
    """
    if re.search(
        r'\b(mozilla|symbian|gobrowser|netfront|opera)\b',
        user_agent, re.I
    ):
        return True
    else:
        return False


# processors

def parse_cli():
    """
    parse command-line arguments
    """
    argparser = argparse.ArgumentParser(description='antibot')
    argparser.add_argument('log')
    argparser.add_argument('-o', '--output')
    # argparser.add_argument('-', '--', type=int, default=1)
    argparser.add_argument('-v', '--verbose', action='store_true')
    return argparser.parse_args()


def parse_log_file(log_file):
    """
    parse the content of a log file

    :param log_file: the CSV file object opened with 'rb' mode
    :yield: traffic in the structured form according to LOG_FORMAT
    """
    row_len = len(LOG_FORMAT)
    zero_timestamps = {}
    for n, row in enumerate(csv.reader(log_file)):
        hit = {}
        try:
            if len(row) != row_len:
                raise AntibotError(
                    'Unsupported CSV format of a log file at row: %s'
                    % (n+1)
                )
            for i, cell in enumerate(row):
                key = LOG_FORMAT[i]
                value = cell.strip()
                if not value:
                    raise AntibotError(
                        'Empty value in a log file at row: %s' % (n+1)
                    )
                if key == 'ip':
                    try:
                        ipv4 = get_ipv4(value)
                    except AntibotError:
                        try:
                            ipv6 = get_ipv6(value)
                        except AntibotError:
                            raise AntibotError(
                                'Unsupported IP address in a log file at row: %s'
                                % (n+1)
                            )
                hit[key] = value
        except AntibotError as e:
            if i:
                logging.debug(str(e))
            continue
        timestamp = parse_timestamp(hit['timestamp'])
        zero_timestamp = zero_timestamps.setdefault(hit['ip'], timestamp)
        hit['timestamp'] = int((timestamp - zero_timestamp).total_seconds())
        yield hit


def process_hit(hit):
    """
    process the unique hit (visit) and identify if it's a bot

    :param hit: hit's data {dict}
    :return: updated hit's data {dict}
    """
    bot = detect_bot_by_user_agent(hit['user_agent'])
    if bot:
        bot_type = BOTS[bot]['type']
        if (
            bot_type == 'good' and
            (
                bot in BOTS_IP_NETWORKS or
                bot in BOTS_DOMAINS
            ) and
            detect_bot_by_ip(hit['ip']) != bot
        ):
            bot = None
            bot_type = 'bad'
        hit['bot'] = {
            'name': bot,
            'type': bot_type,
        }
    elif not detect_real_user_by_user_agent(hit['user_agent']):
        hit['bot'] = {
            'name': None,
            'type': 'bad',
        }
    return hit


def run():
    """
    run antibot
    """
    socket.setdefaulttimeout(20.)
    args = parse_cli()
    # Logging config
    logging.basicConfig(
        format='%(asctime)s [AntiBot::%(levelname)s] %(message)s',
        datefmt='%H:%M:%S',
        level=10 if args.verbose else 20,
    )
    logging.info('Starting...')
    if not os.path.isfile(args.log):
        raise IOError('Log file not found: %s' % args.log)
    logging.info('Parsing and processing the log file...')
    hits_by_ip = {}
    stats = {
        'total': 0,
        'good_bots': {},
        'bad_bots': {},
    }
    with open(args.log, 'rb') as f:
        for hit in imap(process_hit, parse_log_file(f)):
            hits_by_ip.setdefault(hit['ip'], []).append(hit)
            stats['total'] += 1
    logging.info('Analyzing the data...')
    for ip, hits in hits_by_ip.iteritems():
        # bad bot?
        bad_bots_hits = filter(
            lambda hit: hit.get('bot', {}).get('type') == 'bad',
            hits
        )
        # if any hit from this IP has been made by a bad bot
        if bad_bots_hits:
            stats['bad_bots'][ip] = len(hits)
            continue
        # good bot?
        good_bots_hits = filter(
            lambda hit: hit.get('bot', {}).get('type') == 'good',
            hits
        )
        # if any hit from this IP has been made by a good bot
        if good_bots_hits:
            if (
                # but not all hits from this IP
                len(good_bots_hits) != len(hits) or
                # or not all hits by the same good bot
                len(
                    set(
                        map(
                            lambda hit: hit['bot']['name'],
                            good_bots_hits
                        )
                    )
                ) != 1
            ):
                stats['bad_bots'][ip] = len(hits)
            # collect stats
            else:
                bot = good_bots_hits[0]['bot']['name']
                stats['good_bots'][ip] = (len(hits), bot)
            continue
        # real user?
        # skip cases with too few hits
        if len(hits) < 20:
            continue
        # were there too many hits from the same IP?
        # or requests have some pattern? (hits timeouts)
        time_hits = [0, 0]
        timeout = 0
        timeout_patterns = 0.
        timestamp = 0
        for hit in hits:
            dt = max(0.0, float(hit['timestamp'] - timestamp))
            timestamp = hit['timestamp']
            # process hits within 15-minutes interval
            if dt < 900:
                time_hits[1] += 1
                time_hits[0] += dt
            # hits timeouts
            if timeout:
                dtmt = (dt / timeout)
                if (dtmt >= 0.75 and dtmt <= 1.25):
                    timeout_patterns += 1
            timeout = dt
        # is an avg. number of hits per hour is more than max acceptable value?
        # or more than 75% of hits have some pattern (timeout)
        if (
            (
                time_hits[0] and
                (time_hits[1] * 3600 / time_hits[0]) > MAX_HITS_PER_HOUR
            ) or
            (timeout_patterns / len(hits)) >= 0.75
        ):
            stats['bad_bots'][ip] = len(hits)
    # print the report
    logging.info('Generating the report...')
    hits_by_bad_boots = sum(stats['bad_bots'].values())
    hits_by_good_boots = sum(map(lambda _: _[0], stats['good_bots'].values()))
    hits_by_real_users = stats['total'] - hits_by_bad_boots - hits_by_good_boots
    print
    print '='*50
    print 'Total hits: %s' % stats['total']
    print 'Hits by real users: %s (%.2f%%)' % (hits_by_real_users, (hits_by_real_users*100./stats['total']))
    print 'Hits by good bots: %s (%.2f%%)' % (hits_by_good_boots, (hits_by_good_boots*100./stats['total']))
    print 'Hits by bad bots: %s (%.2f%%)' % (hits_by_bad_boots, (hits_by_bad_boots*100./stats['total']))
    print
    print '** TOP-10 IPs used by bad bots **'
    for ip, s in sorted(stats['bad_bots'].items(), key=lambda _: _[1], reverse=True)[:10]:
        print ('[ %s ]' % ip).ljust(20) + ' - %s hits' % s
    print
    print '** TOP-10 IPs used by good bots **'
    for ip, s in sorted(stats['good_bots'].items(), key=lambda _: _[1][0], reverse=True)[:10]:
        print ('[ %s ]' % ip).ljust(20) + ' - %s hits (%s)' % (s[0], s[1])
    print '='*50
    print
    # save IPs used by bad bots into file
    if args.output:
        logging.info(
            'Writing IPs used by bad bots into the file: %s'
            % args.output
        )
        with open(args.output, 'w') as f:
            for ip in stats['bad_bots']:
                f.write(ip + '\n')
    logging.info('Done')


