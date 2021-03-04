#!/usr/bin/python3

import logging
import os
import sys
from argparse import SUPPRESS, ArgumentParser
import requests
import urllib3
from netaddr import *
import _thread
import itertools
import math

try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as ie:
    print(ie)


LOGGING_FORMAT = "%(asctime)s: %(message)s"
PROTOCOLS = ("http", "https")

range_length = 0

total_requests = 0
sent_requests = 0
matches = 0

def print_banner(args):
    global range_length, total_requests

    print("                 _   _             _ _                             ")
    print("                | | (_)           | (_)                            ")
    print("  _ __ ___  __ _| |  _ _ __     __| |_ ___  ___ _____   _____ _ __ ")
    print(" | '__/ _ \/ _` | | | | '_ \   / _` | / __|/ __/ _ \ \ / / _ \ '__|")
    print(" | | |  __/ (_| | | | | |_) | | (_| | \__ \ (_| (_) \ V /  __/ |   ")
    print(" |_|  \___|\__,_|_| |_| .__/   \__,_|_|___/\___\___/ \_/ \___|_|   ")
    print("                      | |                                          ")
    print("                      |_|                      Efrén Díaz @elefr3n \n\n")
    print(f"Host: \t{args.hostname}")
    print(f"IPv4: \t{args.target_list} ({range_length} addresses) ({total_requests} requests)")
    print(f"Match: \t{args.match}")
    print(f"Uri: \t{args.uri}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout}\n")
    logging.info("STARTING...")
    

def iterable_list(item_list):
    ipv4_list = []
    item_list = item_list.split(",")
    for item in item_list:
        try:
            ip_range = IPNetwork(item)
            ipv4_list = list(ip_range) + ipv4_list
        except:
            logging.error(str(item) + " is not valid ipv4 address or range")
            sys.exit()
    
    return ipv4_list, len(ipv4_list)


def distribute_addresses(ipv4list, threads, items_per_thread):
    # create one dimension for each thread
    ipv4_addrs = dict()
    for i, ip in enumerate(ipv4list):
        ipv4_addrs.setdefault(int(i / items_per_thread), []).append(str(ip))
    return ipv4_addrs


def launch_thread(th_number, ipv4_addrs, args):
    for addr, protocol in itertools.product(ipv4_addrs.get(th_number, []), PROTOCOLS):
        logging.debug(f"[TH: {th_number}], addr: {addr}, protocol: {protocol}")
        send_request(addr, protocol, args)


def send_request(ipaddr, protocol, args):
    global sent_requests, matches

    sent_requests = sent_requests + 1 
    progress_control()
    
    target = f"{protocol}://{ipaddr}{args.uri}"

    logging.debug(f"Trying {target}...")

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0",
            "Host": args.hostname,
        }
        response = requests.get(
            target, headers=headers, verify=False, timeout=args.timeout, allow_redirects=False
        )
        if str(args.match) in str(response.content):
            matches = matches + 1
            resp_size = str(round(len(response.content) / 1024))
            msg = f"\033[92m{protocol} request to {ipaddr} matchs ({resp_size}kb)\033[0m \n \
                check it: \"curl -H 'Host: {args.hostname}' {target} -k\""
            logging.info(f"{msg}")

    except:
        logging.debug(f"{target} not responds")

def progress_control():
    global total_requests, sent_requests, matches

    percent = sent_requests / (total_requests / 100);

    sys.stdout.write(f"Progress: "+("%.2f" % percent)+"% \r")
    sys.stdout.flush()
    
    if sent_requests >= total_requests:
        matches_str = str(matches) if matches else "ZERO"
        logging.info(f"FINISHED WITH {matches_str} MATCHES \n")
        os._exit(0)
    
def main(args):
    global range_length, total_requests

    try:
        #create network object
        ip_list, range_length = iterable_list(args.target_list)
        total_requests = range_length * 2  # each address has 2 requests

        #calculate addresses per thread
        items_per_thread = math.ceil(range_length / args.threads)

        # distribute addresses to threads
        ipv4_addrs = distribute_addresses(ip_list, args.threads, items_per_thread)

        #show details
        print_banner(args)

        # start threads
        for i in range(args.threads):
            _thread.start_new_thread(launch_thread, (i, ipv4_addrs, args))

    except Exception as e:
        logging.warning(f"Error: unable to start thread. {e}")

    while True:
        pass


if __name__ == "__main__":
    parser = ArgumentParser(
        add_help=True,
        description="This tool helps you to find a website server ip in an ipv4 range or list.",
        usage=SUPPRESS,
    )
    parser.add_argument("hostname", help="Ex: site.com")
    parser.add_argument("target_list", help="List of ip addresses or ranges | Ex: 0.0.0.0/24,5.5.5.5,6.6.6.6")
    parser.add_argument("match", help='Ex: "welcome to site.com"')
    parser.add_argument("-u", "--uri", help="Ex: /en/index.aspx", default="/")
    parser.add_argument("-t", "--threads", help="", type=int, default=10)
    parser.add_argument("-T", "--timeout", help="", type=int, default=3)
    parser.add_argument(
        "-v", "--verbose", help="Verbose mode", dest="verbose", action="store_true"
    )

    args = parser.parse_args()

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format=LOGGING_FORMAT, datefmt='%H:%M:%S')

    try:
        main(args)
    except KeyboardInterrupt:
        print("\nStopped")
        sys.exit()
