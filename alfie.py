#!/usr/bin/env python3
import sys
import concurrent.futures
import requests
import argparse
import os
import time
import queue
import signal
import json


# This is necessary for disabling the 'verify=False' warning
import urllib3
urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    prog='alfie.py',
    description='''The Automatic Local File Inclusion Enumerator.
    Scan websites for local file inclusion vulnerabilities.''',
    epilog='Author: 4wayhandshake')

parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Show each requested url, along with the status code, size, and words in the response. Use this to help determine your filters.')
parser.add_argument('-u', '--url', dest='url', help='Base URI of the target. Ex. "http://mywebsite.htb/index.php?page="', type=str, required=True)
parser.add_argument('-f', '--fuzz-wordlist', dest='fuzz_wordlist', help='Wordlist of "interesting" files to check for. This wordlist should have one filename per line, with file extensions if applicable.', type=str, required=True)
parser.add_argument('-w', '--wordlist', dest='lfi_wordlist', help='Wordlist to use for LFI strings. If not using the default, it should be similar format to lfi-list.txt.', type=str, default='lfi-list.txt')
parser.add_argument('-t', '--threads', dest='threads', help='Number of threads to use for processing.', type=int, default=10)
parser.add_argument('--min', dest='min', help='Minimum number of steps "back" to traverse.', type=int, default=1)
parser.add_argument('--max', dest='max', help='Maximum number of steps "back" to traverse.', type=int, default=10)
parser.add_argument('--timeout', dest='timeout', help='Timeout for each request (in seconds).', type=int, default=5)
parser.add_argument('--ending', dest='ending', help='A character to append to the end of each test url. Ex. "%%00".', type=str)
parser.add_argument('-c', '--cookies', dest='cookies', help='Cookies to include in each request. Ex \'{"key1": "value1", "key2": "value2"}\'.', type=str)
parser.add_argument('-d', '--data', dest='data', help='Data to include in each request. Only applies if using a POST request (see -X option). Ex \'{"key1": "value1", "key2": "value2"}\'.', type=str)
parser.add_argument('-X', '--request-type', dest='request_type', help='Type of HTTP request to use. Ex "POST".', type=str, default='GET')
parser.add_argument('-fs', '--filter-sizes', dest='filter_sizes', help='Comma-separated list of sizes (in bytes) to filter from the results.', type=str)
parser.add_argument('-fw', '--filter-words', dest='filter_words', help='Comma-separated list of word counts to filter from the results.', type=str)
parser.add_argument('-fc', '--filter-codes', dest='filter_codes', help='Comma-separated list of HTTP status codes to filter from the results.', type=str, default='400,401,402,403,404,405')

args = parser.parse_args()
s = requests.session()
exit_flag = False # Global flag to signal threads to exit
successes = []
filter_codes = []
filter_sizes = []
filter_words = []

def validateArgs():

    def isPositiveInt(x):
        return x >= 0

    def allPositiveInts(l):
        for e in l:
            if not isPositiveInt(e):
                return False
        return True

    if args.request_type.upper() not in ['GET','POST']:
        print("Invalid request type provided. Only GET and POST are supported")
        sys.exit(1)

    if args.min < 0:
        print("Invalid miminum depth provided. Minimum LFI depth must be at least 0")
        sys.exit(1)

    global filter_codes
    filter_codes = [int(x) for x in args.filter_codes.split(',')]
    if not allPositiveInts(filter_codes):
        print("Invalid filter-codes argument. All must be positive integers")
        sys.exit(1)

    if args.filter_sizes:
        global filter_sizes
        filter_sizes = [int(x) for x in args.filter_sizes.split(',')]
        if not allPositiveInts(filter_sizes):
            print("Invalid filter-sizes argument. All must be positive integers")
            sys.exit(1)

    if args.filter_words:
        global filter_words
        filter_words = [int(x) for x in args.filter_sizes.split(',')]
        if not allPositiveInts(filter_words):
            print("Invalid filter-words argument. All must be positive integers")
            sys.exit(1)

    if args.cookies:
        try:
            json.loads(args.cookies)
        except:
            print('Invalid cookie provided. Please use a format like \'{"key1": "value1", "key2": "value2"}\'')
            sys.exit(1)

    if args.data:
        try:
            json.loads(args.data)
        except:
            print('Invalid data provided. Please use a format like \'{"key1": "value1", "key2": "value2"}\'')
            sys.exit(1)

def loadWordlist(filename):
    if (filename[0] in '/\\'):
        # absolute path was provided
        filepath = filename
    else:
        # relative path was provided
        filepath = os.path.join(os.path.dirname(__file__), filename)
    # Read the file, remove the whitespace from each line
    with open(filepath, 'r') as f:
        return [ line.rstrip() for line in f.readlines() ]

def matches(resp, url):
    ret = True
    code = int(resp.status_code)
    bytes = len(resp.content)
    words = len(resp.text.split())
    if code in filter_codes:
        ret = False
    if bytes in filter_sizes:
        ret = False
    if words in filter_words:
        ret = False
    if ret:
        if args.verbose:
            print(f"\n[+] {url}\n    HTTP {code:<8} Size: {bytes:<12} Words: {words:<12}")
        else:
            print(f"[+] {url}")
    elif args.verbose:
        print(f"\n[-] {url}\n    HTTP {code:<8} Size: {bytes:<12} Words: {words:<12}")
    return ret

def makeRequest(url):
    c = json.loads(args.cookies) if args.cookies else None
    d = json.loads(args.data) if args.data else None
    try:
        if args.request_type.upper() == 'POST':
            response = requests.post(url, cookies=c, json=d, timeout=args.timeout)
        else:
            response = requests.get(url, cookies=c, timeout=args.timeout)
        if matches(response, url):
            successes.append(url)
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def processUrls(url_queue):
    global exit_flag
    while not exit_flag:
        try:
            url = url_queue.get(timeout=1)
        except queue.Empty:
            exit_flag = True
            continue
        except Exception as e:
            print(e)
        if url is not None:
            makeRequest(url)
            url_queue.task_done()

def signalHandler(signum, frame):
    global exit_flag
    exit_flag = True
    print("\nCancelling enumeration...\n")

def main():
    # Register the signal handler for SIGINT
    signal.signal(signal.SIGINT, signalHandler)
    # Validate the args provided
    validateArgs()
    # load the wordlists
    lfi_words = loadWordlist(args.lfi_wordlist)
    fuzz_words = loadWordlist(args.fuzz_wordlist)
    ending = args.ending if args.ending else ''
    # Create a queue and populate it with tests
    url_queue = queue.Queue()
    for depth in range(args.min, args.max+1):
        for w in lfi_words:
            for f in fuzz_words:
                if exit_flag:
                    break
                url = f'{args.url}{depth*w}{f}{ending}'
                url_queue.put(url)
    # Using ThreadPoolExecutor for asynchronous web requests with a limited number of threads
    N = min(args.threads,url_queue.qsize())
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as executor:
        # Submit the process_urls function for each worker thread
        workers = [executor.submit(processUrls, url_queue) for _ in range(N)]
        # Wait for all tasks to complete
        try:
            # Wait for all tasks to complete
            while not exit_flag:
                time.sleep(1)
        except KeyboardInterrupt:
            print("")
        # Stop the worker threads by adding None to the queue for each worker
        for _ in range(N):
            url_queue.put(None)
        # Wait for all worker threads to finish
        concurrent.futures.wait(workers)

if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    print(f"Time taken: {end_time - start_time} seconds")