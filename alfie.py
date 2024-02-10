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
parser.add_argument('-b', '--cookies', dest='cookies', help='Cookies to include in each request. Ex "key1=value1; key2=value2".', type=str)
parser.add_argument('-d', '--data', dest='data', help='Data to include in each request. Only applies if using a POST request (see -X option). Ex "key1=value1; key2=value2".', type=str)
parser.add_argument('-X', '--request-type', dest='request_type', help='Type of HTTP request to use. Ex "POST".', type=str, default='GET')
parser.add_argument('-fs', '--filter-sizes', dest='filter_sizes', help='Comma-separated list of sizes (in bytes) to filter from the results.', type=str)
parser.add_argument('-fw', '--filter-words', dest='filter_words', help='Comma-separated list of word counts to filter from the results.', type=str)
parser.add_argument('-fc', '--filter-codes', dest='filter_codes', help='Comma-separated list of HTTP status codes to filter from the results.', type=str, default='400,401,402,403,404,405')
parser.add_argument('-o', '--output', dest='output', help='File to log positive results.', type=str)
parser.add_argument('--quiet', dest='quiet', action='store_true', help='Don\'t print the banner or options.')
parser.add_argument('-nc', '--no-color', dest='colorless', action='store_true', help='Don\'t ANSII colors in console output.')

args = parser.parse_args()

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

banner_colorless = '''
           ,ggg,
          dP""8I   ,dPYb, ,dPYb,                   ,,,,,,,,,,,,
         dP   88   IP'`Yb IP'`Yb                  : AUTOMATIC  :
        dP    88   I8  8I I8  8I   gg             : LOCAL      :
       ,8'    88   I8  8' I8  8'   ""             : FILE       :
       d88888888   I8 dP  I8 dP    gg    ,ggg,    : INCLUSION  :
 __   ,8"     88   I8dP   I8dP     88   i8" "8i   : ENUMERATOR :
dP"  ,8P      Y8   I8P    I8P      88   I8, ,8I    ````````````
Yb,_,dP       `8b,,d8b,_ ,d8b,_  _,88,_ `YbadP'    by
 "Y8P"         `Y88P'"Y88PI8"88888P""Y8888P"Y888   4wayhandshake
                          I8 `8,                        🤝🤝🤝🤝
//#//#//#//#//#//#//#//#/ I8  `8, //#//#//#//#//
                          I8   8I
                          I8   8I
                          I8, ,8'
                           "Y8P'
'''

banner = '''\033[94m
           ,ggg,
          dP""8I   ,dPYb, ,dPYb,                  \033[92m ,,,,,,,,,,,,  \033[0m \033[94m
         dP   88   IP'`Yb IP'`Yb                  \033[92m: AUTOMATIC  : \033[0m \033[94m
        dP    88   I8  8I I8  8I   gg             \033[92m: LOCAL      : \033[0m \033[94m
       ,8'    88   I8  8' I8  8'   ""             \033[92m: FILE       : \033[0m \033[94m
       d88888888   I8 dP  I8 dP    gg    ,ggg,    \033[92m: INCLUSION  : \033[0m \033[94m
 __   ,8"     88   I8dP   I8dP     88   i8" "8i   \033[92m: ENUMERATOR : \033[0m \033[94m
dP"  ,8P      Y8   I8P    I8P      88   I8, ,8I   \033[92m ```````````` \033[0m \033[94m
Yb,_,dP       `8b,,d8b,_ ,d8b,_  _,88,_ `YbadP'   \033[92m by \033[0m \033[94m
 "Y8P"         `Y88P'"Y88PI8"88888P""Y8888P"Y888  \033[92m 4wayhandshake \033[0m \033[94m
                          I8 `8,                        🤝🤝🤝🤝
//#//#//#//#//#//#//#//#/ I8  `8, //#//#//#//#//
                          I8   8I
                          I8   8I
                          I8, ,8'
                           "Y8P'\033[0m
'''
# See https://manytools.org/hacker-tools/ascii-banner/ for banner creation
# Font (nscript) by Normand Veilleux <nveilleu@emr.ca> Oct 7, 1994
# figletized by Peter Samuelson <psamuels@hmc.edu> Nov 29, 1994

s = requests.session()
exit_flag = False # Global flag to signal threads to exit
successes = []

# Use some globals to store info used in every request
filter_codes = []
filter_sizes = []
filter_words = []
request_cookie = None
request_data = None

def stringToDict(s):
    # Parse a cookie-like string into a dict
    key_value_pairs = [e.strip() for e in s.split(';')]
    dict = {}
    for kvp in key_value_pairs:
        k, v = kvp.split('=',1)
        # According to the HTTP cookie specification (RFC 6265),
        # cookie values cant contain semicolon, comma, or whitespace
        if any((c == ';' or c == ',' or c.isspace()) for c in v):
            raise ValueError
        dict[k] = v
    if len(dict) == 0:
        raise ValueError
    return dict

def parseCookie(s):
    cookie_dict = stringToDict(s)
    # return a requests cookiejar from a dictionary
    return requests.utils.cookiejar_from_dict(cookie_dict)

def parseData(s):
    return stringToDict(s)

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
        global request_cookie
        try:
            request_cookie = parseCookie(args.cookies)
        except ValueError as e:
            if args.colorless:
                print(f'Warning: invalid cookies provided.\nPlease use this format: "key1=value1; key2=value2".\nProceeding without cookies.\n')
            else:
                print(f'{colors.MAGENTA}Warning: invalid cookies provided.{colors.END}\nPlease use this format: "key1=value1; key2=value2".\nProceeding without cookies.\n')
            request_cookie = None
        except Exception as e:
            if args.colorless:
                print(f'An error occurred while parsing cookies:\n{e}\n')
            else:
                print(f'{colors.MAGENTA}An error occurred while parsing cookies:{colors.END}\n{e}\n')
            sys.exit(1)

    if args.data:
        global request_data
        try:
            request_data = parseData(args.data)
        except ValueError as e:
            if args.colorless:
                print(f'Warning: invalid request data provided.\nPlease use this format: "key1=value1; key2=value2".\nProceeding without request data.\n')
            else:
                print(f'{colors.MAGENTA}Warning: invalid request data provided.{colors.END}\nPlease use this format: "key1=value1; key2=value2".\nProceeding without request data.\n')
            request_data = None
        except Exception as e:
            if args.colorless:
                print(f'An error occurred while parsing request data:\n{e}\n')
            else:
                print(f'{colors.MAGENTA}An error occurred while parsing request data:{colors.END}\n{e}\n')
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
            if args.colorless:
                print(f"{' '*64}\n[+] {url:<60}\n    HTTP {code:<8} Size: {bytes:<12} Words: {words:<20}")
            else:
                print(f"{' '*64}\n{colors.GREEN}[+] {url:<60}{colors.END}\n    HTTP {code:<8} Size: {bytes:<12} Words: {words:<20}")
        else:
            if args.colorless:
                print(f"[+] {url:<60}")
            else:
                print(f"{colors.GREEN}[+] {url:<60}{colors.END}")
    elif args.verbose:
        if args.colorless:
            print(f"{' '*64}\n[-] {url:<60}\n    HTTP {code:<8} Size: {bytes:<12} Words: {words:<20}")
        else:
            print(f"{' '*64}\n{colors.RED}[-] {url:<60}{colors.END}\n    HTTP {code:<8} Size: {bytes:<12} Words: {words:<20}")
    return ret

def makeRequest(url):
    try:
        if args.request_type.upper() == 'POST':
            response = requests.post(url, cookies=request_cookie, json=request_data, timeout=args.timeout)
        else:
            response = requests.get(url, cookies=request_cookie, timeout=args.timeout)
        if matches(response, url):
            global successes
            successes.append(url)
    except requests.RequestException as e:
        if args.colorless:
            print(f'An error occurred while making a request to {url}:\n{e}\n')
        else:
            print(f'{colors.MAGENTA}An error occurred while making a request to {url}:{colors.END}\n{e}\n')

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

def writeLogfile(filename, successful_urls):
    if (filename[0] in '/\\'):
        filepath = filename # absolute path was provided
    else:
        # relative path was provided
        filepath = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(filepath, 'w') as f:
            for url in successful_urls:
                f.write(url+'\n')
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' could not be found.")
    except PermissionError:
        print(f"Error: Permission denied. Unable to write to the file '{file_path}'.")
    except Exception as e:
        print(f"While writing the output file, an unexpected error occurred: {e}")

def printOptions():
    print('='*64)
    print(f'URL: {args.url:>59}')
    if args.verbose:
        print('Verbose mode')
    if args.lfi_wordlist != parser.get_default('lfi_wordlist'):
        print(f'LFI wordlist: {args.lfi_wordlist:>50}')
    if args.fuzz_wordlist != parser.get_default('fuzz_wordlist'):
        print(f'Fuzz wordlist: {args.fuzz_wordlist:>49}')
    if args.threads != parser.get_default('threads'):
        print(f'Threads: {args.threads:>55}')
    if args.filter_codes != parser.get_default('filter_codes'):
        print(f'HTTP code filter: {args.filter_codes.upper():>46}')
    if args.filter_sizes != parser.get_default('filter_sizes'):
        print(f'Size filter (bytes): {args.filter_sizes:>43}')
    if args.filter_words != parser.get_default('filter_words'):
        print(f'Word count filter (# words): {args.filter_words:>35}')
    if args.min != parser.get_default('min'):
        print(f'Minimum traversal steps: {args.min:>39}')
    if args.max != parser.get_default('max'):
        print(f'Maximum traversal steps: {args.max:>39}')
    if args.timeout != parser.get_default('timeout'):
        print(f'Timeout: {args.timeout:>54}s')
    if args.request_type != parser.get_default('request_type'):
        print(f'Request type: {args.request_type.upper():>50}')
    if args.cookies:
        print(f'Cookies: {args.cookies:>55}')
    if args.data:
        print(f'Data: {args.data:>58}')
    if args.ending != parser.get_default('ending'):
        s = f'"{args.ending}"'
        print(f'Ending string: {s:>49}')
    if args.output:
        print(f'Output file: {args.output:>51}')
    print('='*64+'\n')

def main():
    if not args.quiet:
        if args.colorless:
            print(banner_colorless)
        else:
            print(banner)
        printOptions()
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
    num_jobs = url_queue.qsize()
    N = min(args.threads, num_jobs)
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
    if args.output:
        writeLogfile(args.output, successes)
    return num_jobs

if __name__ == "__main__":
    start_time = time.time()
    n = main()
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\nComplete: {n} requests in {elapsed:.1f}s ({n/elapsed:.0f} req/s)")
