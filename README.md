![banner](images/banner.png)

Scan websites for LFI vulnerabilities and path traversals.

> *The speed of multithreading, with all the precision you'll need*

---

## Usage

*Alfie* is used in three steps:

1. `filter` mode: 
   Determine your HTTP status code (`-fc`), response word count (`-fw`), and response size (`-fs`) filters
2. `scan` mode:
   Attempt to find one valid path traversal (+/- encoding, +/- bypasses) to one of the test files. 
   Success is determined by the filters from the first step.
3. `enum` mode:
   Given the example LFI from a successful run of `scan` mode, try to find as many files as possible

> I'll use the HackTheBox lab *Download* as an example in the following sections. Spoiler alert! :warning:

### STEP 1 - Filter mode

Run Alfie in filter mode to have it try to determine the best filters to use. It fires a bunch of random test payloads at the target (not actual filepaths, just random data) and reads the responses, building a simple statistical model of how the server responded.

> :point_up: Alfie attempts to find filter values that will eliminate responses within two standard deviations of the mean.

The filters that Alfie calculates can be used for the subsequent `scan` and `enum` modes.

##### Example

```bash
python3 alfie.py -u "http://download.htb/files/download/" --threads 50 filter
```

![Finding filters](images/Finding%20filters.gif)

You should be able to just copy-paste the green text for `scan` and `enum` mode :slightly_smiling_face:

### STEP 2 - Scan mode

The filters we determined in [`filter` mode](#step-1---filter-mode) become the metric for "success" in `scan` and `enum` mode. 

> Any combination of HTTP **status codes** (`-fs`), **word counts** (`-fw`), and response **sizes** (`-fs`) can be used as filters.
>
> If it's convenient, you can even uses ranges and comma-separated lists, like `-fw 12-14,166` :heart:

If you already know a little about your target, it's helpful to specify tags for it. In the next example, we already know that the target is a Linux server running NodeJS. We also know that it's likely we'll find *relative filepaths*:

> :bulb: Knowing a bit about your target will vastly improve your scan speeds!

```bash
python3 alfie.py -u "http://download.htb/files/download/" --max 1 --target_system 'linux,node' --threads 50 -fc '404'  -fw '12,13,14,166' scan -rel
```

![scanning for valid enum](images/scanning%20for%20valid%20enum.gif)

If successful, `scan` mode will report the first success it achieves. Copy the green, bold text in the output for use in `enum` mode.

### STEP 3 - Enum mode

**Enum**eration mode is when we get a list of files accessible on the target. All you need to do is provide the `-ex` or `--example-lfi` parameter to scan mode.

> :warning: Since the `--example-lfi` argument is *required* for enum mode, you <u>must</u> specify it *after the positional argument "enum"*

```bash
python3 alfie.py -u "http://download.htb/files/download/" --max 1 --target_system 'linux,node' --threads 50 -fc '404'  -fw '12,13,14,166' enum --example-lfi '..%2fapp.js'
```

![enum mode](images/enum%20mode.gif)

### Logging

For logging of your results, use the `-o` or `--output` argument. The output is a text file with one positive result per line, and can be easily read by other scripts or programs. Here is a sample:

```
http://download.htb/files/download/%2e%2e%2fpackage.json
http://download.htb/files/download/%2e%2e%2fapp.js
http://download.htb/files/download/..%2fapp.js
http://download.htb/files/download/..%2fpackage.json
```

## Options / Arguments

By default, **Alfie** will output any non-default options you provide as arguments:

![options display](images/options%20display.png)

You can suppress this behavior and hide the banner with the `-q` or `--quiet` flag (in case you want to pipe the output to another program).

### Positional Arguments

| Argument | Description |
|----------|-------------|
| `{filter,scan,enum,batch}` | Mode of operation. |
| `filter` | Attempt to establish a baseline of which responses should be filtered. The most likely filters will be suggested. |
| `scan` | Find a valid path traversal. The program will make requests using various traversals until at least one non-relative filepath is found. |
| `enum` | Use a known path traversal, and try to enumerate files on the target system. If possible, attempts will be made to gain RCE. |
| `batch` | Automatically run "filter" mode, then "scan" mode, then "enum" mode. |

### Options

| Argument | Description |
|----------|-------------|
| `-h, --help` | Show this help message and exit. |
| `-u URL, --url URL` | Base URL of the target. Ex. "http://mywebsite.tld/index.php?page=". |

### Display / Output

Affect the way that Alfie looks.

| Argument | Description |
|----------|-------------|
| `--version` | Show program's version number and exit. |
| `-v, --verbose` | Show extra output to console. Does not affect log file verbosity. |
| `--no-color` | Don't ANSI color escapes in console output. |
| `--quiet` | Don't print the banner or options. |
| `-o OUTPUT, --output OUTPUT` | File to log positive results. |

### Traversal

Affect the bounds and method of traversal.

| Argument | Description |
|----------|-------------|
| `--min MIN` | Minimum number of steps "back" to traverse. |
| `--max MAX` | Maximum number of steps "back" to traverse. |

### Request

Affect how requests are sent to the target.

| Argument | Description |
|----------|-------------|
| `--target_system TARGET_SYSTEM` | List of attributes of the target system, to help choose what files to check for. No spaces. Ex "linux,php". Choose attributes from this list: any, windows, ruby, rails, xampp, apache, python, js, node, nginx, php, linux. |
| `-t THREADS, --threads THREADS` | Number of threads to use for processing. |
| `--timeout TIMEOUT` | Timeout for each request (in seconds). |
| `-X REQUEST_TYPE, --request-type REQUEST_TYPE` | Type of HTTP request to use. Ex "POST". |
| `-b COOKIES, --cookies COOKIES` | Cookies to include in each request. Ex "key1=value1; key2=value2" (Tip: use document.cookie in browser console). |
| `-H HEADERS, --headers HEADERS` | Extra headers to include in each request. Use semicolons as a separator. Ex "Host: 4wayhandshake.test.tld; Authorization: Bearer 23456.hgfds.234567890". |
| `-d DATA, --data DATA` | Data to include in each request. Only applies if using a POST request (see -X option). Ex "key1=value1; key2=value2". |

### Response

Affect how responses are received and processed.

| Argument | Description |
|----------|-------------|
| `-fs FILTER_SIZES, --filter-sizes FILTER_SIZES` | Comma-separated list of sizes (in bytes) to filter from the results. |
| `-fw FILTER_WORDS, --filter-words FILTER_WORDS` | Comma-separated list of word counts to filter from the results. |
| `-fc FILTER_CODES, --filter-codes FILTER_CODES` | Comma-separated list of HTTP status codes to filter from the results. |

### Scan Mode Arguments

| Argument | Description |
|----------|-------------|
| `-rel, --relative-only` | Only use relative paths in scan mode. Great for finding files like `package.json` (Defaults to false when not specified). |

### Enum Mode Arguments

| Argument | Description |
|----------|-------------|
| `-ex EXAMPLE_LFI, --example-lfi EXAMPLE_LFI` | Example of a traversal that successfully discloses a local file (the bold part of the output of "scan" mode). Ex. `/../../../etc/passwd`. |
| `-nx, --no-extra-tests` | Don't run the extra LFI tests (only useful for WAF evasion). |



## Change Log

- 1.0.0:
  - [x] Runs successfully. Mimics behaviour of my [LFI-Enumerator bash script](https://github.com/4wayhandshake/LFI-Enumerator).
- 1.1.0:
  - [x] Add a `-o` switch to output results to a file.
  - [x] Include a banner with all non-default options shown
- 1.2.0:
  - [x] Improve parsing of arguments `--cookie` and `--data` so that it uses browser-like formatting.
- 1.3.0:
  - [x] Added "extra checks" mechanism to automate tests for things like insecure PHP modules
  - [x] Started using semantic versioning
  - [x] Updated README and `--help` to include `--no-extra-checks` and `--version`
- 1.3.1:
  - [x] Added additional "extra checks" for other types of LFIs
  - [x] Replaced `--ending` option with `--no-ending-checks`: it now checks for null-byte termination by default.
- 2.0.0:
  - [x] Huge rewrite. Split everything into `filter`, `scan` and `enum` mode. Left a stub for `batch` mode where all three other modes are completed sequentially.
  - [x] Overhauled the way that path traversals are generated, making the whole process a lot more hands-off by default.
  - [x] Greatly improved the degree of control over requests, and how things get scanned.
  - [x] Hueristic-based filter suggestion during `filter` mode means you no longer need to run it in verbose initially
  - [x] Early exit during `scan` mode, so that we only attempt to find one successful LFI, then use that pattern to enumerate
  - [x] Added an accompanying `file-list.json` that controls which files are used for scanning vs enumeration
  - [x] Added the ability to include regex-powered variables within the filepaths listed in `file-list.json`
- 2.1.0:
  - [x] Added progress spinner
  - [x] Included the ability to specify custom request headers (not just cookies)
  - [x] You can now `scan` for only the relative-filepath targets (good for finding stuff like `package.json` instead of `/etc/passwd`)
  - [x] Amended this README to show new options/args




## To-Do
- [ ] Figure out why extra tests aren't working
- [ ] Log errors to a log file instead of the screen
- [ ] Separate out the PHP-only tests. 
  - https://www.php.net/manual/en/wrappers.php.php
  - https://www.php.net/manual/en/filters.php
- [ ] Encoding mutations should apply to the whole payload, not just the traversal
- [ ] Add `batch` mode: where `filter` leads into `scan` which leads into `enum`.
- [ ] Add interactive `enum` mode, that allows you to just drop into a prompt where you can request specific files if you'd rather.
- [ ] Allow dumping all file contents acquired in `enum` mode into some kind of output directory. 
- [ ] Make the whole view a little wider (nobody's using this on their phone :sweat_smile:)

**Please :star: this repo if you found it useful!**


---

Enjoy,

:handshake::handshake::handshake::handshake:
@4wayhandshake
