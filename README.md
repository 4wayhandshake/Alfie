# Alfie
**A**utomatic **L**ocal **F**ile **I**nclusion **E**numerator

Scan websites for LFI vulnerabilities and path traversals. Multi-threaded for max speed; tasteful filters for max precision.

## Usage

Good fuzzing requires separating false-positives from the actual results. **Start with Alfie by determining which filters to apply** - just like you might do with `ffuf` or `gobuster`.

In this example, a known false-positive is identified, then it's size is used as a filter:

![false-positive](false-positive.gif)

Any combination of HTTP status codes, word counts, and response sizes can be used as filters. 

Next, **apply the filter and do a non-verbose run**. In this example, the LFI stands out right away, leading to the hidden file `package.json`:

![lfi-test](lfi-test.gif)



## Options

```html
  -h, --help            
	show this help message and exit

  -v, --verbose         
	Show each requested url, along with the status code, size, and words in the response.
	Use this to help determine your filters.

  -u URL, --url URL     
	Base URI of the target. Ex. "http://mywebsite.htb/index.php?page="

  -f FUZZ_WORDLIST, --fuzz-wordlist FUZZ_WORDLIST
	Wordlist of "interesting" files to check for. 
	This wordlist should have one filename per line, with file extensions if applicable.

  -w LFI_WORDLIST, --wordlist LFI_WORDLIST
	Wordlist to use for LFI strings. 
	If not using the default, it should be similar format to lfi-list.txt.

  -t THREADS, --threads THREADS
	Number of threads to use for processing.

  --min MIN             
	Minimum number of steps "back" to traverse.

  --max MAX             
	Maximum number of steps "back" to traverse.

  --timeout TIMEOUT     
	Timeout for each request (in seconds).

  --ending ENDING       
	A character to append to the end of each test url. Ex. "%00".

  -c COOKIES, --cookies COOKIES
	Cookies to include in each request. 
	Ex '{"key1": "value1", "key2": "value2"}'.

  -d DATA, --data DATA  
	Data to include in each request. Only applies if using a POST request (see -X option).
    Ex '{"key1": "value1", "key2": "value2"}'.

  -X REQUEST_TYPE, --request-type REQUEST_TYPE
	Type of HTTP request to use. Ex "POST".

  -fs FILTER_SIZES, --filter-sizes FILTER_SIZES
	Comma-separated list of sizes (in bytes) to filter from the results.

  -fw FILTER_WORDS, --filter-words FILTER_WORDS
	Comma-separated list of word counts to filter from the results.

  -fc FILTER_CODES, --filter-codes FILTER_CODES
	Comma-separated list of HTTP status codes to filter from the results.

```



## To Do

[ ] Add a `-o` switch to output results to a file.
[ ] Include a banner
[ ] Include a progress meter, with guesses per second and an estimated runtime.
[ ] Improve parsing of arguments `--cookie` and `--data` so that it isn't so strict about formatting.



Please :star: this repo if you found it useful!


---

Enjoy, 

:handshake::handshake::handshake::handshake:
@4wayhandshake