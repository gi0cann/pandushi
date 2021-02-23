# Pandushi is a web application fuzzer

Pandushi keeps track of every fuzz case and the injection type used for later manual analysis.

## Key features

* Store every request and response with their injection and injection type (sqli, xss, xxe, cmdi, os injection, etc.)
* Extensible collection of payloads

## Wish list

- [x] Add option to scan data to a file by passing file:// URI on the command line.
- [x] Add option to scan data to mongodb by passing mongodb:// URI on the command line.
- [ ] Add option to scan data to elasticsearch by passing elastic:// URI on the command line.
- [ ] Add option to scan data to an REST API by passing http:// URI on the command line.
- [ ] Build front-end to analyze the scan data

## TODO

- [x] Create injection/payload type
- [x] Create custom http request type
- [x] Create custom http response type
- [x] Create TestCase type to countain information about each individual injection (Request, Response, injection, injection type, injeciton point type, injection point location, total duration, status, response code)
- [x] Create function to count total injection points, url path injection points, query injection points, header injection points, cookie injection points, body injection points
- [x] Inject request headers
- [x] Inject request body x-www-form-urlencoded parameters
- [ ] Inject request body multipart/form-data parameters
- [x] Inject request body application/json parameters
- [ ] Inject request body application/xml parameters
- [x] Inject request query parameters
- [x] Inject request uri path
- [x] Inject marked (§§) requests
- [x] Store finished task with testcase in mongodb
- [x] Add check to make sure target is live before initiating scan
- [x] Write payload importer
- [ ] Deduplicate payloads
- [x] Force https

## Design notes

* Create different a type of fuzzing tasks for each injection point type (url path, query parameters, headers, cookies, request body x-www-form-urlencoded, request body multipart/form-data, request body json)
* Each injection point types get its own function that takes a list of injection types (sqli, xss, xxe, etc.)
* These functions will follow the following pattern:
  1. For each injection point
  2. Grab all inputs from the mongodb database 
  3. Loop over the inputs
  4. Create a new request for the current input
  5. Send the newly created request or add it to a queue TBD (To be decided)
  6. Get Response and store Request and Response with injection info to mongodb

### Approach #1 for injecting parameters into a request

#### Query parameters
1. inject payload in URL.RawQuery or http.Request.Form
2. Submit request
