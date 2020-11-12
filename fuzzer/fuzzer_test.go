package fuzzer

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/gi0cann/pandushi/payloads"
)

func TestInjectJSONParameters(t *testing.T) {
	tests := []struct {
		inputRequest           string
		expectedTotalTestCases int8
		injection              payloads.Payload
	}{
		{
			`POST /test.php HTTP/1.1
Host: pbanner.gi0cann.io
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 45

{"foo":"bar", "hello":"world", "bar": "foo"}`,
			int8(3),
			payloads.Payload{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		},
		{
			`POST /test.php HTTP/1.1
Host: pbanner.gi0cann.io
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 114

{"test": [{"hello":"world", "pizza":"cheese", "foo": ["a", "b", "c"]}], "go": {"1": "3", "2": ["hello", "world"]}}`,
			int8(8),
			payloads.Payload{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		},
	}

	for _, tt := range tests {
		count := int8(0)
		req, err := NewHTTPRequestFromBytes([]byte(tt.inputRequest))
		if err != nil {
			t.Fatalf("Error creating HTTPRequest using NewHTTPRequestFromBytes: %s", err)
		}

		TestCases := req.InjectJSONParameters([]payloads.Payload{tt.injection})

		count = int8(len(TestCases))

		if count != tt.expectedTotalTestCases {
			t.Errorf("Expected: %d TotalTestCases got: %d", tt.expectedTotalTestCases, count)
		}
	}
}

func TestInjectFormURLEncodedBody(t *testing.T) {
	tests := []struct {
		inputRequest           string
		expectedTotalTestCases int8
		injection              payloads.Payload
	}{
		{
			`POST /test.php HTTP/1.1
Host: pbanner.gi0cann.io
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

foo=bar&hello=world`,
			int8(2),
			payloads.Payload{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		},
		{
			`POST /test.php HTTP/1.1
Host: pbanner.gi0cann.io
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

foo=bar&hello=world&bar=foo`,
			int8(3),
			payloads.Payload{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		},
	}

	for _, tt := range tests {
		count := int8(0)
		req, err := NewHTTPRequestFromBytes([]byte(tt.inputRequest))
		if err != nil {
			t.Fatalf("Error creating HTTPRequest using NewHTTPRequestFromBytes: %s", err)
		}

		TestCases := req.InjectFormURLEncodedBody([]payloads.Payload{tt.injection})

		for _, TestCase := range TestCases {
			PostParams := TestCase.Request.Request.PostForm
			for k := range PostParams {
				if PostParams.Get(k) == tt.injection.Value {
					count++
				}
			}
		}

		if count != tt.expectedTotalTestCases {
			t.Errorf("Expected: %d TotalTestCases got: %d", tt.expectedTotalTestCases, count)
		}
	}
}

func TestInjectHeaders(t *testing.T) {
	tests := []struct {
		inputRequest           string
		expectedTotalTestCases int8
		injection              payloads.Payload
	}{
		{
			`GET /test.php?foo=bar&hello=world HTTP/1.1
Host: pbanner.gi0cann.io
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

`,
			int8(5),
			payloads.Payload{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		},
	}

	for _, tt := range tests {
		count := int8(0)
		req, err := NewHTTPRequestFromBytes([]byte(tt.inputRequest))
		if err != nil {
			t.Fatalf("Error creating HTTPRequest using NewHTTPRequestFromBytes")
		}

		TestCases := req.InjectHeaders([]payloads.Payload{tt.injection})

		for _, TestCase := range TestCases {
			headers := TestCase.Request.Request.Header
			for k := range headers {
				if headers.Get(k) == tt.injection.Value {
					count++
				}
			}
		}

		if count != tt.expectedTotalTestCases {
			t.Errorf("Expected: %d TotalTestCases got: %d", tt.expectedTotalTestCases, count)
		}
	}

}

func TestInjectQueryParameters(t *testing.T) {
	tests := []struct {
		inputRequest     string
		expectedRequests []string
		injection        payloads.Payload
	}{
		{
			`GET /test.php?foo=bar&hello=world HTTP/1.1
Host: pbanner.gi0cann.io
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

`,
			[]string{
				"GET /test.php?foo=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&hello=world HTTP/1.1\r\n",
				"GET /test.php?foo=bar&hello=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\n",
			},
			payloads.Payload{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		},
	}

	for _, tt := range tests {
		request, err := NewHTTPRequestFromBytes([]byte(tt.inputRequest))
		if err != nil {
			t.Fatalf("Error create HTTPRequest from Bytes: %s\n", err)
		}

		InjectedTestCases := request.InjectQueryParameters([]payloads.Payload{tt.injection})
		//t.Log(InjectedRequests)

		if len(tt.expectedRequests) != len(InjectedTestCases) {
			t.Fatalf("Expected HTTPRequest.InjectQueryParameters to return %d requests got %d\n", len(tt.expectedRequests), len(InjectedTestCases))
		}

		for i, req := range tt.expectedRequests {
			currentTestCase := InjectedTestCases[i]
			firstline := strings.Split(currentTestCase.Request.RequestText, "\r\n")[0] + "\r\n"
			if firstline != req {
				t.Errorf("Injected request doesn't match expected request.\nexpected:\n%s\ngot:\n%s\n", req, firstline)
			}
		}
	}
}

func TestCountJSONBody(t *testing.T) {
	tests := []struct {
		input         string
		expectedCount int8
	}{
		{
			`{"hello":"world"}`,
			1,
		},
		{
			`{"hello":"world", "pizza":"cheese", "foo":"bar"}`,
			3,
		},
		{
			`{"hello": ["world", "lol"]}`,
			2,
		},
		{
			`{"obj": {"hello": "world", "pizza":"cheese", "foo":"bar"}}`,
			3,
		},
		{
			`{"test": [{"hello":"world", "pizza":"cheese"}]}`,
			2,
		},
		{
			`{"test": [{"hello":"world", "pizza":"cheese", "foo": ["a", "b", "c"]}], "go": {"1": "3", "2": ["hello", "world"]}}`,
			8,
		},
	}

	for _, tt := range tests {
		reader := ioutil.NopCloser(strings.NewReader(tt.input))
		JSONInterface, _, err := ByteToJSONInterface(reader)
		if err != nil {
			t.Fatalf("Error parsing JSON string: %s\n", err)
		}

		total := CountJSONBody(JSONInterface)

		if total != tt.expectedCount {
			t.Errorf("total did not match expectedCount on input %s. expected: %d got: %d\n", tt.input, tt.expectedCount, total)
		}
	}
}

func TestCountingInjectionPoints(t *testing.T) {
	tests := []struct {
		input               string
		expectedPathCount   int8
		expectedCookieCount int8
		expectedHeaderCount int8
		expectedQueryCount  int8
		expectedBodyCount   int8
		expectedTotalCount  int8
	}{
		{
			`GET /?q=hello HTTP/1.1
Host: github.com
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

`,
			1,
			0,
			10,
			1,
			0,
			12,
		},
		{
			`POST /1.1/jot/client_event.json HTTP/1.1
Host: api.twitter.com
Connection: close
Content-Length: 1044
x-twitter-client-language: en
x-csrf-token: 29b13902476d063119eb45e64b499f02
authorization: Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA
content-type: application/x-www-form-urlencoded
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
x-guest-token: 1298697166744096776
x-twitter-active-user: no
Origin: https://twitter.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://twitter.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: personalization_id="v1_m1X67HiXxMWOO2SVGGlymA=="; guest_id=v1%3A159846850781121896; gt=1298697166744096776; ct0=29b13902476d063119eb45e64b499f02; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCLfQJSx0AToMY3NyZl9p%250AZCIlNDczYzMyNDQwYmQ2YzkxMDBiOGMxNzVkOTZhMmFkMjM6B2lkIiU1ZWE5%250ANDlhODE3ZTQzMDQ4ZWRlNTYxYzFhYjk1NDRhZQ%253D%253D--1e6afb44360f4ac78c7e6f33833704ce424779c0; external_referer=padhuUp37zjgzgv1mFWxJ12Ozwit7owX|0|8e8t2xd8A2w%3D; _ga=GA1.2.1526578839.1598468512; _gid=GA1.2.1748207117.1598468512

category=perftown&log=%5B%7B%22description%22%3A%22rweb%3Aurt%3Aexplore-web_sidebar%3Afetch_Initial%3Asuccess%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A1159%7D%2C%7B%22description%22%3A%22rweb%3Aurt%3Aexplore-web_sidebar%3Afetch_Initial%3Aformat%3Asuccess%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A1161%7D%2C%7B%22description%22%3A%22rweb%3Ascroller%3Attfv%3Ascroller_v3%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A542%7D%2C%7B%22description%22%3A%22rweb%3Aurt%3Aexplore-web_sidebar%3Afetch_Initial%3Asuccess%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A887%7D%2C%7B%22description%22%3A%22rweb%3Aurt%3Aexplore-web_sidebar%3Afetch_Initial%3Aformat%3Asuccess%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A888%7D%2C%7B%22description%22%3A%22rweb%3Aurt%3Asearch%3Afetch_Initial%3Asuccess%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A1342%7D%2C%7B%22description%22%3A%22rweb%3Aurt%3Asearch%3Afetch_Initial%3Aformat%3Asuccess%22%2C%22product%22%3A%22rweb%22%2C%22duration_ms%22%3A1348%7D%5D`,
			3,
			8,
			18,
			0,
			2,
			31,
		},
		{
			`POST / HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:29.0) Gecko/20100101 Firefox/29.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: __atuvc=34%7C7; permanent=0; _gitlab_session=226ad8a0be43681acf38c2fab9497240; __profilin=p%3Dt; request_method=GET
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266
Content-Length: 554

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="text"

text default
-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file1"; filename="a.txt"
Content-Type: text/plain

Content of a.txt.

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file2"; filename="a.html"
Content-Type: text/html

<!DOCTYPE html><title>Content of a.html.</title>

-----------------------------9051914041544843365972754266--
`,
			1,
			5,
			8,
			0,
			3,
			17,
		},
		{
			`POST /api/v2/client/sites/1783312/visit-data?sv=6 HTTP/1.1
Host: in.hotjar.com
Connection: close
Content-Length: 191
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Content-Type: text/plain; charset=UTF-8
Accept: */*
Origin: https://www.logitech.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.logitech.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

{"window_width":956,"window_height":1098,"url":"https://www.logitech.com/en-us","r_value":1,"is_vpv":false,"session_only":false,"rec_value":1,"user_id":"c5da6a65-eb05-5eac-9867-36ce7342d1c0"}`,
			6,
			0,
			12,
			1,
			8,
			27,
		},
		{
			`POST /api/v2/client/sites/1783312/visit-data?sv=6 HTTP/1.1
Host: in.hotjar.com
Connection: close
Content-Length: 209
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Content-Type: application/json; charset=UTF-8
Accept: */*
Origin: https://www.logitech.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.logitech.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

{"hello":[34.4,34],"window_width":956,"window_height":1098,"url":"https://www.logitech.com/en-us","r_value":1,"is_vpv":false,"session_only":false,"rec_value":1,"user_id":"c5da6a65-eb05-5eac-9867-36ce7342d1c0"}`,
			6,
			0,
			12,
			1,
			10,
			29,
		},
	}

	for _, tt := range tests {

		request, err := NewHTTPRequestFromBytes([]byte(tt.input))
		if err != nil {
			t.Fatalf("Error creating HTTPRequest from bytes %s\n", err)
		}

		if request.TotalPathInjectionPoints != tt.expectedPathCount {
			t.Errorf("Total path injection points don't match the expected total. Expected: %d got: %d\n", tt.expectedPathCount, request.TotalPathInjectionPoints)
		}

		if request.TotalCookieInjectionPoints != tt.expectedCookieCount {
			t.Errorf("Total cookie injection points don't match the expected total. Expected: %d got: %d\n", tt.expectedCookieCount, request.TotalCookieInjectionPoints)
		}

		if request.TotalHeaderInjectionPoints != tt.expectedHeaderCount {
			t.Errorf("Total header injection points don't match the expected total. Expected: %d got: %d\n", tt.expectedHeaderCount, request.TotalHeaderInjectionPoints)
		}

		if request.TotalQueryInjectionPoints != tt.expectedQueryCount {
			t.Errorf("Total query injection points don't match the expected total. Expected: %d got: %d\n", tt.expectedQueryCount, request.TotalQueryInjectionPoints)
		}

		if request.TotalBodyInjectionPoints != tt.expectedBodyCount {
			t.Errorf("Total body injection points don't match the expected total. Expected: %d got: %d\n", tt.expectedBodyCount, request.TotalBodyInjectionPoints)
		}

		if request.TotalInjectionPoints != tt.expectedTotalCount {
			t.Errorf("Total injection points don't match the expected total. Expected: %d got: %d\n", tt.expectedTotalCount, request.TotalInjectionPoints)
		}
	}
}

func TestParsingHTTPRequestFromBytes(t *testing.T) {
	tests := []struct {
		input            string
		expectedMethod   string
		expectedHost     string
		expectedProtocol string
		expectedHeaders  http.Header
	}{
		{
			`GET / HTTP/1.1
Host: github.com
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

`,
			"GET",
			"github.com",
			"HTTP/1.1",
			map[string][]string{
				"Connection":                {"close"},
				"Upgrade-Insecure-Requests": {"1"},
				"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36"},
				"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"Sec-Fetch-Site":            {"none"},
				"Sec-Fetch-Mode":            {"navigate"},
				"Sec-Fetch-User":            {"?1"},
				"Sec-Fetch-Dest":            {"document"},
				"Accept-Encoding":           {"gzip, deflate"},
				"Accept-Language":           {"en-US,en;q=0.9"},
			},
		},
	}

	for _, tt := range tests {

		request, err := NewHTTPRequestFromBytes([]byte(tt.input))
		if err != nil {
			t.Fatalf("Error creating HTTPRequest from bytes %s\n", err)
		}

		if request.RequestText != tt.input {
			t.Errorf("request.RequestText doesn't match input. expected:\n%s \n--\n got:\n%s\n", tt.input, request.RequestText)
		}

		if request.Request.Method != tt.expectedMethod {
			t.Errorf("request.Request.Method doesn't match input. expected: %s got: %s\n", tt.expectedMethod, request.Request.Method)
		}

		if request.Request.Host != tt.expectedHost {
			t.Errorf("request.Request.Host doesn't match input. expected: %s got: %s\n", tt.expectedHost, request.Request.Host)
		}

		if request.Request.Proto != tt.expectedProtocol {
			t.Errorf("request.Request.Proto doesn't match input. expected: %s got: %s\n", tt.expectedProtocol, request.Request.Proto)
		}

		for k := range tt.expectedHeaders {
			if request.Request.Header.Get(k) != tt.expectedHeaders.Get(k) {
				t.Errorf("request.Request.Header doesn't match input. expected: %s got: %s\n", tt.expectedHeaders.Get(k), request.Request.Header.Get(k))
			}
		}

	}

}

// func TestRequestToString(t *testing.T) {
// 	tests := []struct {
// 		inputRequest    string
// 		expectedRequest string
// 	}{
// 		{
// 			`POST /test.php HTTP/1.1
// Host: pbanner.gi0cann.io
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
// Accept-Encoding: gzip, deflate
// Accept-Language: en-US,en;q=0.9
// Connection: close
// Content-Type: application/x-www-form-urlencoded
// Content-Length: 19

// foo=bar&hello=world`,
// 			`POST /test.php HTTP/1.1
// Host: pbanner.gi0cann.io
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
// Accept-Encoding: gzip, deflate
// Accept-Language: en-US,en;q=0.9
// Connection: close
// Content-Type: application/x-www-form-urlencoded
// Content-Length: 19

// foo=bar&hello=world`,
// 		},
// 		{
// 			`POST /api/v2/client/sites/1783312/visit-data?sv=6 HTTP/1.1
// Host: in.hotjar.com
// Connection: close
// Content-Length: 209
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
// Content-Type: application/json; charset=UTF-8
// Accept: */*
// Origin: https://www.logitech.com
// Sec-Fetch-Site: cross-site
// Sec-Fetch-Mode: cors
// Sec-Fetch-Dest: empty
// Referer: https://www.logitech.com/
// Accept-Encoding: gzip, deflate
// Accept-Language: en-US,en;q=0.9

// {"hello":[34.4,34],"window_width":956,"window_height":1098,"url":"https://www.logitech.com/en-us","r_value":1,"is_vpv":false,"session_only":false,"rec_value":1,"user_id":"c5da6a65-eb05-5eac-9867-36ce7342d1c0"}`,
// 			`POST /api/v2/client/sites/1783312/visit-data?sv=6 HTTP/1.1
// Host: in.hotjar.com
// Connection: close
// Content-Length: 209
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
// Content-Type: application/json; charset=UTF-8
// Accept: */*
// Origin: https://www.logitech.com
// Sec-Fetch-Site: cross-site
// Sec-Fetch-Mode: cors
// Sec-Fetch-Dest: empty
// Referer: https://www.logitech.com/
// Accept-Encoding: gzip, deflate
// Accept-Language: en-US,en;q=0.9

// {"hello":[34.4,34],"window_width":956,"window_height":1098,"url":"https://www.logitech.com/en-us","r_value":1,"is_vpv":false,"session_only":false,"rec_value":1,"user_id":"c5da6a65-eb05-5eac-9867-36ce7342d1c0"}`,
// 		},
// 	}

// 	for _, tt := range tests {
// 		req, err := NewHTTPRequestFromBytes([]byte(tt.inputRequest))
// 		if err != nil {
// 			t.Fatalf("Error creating request from bytes: %s", err)
// 		}
// 		requeststr, err := RequestToString(req.Request)
// 		if err != nil {
// 			t.Fatalf("Error converting request to string: %s", err)
// 		}

// 		t.Logf("RequestText:\n%s\n", requeststr)
// 		if tt.expectedRequest != requeststr {
// 			t.Errorf("expected:\n%s\ngot:\n%s\n", tt.expectedRequest, requeststr)
// 			body, err := ioutil.ReadAll(req.Request.Body)
// 			if err != nil {
// 				t.Errorf("Error reading body: %s\n", err)
// 			}
// 			t.Errorf("Body: %s\n len: %d", body, len(body))
// 			for k, v := range req.Request.Form {
// 				t.Errorf("K: %s, v: %s\n", k, v)
// 			}
// 		}
// 	}
// }
