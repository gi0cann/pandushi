package fuzzer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// HTTPRequest represents a fuzzer HTTP request
type HTTPRequest struct {
	Request     *http.Request
	RequestText string // String representation of the Request
}

// NewHTTPRequestFromBytes take a []byte and returns a HTTPRequest
func NewHTTPRequestFromBytes(reqstr []byte) (req HTTPRequest, err error) {
	req.RequestText = string(reqstr)
	reader := bytes.NewReader(reqstr)
	bufreader := bufio.NewReader(reader)
	request, err := http.ReadRequest(bufreader)
	if err != nil {
		return req, err
	}
	request.RequestURI = ""
	newurl, err := url.Parse("http://" + request.Host + request.URL.Path + "?" + request.URL.RawQuery)
	if err != nil {
		return req, err
	}
	request.URL = newurl
	req.Request = request
	return req, nil
}

// NewHTTPRequestFromRequest takes a http.Request and returns a HTTPRequest
func NewHTTPRequestFromRequest(r *http.Request) (req HTTPRequest) {
	req.Request = r
	req.RequestText = string("test")
	return req
}

// RequestToString takes a http.Request and returns a string
func RequestToString(r *http.Request) (string, error) {
	var RequestStr bytes.Buffer
	RequestStr.WriteString(r.Method + " ")
	RequestStr.WriteString(r.URL.Path + " ")
	RequestStr.WriteString(r.Proto + "\r\n")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return RequestStr.String(), err
	}
	if r.ContentLength != -1 {
		r.Header.Set("Content-Lenght", strconv.FormatInt(int64(len(body)), 10))
	}
	for key, header := range r.Header {
		RequestStr.WriteString(key + ": " + strings.Join(header, " ") + "\r\n")
	}
	RequestStr.WriteString("\r\n" + string(body) + "\r\n")
	return RequestStr.String(), nil
}

// HTTPResponse represents a fuzzer HTTP response
type HTTPResponse struct {
	Response     *http.Response
	ResponseText string // String representation of the Response
}

// NewHTTPResponseFromBytes take a []byte and returns a HTTPResponse
func NewHTTPResponseFromBytes(resstr []byte, req *http.Request) (res HTTPResponse, err error) {
	res.ResponseText = string(resstr)
	reader := bytes.NewReader(resstr)
	bufreader := bufio.NewReader(reader)
	response, err := http.ReadResponse(bufreader, req)
	if err != nil {
		return res, err
	}
	req.Response = response
	return res, nil
}

// ResponseToString takes a http.Response and returns a string
func ResponseToString(r *http.Response) (string, error) {
	var ResponseStr bytes.Buffer
	ResponseStr.WriteString(r.Proto + " ")
	ResponseStr.WriteString(r.Status + "\r\n")
	for key, header := range r.Header {
		ResponseStr.WriteString(key + ": " + strings.Join(header, " ") + "\r\n")
	}
	var body []byte
	var reader io.ReadCloser
	switch r.Header.Get("Content-Encoding") {
	case "gzip":
		var err error
		reader, err = gzip.NewReader(r.Body)
		if err != nil {
			return ResponseStr.String(), err
		}
	default:
		reader = r.Body
	}
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		return ResponseStr.String(), err
	}
	ResponseStr.WriteString("\r\n" + string(body) + "\r\n")
	return ResponseStr.String(), nil
}

// NewHTTPResponse takes a http.Response and returns a HTTPResponse
func NewHTTPResponse(baseres *http.Response) (res HTTPResponse, err error) {
	res.Response = baseres
	resStr, err := ResponseToString(baseres)
	if err != nil {
		return res, err
	}
	res.ResponseText = resStr
	return res, nil
}
