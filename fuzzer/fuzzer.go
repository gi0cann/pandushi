package fuzzer

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// HTTPRequest represents an scanner HTTP request
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
