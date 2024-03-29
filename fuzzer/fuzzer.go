package fuzzer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gi0cann/pandushi/payloads"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// SuccessCodes http success response codes
var SuccessCodes = []int{
	100,
	101,
	102,
	103,

	200,
	201,
	202,
	203,
	204,
	205,
	206,
	207,
	208,
	226,

	300,
	301,
	302,
	303,
	304,
	305,

	307,
	308,
}

// ErrorCodes http error response codes
var ErrorCodes = []int{
	400,
	401,
	402,
	403,
	404,
	405,
	406,
	407,
	408,
	409,
	410,
	411,
	412,
	413,
	414,
	415,
	416,
	417,
	418,
	421,
	422,
	423,
	424,
	425,
	426,
	428,
	429,
	431,
	451,
	500,
	501,
	502,
	503,
	504,
	505,
	506,
	507,
	508,
	510,
	511,
}

// MarkerRegex is the default request injection marker regex string
const MarkerRegex = `§(.*?)§`

// HTTPRequest represents a fuzzer HTTP request
type HTTPRequest struct {
	Request                    *http.Request
	RequestText                string // String representation of the Request
	TotalInjectionPoints       int8   // Total number of injection points
	TotalPathInjectionPoints   int8   // Total number of URL path injection points
	TotalCookieInjectionPoints int8   // Total number of Cookie injection points
	TotalHeaderInjectionPoints int8   // Total number of Cookie injection points
	TotalQueryInjectionPoints  int8   // Total number of Query injection points
	TotalBodyInjectionPoints   int8   // Total number of Body injection points
	ForceTLS                   bool   // Force request to use TLS/SSL
}

// NewHTTPRequestFromBytes take a []byte and returns a HTTPRequest
func NewHTTPRequestFromBytes(reqstr []byte, forceTLS bool) (req HTTPRequest, err error) {
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
	req.CountInjectionPoints()
	req.ForceTLS = forceTLS
	if forceTLS {
		req.Request.URL.Scheme = "https"
	}
	return req, nil
}

// HTTPRequestToJSONInterface take a HTTPRequest pointer and returns a JSON interface
func HTTPRequestToJSONInterface(req *HTTPRequest) (interface{}, error) {
	JSONInterface, bodyBytes, err := ByteToJSONInterface(req.Request.Body)
	req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	if err != nil {
		return 0, err
	}
	return JSONInterface, nil
}

// ByteToJSONInterface takes a byte array as input and returns JSON inteface
func ByteToJSONInterface(r io.ReadCloser) (interface{}, []byte, error) {
	var JSONInterface interface{}
	input, err := ioutil.ReadAll(r)
	if err != nil {
		return 0, input, err
	}
	//fmt.Println(input)
	err = json.Unmarshal(input, &JSONInterface)
	if err != nil {
		return JSONInterface, input, err
	}
	return JSONInterface, input, nil
}

//CountJSONBody take http.Request and return total amount of parameters
func CountJSONBody(jsoni interface{}) int8 {
	count := int8(0)
	m := jsoni.(map[string]interface{})
	for k, v := range m {
		switch vv := v.(type) {
		case string:
			count++
		case int:
			count++
		case float64:
			count++
		case []interface{}:
			for _, vi := range vv {
				switch vi.(type) {
				case map[string]interface{}:
					count += CountJSONBody(vi)
				default:
					count++
				}

			}
		case bool:
			count++
		case map[string]interface{}:
			count += CountJSONBody(v)
		default:
			fmt.Printf("default: key:%s, value:%v, type:%T\n", k, v, v)
		}
	}
	return count
}

// CountInjectionPoints takes a http.Request and return to total amount of injection points
func (req *HTTPRequest) CountInjectionPoints() {
	r := req.Request
	req.TotalInjectionPoints = int8(0)
	req.TotalBodyInjectionPoints = int8(0)
	req.TotalQueryInjectionPoints = int8(len(r.URL.Query()))
	req.TotalInjectionPoints += req.TotalQueryInjectionPoints
	req.TotalHeaderInjectionPoints = int8(len(r.Header))
	req.TotalInjectionPoints += req.TotalHeaderInjectionPoints
	req.TotalPathInjectionPoints = int8(0)
	for _, p := range strings.Split(r.URL.Path, "/") {
		p = strings.TrimSpace(p)
		if p != "" {
			req.TotalPathInjectionPoints++
		}
	}
	if req.TotalPathInjectionPoints == 0 {
		req.TotalInjectionPoints++
		req.TotalPathInjectionPoints++
	} else {
		req.TotalInjectionPoints += req.TotalPathInjectionPoints
	}
	req.TotalCookieInjectionPoints = int8(len(r.Cookies()))
	req.TotalInjectionPoints += req.TotalCookieInjectionPoints
	ContentType := r.Header.Get("content-type")
	if ContentType == "application/x-www-form-urlencoded" {
		body, err := ioutil.ReadAll(req.Request.Body)
		if err == nil {
			req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}
		err = r.ParseForm()
		if err == nil {
			req.TotalBodyInjectionPoints = int8(len(r.PostForm))
			req.TotalInjectionPoints += req.TotalBodyInjectionPoints
		}
		req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	} else if strings.Contains(ContentType, "multipart/form-data") {
		err := r.ParseMultipartForm(4096000)
		if err == nil {
			req.TotalBodyInjectionPoints += int8(len(r.MultipartForm.File))
			req.TotalBodyInjectionPoints += int8(len(r.MultipartForm.Value))
			req.TotalInjectionPoints += req.TotalBodyInjectionPoints
		}
	} else if strings.Contains(ContentType, "application/json") {
		JSONInterface, err := HTTPRequestToJSONInterface(req)
		if err != nil {
			fmt.Println("ContInjectionPoints", err)
		} else {
			jsoncount := CountJSONBody(JSONInterface)
			req.TotalBodyInjectionPoints += jsoncount
			req.TotalInjectionPoints += jsoncount
		}
	} else if strings.Contains(ContentType, "text/plain") {
		JSONInterface, err := HTTPRequestToJSONInterface(req)
		if err != nil {
			fmt.Println("ContInjectionPoints", err)
		} else {
			jsoncount := CountJSONBody(JSONInterface)
			req.TotalBodyInjectionPoints += jsoncount
			req.TotalInjectionPoints += jsoncount
		}
	}

}

// NewHTTPRequestFromRequest takes a http.Request and returns a HTTPRequest
func NewHTTPRequestFromRequest(r *http.Request, forceTLS bool) (req HTTPRequest) {
	req.Request = r
	RequestText, err := RequestToString(req.Request)
	if err != nil {
		req.RequestText = ""
	} else {
		req.RequestText = RequestText
	}
	req.CountInjectionPoints()
	req.ForceTLS = forceTLS
	if forceTLS {
		req.Request.URL.Scheme = "https"
	}
	return req
}

// RequestToString takes a http.Request and returns a string
func RequestToString(r *http.Request) (string, error) {
	var RequestStr bytes.Buffer
	//query, _ := url.QueryUnescape(r.URL.RawQuery)
	query := r.URL.RawQuery
	RequestStr.WriteString(r.Method + " ")
	RequestStr.WriteString(r.URL.Path + "?" + query + " ")
	RequestStr.WriteString(r.Proto + "\r\n")
	RequestStr.WriteString("Host: " + r.Host + "\r\n")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return RequestStr.String(), err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	for key, header := range r.Header {
		RequestStr.WriteString(key + ": " + strings.Join(header, " ") + "\r\n")
	}
	RequestStr.WriteString("\r\n" + string(body) + "\r\n")
	return RequestStr.String(), nil
}

// IsMarked check for injection markers inside of a request and return true if found or false if not found.
func (req *HTTPRequest) IsMarked() bool {
	Marker := regexp.MustCompile(MarkerRegex)
	return Marker.MatchString(req.RequestText)
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

// TestCase contain information about a fuzz case such as request, response, injection, etc.
type TestCase struct {
	BaseRequest        HTTPRequest
	Request            HTTPRequest
	Response           HTTPResponse
	Injection          string
	InjectionType      string
	InjectionPoint     string
	InjectionPointType string
	Duration           string
	Status             string
}

// SerializedTestCase is the BSON serialized version of TestCase
type SerializedTestCase struct {
	Request            string `bson:"request,omitempty"`
	Response           string `bson:"response,omitempty"`
	Injection          string `bson:"injection,omitempty"`
	InjectionType      string `bson:"injectiontype,omitempty"`
	InjectionPoint     string `bson:"injectionpoint,omitempty"`
	InjectionPointType string `bson:"injectionpointtype,omitempty"`
	Duration           string `bson:"duration,omitempty"`
}

// Serialize return a serialize version of TestCase
func (TC *TestCase) Serialize() SerializedTestCase {
	return SerializedTestCase{
		Request:            TC.Request.RequestText,
		Response:           TC.Response.ResponseText,
		Injection:          TC.Injection,
		InjectionType:      TC.InjectionType,
		InjectionPoint:     TC.InjectionPoint,
		InjectionPointType: TC.InjectionPointType,
		Duration:           TC.Duration,
	}
}

// SupportedInjectionPointTypes is a list of supported injection point types
var SupportedInjectionPointTypes = []string{
	"QUERY",
	"JSON",
	"FORM_URLENCODE",
	"HEADER",
	"PATH",
	"MARKED",
}

// CreateTestCases takes a arrays of InjectionPointType, InjectionType, and a mongodbURI and returns an array of TestCases
func CreateTestCases(injectionpointtypes []string, injectiontypes []string, mongodbURI string, request HTTPRequest) ([]TestCase, error) {
	var testcases []TestCase
	payloadArr, err := payloads.CreatePayloadsFromInputTypes(injectiontypes, mongodbURI)
	if err != nil {
		return testcases, err
	}

	for _, injectionpointtype := range injectionpointtypes {
		injectionpointtype = strings.ToUpper(injectionpointtype)
		if injectionpointtype == "QUERY" {
			testcases = append(testcases, request.InjectQueryParameters(payloadArr)...)
		}

		if injectionpointtype == "JSON" {
			testcases = append(testcases, request.InjectJSONParameters(payloadArr)...)
		}

		if injectionpointtype == "FORM_URLENCODE" {
			testcases = append(testcases, request.InjectFormURLEncodedBody(payloadArr)...)
		}

		if injectionpointtype == "HEADER" {
			testcases = append(testcases, request.InjectHeaders(payloadArr)...)
		}

		if injectionpointtype == "PATH" {
			testcases = append(testcases, request.InjectPath(payloadArr)...)
		}

		if injectionpointtype == "MARKED" {
			testcases = append(testcases, request.InjectMarked(payloadArr)...)
		}
	}

	return testcases, nil
}

// Task represents a Fuzzer task
type Task struct {
	Project        string
	Name           string
	InjectionTypes []string
	BaseRequest    HTTPRequest
	Start          time.Time
	End            time.Time
	State          string
	TestCases      []TestCase
}

// SerializedTask is the bson serialized version of Task
type SerializedTask struct {
	Project     string               `bson:"project"`
	Name        string               `bson:"name"`
	BaseRequest string               `bson:"baserequest"`
	Start       time.Time            `bson:"start"`
	End         time.Time            `bson:"end"`
	TestCases   []SerializedTestCase `bson:"testcases"`
}

// Serialize returns a serialized version of Task
func (T *Task) serialize() SerializedTask {
	task := SerializedTask{
		Project:     T.Project,
		Name:        T.Name,
		BaseRequest: T.BaseRequest.RequestText,
		Start:       T.Start,
		End:         T.End,
	}
	for _, tc := range T.TestCases {
		task.TestCases = append(task.TestCases, tc.Serialize())
	}
	return task
}

// NewTask takes a list of InjectionTypes and HTTPRequest and returns a FuzzerTask
func NewTask(Project string, Name string, InjectionTypes []string, InjectionPointTypes []string, BaseRequest HTTPRequest, mongodbURI string) (Task, error) {
	var task Task
	TestCases, err := CreateTestCases(InjectionPointTypes, InjectionTypes, mongodbURI, BaseRequest)
	if err != nil {
		return task, err
	}
	task = Task{
		Project:        Project,
		Name:           Name,
		InjectionTypes: InjectionTypes,
		BaseRequest:    BaseRequest,
		TestCases:      TestCases,
	}

	return task, nil
}

// Run starts and run a fuzzer Task
func (T *Task) Run(TotalThreads int, storageconfig StorageConfig, Proxy *url.URL) {
	if TotalThreads == 0 {
		TotalThreads = 10
	}

	T.Start = time.Now()
	T.Name += "_" + T.Start.Format(time.RFC3339)
	fmt.Printf("Project Name: %s\n", T.Project)
	fmt.Printf("Scan Name: %s\n", T.Name)
	var mutex = &sync.Mutex{}
	var wg sync.WaitGroup
	for i := range T.TestCases {
		for j := 0; j < TotalThreads; j++ {
			wg.Add(1)
			mutex.Lock()
			go func(i int) {
				defer wg.Done()
				testcase := &(T.TestCases[i])
				var transportConfig *http.Transport = &http.Transport{
                    Proxy: http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				}
                if Proxy != nil {
                    transportConfig.Proxy = http.ProxyURL(Proxy)
                }
                var transport http.RoundTripper = transportConfig
				httpclient := http.Client{
					Timeout:   time.Duration(120 * time.Second),
					Transport: transport,
				}

				testcase.Request.Request.Close = true
				resp, err := httpclient.Do(testcase.Request.Request)
				if err != nil {
					fmt.Printf("Task.Run httpclient error: %s\n", err)
				} else {
					httpres, err := NewHTTPResponse(resp)
					if err != nil {
						fmt.Printf("Task.Run NewHTTPResponse error: %s\n", err)
					} else {
						testcase.Response = httpres
					}
				}
				testcase.Status = "Done"
			}(i)
			mutex.Unlock()
		}
		wg.Wait()
	}
	T.End = time.Now()
	serializedTask := T.serialize()

	if storageconfig.UseMongoDB {
		err := ResultsToMongoDB(storageconfig.MongoDBURI, serializedTask)
		if err != nil {
			log.Printf("Run ResultsToMongoDB error: %s\n", err)
		}
	}

	if storageconfig.UseFile {
		err := ResultsToFile(storageconfig.FileURI, serializedTask)
		if err != nil {
			log.Printf("Run ResultsToFile error: %s\n", err)
		}
	}
}

// InjectQueryParameters take an array of payloads and return an array of TestCases with the payloads injected into query parameters
func (req *HTTPRequest) InjectQueryParameters(injections []payloads.Payload) []TestCase {
	var InjectedTestCases []TestCase
	query := req.Request.URL.Query()
	for _, injection := range injections {
		for k := range query {
			NewQuery := url.Values{}
			for ik, v := range query {
				NewQuery.Set(ik, strings.Join(v, ""))
			}
			NewQuery.Set(k, injection.Value)
			rawquery := NewQuery.Encode()
			NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(req.RequestText), req.ForceTLS)
			if err != nil {
				fmt.Printf("Error Creating HTTPRequest: %s", err)
			} else {
				NewHTTPRequest.Request.URL.RawQuery = rawquery
				NewRequestText, err := RequestToString(NewHTTPRequest.Request)
				if err == nil {
					NewHTTPRequest.RequestText = NewRequestText
				}
				InjectedTestCases = append(InjectedTestCases, TestCase{
					BaseRequest:        *req,
					Request:            NewHTTPRequest,
					Injection:          injection.Value,
					InjectionType:      injection.InputType,
					InjectionPoint:     k,
					InjectionPointType: "query",
					Status:             "queued",
				})
			}

		}
	}

	return InjectedTestCases
}

func arrayContains(arr []string, item string) bool {
	for _, v := range arr {
		if v == item {
			return true
		}
	}
	return false
}

// InjectHeaders takes a array of payloads and returns an array of TestCases with the payloads injected in the headers
func (req *HTTPRequest) InjectHeaders(injections []payloads.Payload) []TestCase {
	exclusions := []string{
		"cookie",
		"content-length",
		"connection",
	}
	var InjectedTestCases []TestCase
	headers := req.Request.Header
	for _, injection := range injections {
		for k := range headers {
			NewHeaders := headers.Clone()
			if arrayContains(exclusions, strings.ToLower(k)) {
				continue
			}
			NewHeaders.Set(k, injection.Value)
			NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(req.RequestText), req.ForceTLS)
			if err != nil {
				fmt.Printf("Error Creating HTTPRequest: %s", err)
			} else {
				NewHTTPRequest.Request.Header = NewHeaders
				NewRequestText, err := RequestToString(NewHTTPRequest.Request)
				if err == nil {
					NewHTTPRequest.RequestText = NewRequestText
				}
				InjectedTestCases = append(InjectedTestCases, TestCase{
					BaseRequest:        *req,
					Request:            NewHTTPRequest,
					Injection:          injection.Value,
					InjectionType:      injection.InputType,
					InjectionPoint:     k,
					InjectionPointType: "headers",
					Status:             "queued",
				})
			}
		}
	}

	return InjectedTestCases
}

// InjectFormURLEncodedBody takes a array of payloads and return an array of TestCases with the payloads injected in a x-www-form-urlencoded HTTP request body
func (req *HTTPRequest) InjectFormURLEncodedBody(injections []payloads.Payload) []TestCase {
	var InjectedTestCases []TestCase
	ContentType := req.Request.Header.Get("Content-Type")
	if ContentType == "x-www-form-urlencoded" {
		return InjectedTestCases
	}
	PostBody := req.Request.PostForm
	for _, injection := range injections {
		for k := range PostBody {
			NewPostBody := url.Values{}
			for ik, v := range PostBody {
				NewPostBody.Set(ik, strings.Join(v, ""))
			}
			NewPostBody.Set(k, injection.Value)
			rawbody := NewPostBody.Encode()
			NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(req.RequestText), req.ForceTLS)
			if err != nil {
				fmt.Printf("Error Creating HTTPRequest: %s", err)
			} else {
				NewHTTPRequest.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(rawbody)))
				NewHTTPRequest.Request.Header.Set("Content-Length", strconv.Itoa(len(rawbody)))
				NewHTTPRequest.Request.ContentLength = 0
				NewRequestText, err := RequestToString(NewHTTPRequest.Request)
				if err == nil {
					NewHTTPRequest.RequestText = NewRequestText
				}
				NewHTTPRequest.Request.PostForm = nil
				NewHTTPRequest.Request.Form = nil
				NewHTTPRequest.Request.ParseForm()
				InjectedTestCases = append(InjectedTestCases, TestCase{
					BaseRequest:        *req,
					Request:            NewHTTPRequest,
					Injection:          injection.Value,
					InjectionType:      injection.InputType,
					InjectionPoint:     k,
					InjectionPointType: "x-www-form-urlencoded",
					Status:             "queued",
				})
			}
		}
	}

	return InjectedTestCases
}

// InjectPath takes an array of payloads and returns an array of TestCases with the payloads injected in the URI path
func (req *HTTPRequest) InjectPath(injections []payloads.Payload) []TestCase {
	var InjectedTestCases []TestCase
	for _, injection := range injections {
		pathList := strings.Split(req.Request.URL.Path, "/")
		pathList = pathList[1:]
		for i := range pathList {
			current := strings.Split(req.Request.URL.Path, "/")
			current = current[1:]
			current[i] = injection.Value
			NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(req.RequestText), req.ForceTLS)
			if err != nil {
				fmt.Printf("Error Creating HTTPRequest: %s\n", err)
			} else {
				NewHTTPRequest.Request.URL.Path = "/" + strings.Join(current, "/")
				NewHTTPRequest.Request.URL.RawPath = "/" + strings.Join(current, "/")
				NewRequestText, err := RequestToString(NewHTTPRequest.Request)
				if err == nil {
					NewHTTPRequest.RequestText = NewRequestText
				}
				InjectedTestCases = append(InjectedTestCases, TestCase{
					BaseRequest:        *req,
					Request:            NewHTTPRequest,
					Injection:          injection.Value,
					InjectionType:      injection.InputType,
					InjectionPoint:     pathList[i],
					InjectionPointType: "path",
					Status:             "queued",
				})
			}
		}
	}
	return InjectedTestCases
}

// InjectJSONParameters takes a array of payloads and returns a array of TestCases with the payloads injected in the JSON body of each HTTP request
func (req *HTTPRequest) InjectJSONParameters(injections []payloads.Payload) []TestCase {
	var InjectedTestCases []TestCase
	var marks []string
	count := 0
	ContentType := req.Request.Header.Get("Content-Type")
	if !(strings.Contains(ContentType, "application/json") || strings.Contains(ContentType, "application/text")) {
		fmt.Printf("Not JSON %s\n", ContentType)
		return InjectedTestCases
	}
	JSONInterface, err := HTTPRequestToJSONInterface(req)
	if err != nil {
		fmt.Printf("HTTPRequestToJSONInterface error: %s\n", err)
		return InjectedTestCases
	}
	m := JSONInterface.(map[string]interface{})
	MarkedJSONInterface := markjson(m, &count, &marks, `§`)
	jsonBytes, err := json.Marshal(MarkedJSONInterface)
	if err != nil {
		fmt.Println(err)
	}

	for _, injection := range injections {
		for _, v := range marks {
			pattern := regexp.MustCompile(`§` + v + `.*?§`)
			injected := pattern.ReplaceAll(jsonBytes, []byte(injection.Value))
			for _, vi := range marks {
				pattern := regexp.MustCompile(`§` + vi + `.*?§`)
				pattern2 := regexp.MustCompile(`§` + vi + `(.*?)§`)
				submatch := pattern2.FindSubmatch(injected)
				if len(submatch) != 2 {
					continue
				}
				replacer := submatch[1]
				injected = pattern.ReplaceAll(injected, replacer)
			}
			NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(req.RequestText), req.ForceTLS)
			if err != nil {
				fmt.Printf("Error Creating HTTPRequest: %s", err)
			} else {
				NewHTTPRequest.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(injected)))
				NewHTTPRequest.Request.Header.Set("Content-Length", strconv.Itoa(len(injected)))
				NewHTTPRequest.Request.ContentLength = 0
				NewRequestText, err := RequestToString(NewHTTPRequest.Request)
				if err == nil {
					NewHTTPRequest.RequestText = NewRequestText
				}
				InjectedTestCases = append(InjectedTestCases, TestCase{
					BaseRequest:        *req,
					Request:            NewHTTPRequest,
					Injection:          injection.Value,
					InjectionType:      injection.InputType,
					InjectionPoint:     "",
					InjectionPointType: "json",
					Status:             "queued",
				})
			}
		}
	}

	return InjectedTestCases
}

// InjectMarked takes a array of payloads and returns a array of TestCases with the payloads injected in the JSON body of each HTTP request
func (req *HTTPRequest) InjectMarked(injections []payloads.Payload) []TestCase {
	var InjectedTestCases []TestCase

	if req.IsMarked() {
		pattern := regexp.MustCompile(`§.*?§`)
		indexes := pattern.FindAllStringIndex(req.RequestText, -1)
		current := 0
		reqArr := make([]string, len(indexes)+1)
		for i, index := range indexes {
			reqArr[i] = string(req.RequestText[current:index[1]])
			current = index[1]
		}
		reqArr[len(reqArr)-1] = string(req.RequestText[current:])
		for _, injection := range injections {
			for i := range indexes {
				newReqArr := make([]string, len(reqArr))
				copy(newReqArr, reqArr)
				newReqArr[i] = pattern.ReplaceAllString(newReqArr[i], injection.Value)
				newReqString := strings.Join(newReqArr, "")
				newReqString = pattern.ReplaceAllString(newReqString, "")
				NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(newReqString), req.ForceTLS)

				if err != nil {
					newReqArr = make([]string, len(reqArr))
					copy(newReqArr, reqArr)
					newReqArr[i] = pattern.ReplaceAllString(newReqArr[i], url.QueryEscape(injection.Value))
					newReqString = strings.Join(newReqArr, "")
					newReqString = pattern.ReplaceAllString(newReqString, "")
					NewHTTPRequest, err = NewHTTPRequestFromBytes([]byte(newReqString), req.ForceTLS)
				}
				if err != nil {
					fmt.Printf("Error Creating HTTPRequest: %s", err)
				} else {
					InjectedTestCases = append(InjectedTestCases, TestCase{
						BaseRequest:        *req,
						Request:            NewHTTPRequest,
						Injection:          injection.Value,
						InjectionType:      injection.InputType,
						InjectionPoint:     strconv.Itoa(indexes[i][0]) + " - " + strconv.Itoa(indexes[i][1]),
						InjectionPointType: "marked",
						Status:             "queued",
					})
				}
			}

		}
	}

	return InjectedTestCases
}

func markjson(data interface{}, count *int, marks *[]string, marker string) interface{} {

	if reflect.ValueOf(data).Kind() == reflect.Slice {
		d := reflect.ValueOf(data)
		tmpData := make([]interface{}, d.Len())
		returnSlice := make([]interface{}, d.Len())
		for i := 0; i < d.Len(); i++ {
			tmpData[i] = d.Index(i).Interface()
		}
		for i, v := range tmpData {
			typeOfValue := reflect.TypeOf(v).Kind()
			if typeOfValue == reflect.Map || typeOfValue == reflect.Slice {
				returnSlice[i] = markjson(v, count, marks, marker)
			} else {
				returnSlice[i] = marker + strconv.Itoa(*count) + reflect.ValueOf(v).String() + marker
				*marks = append(*marks, strconv.Itoa(*count))
				*count++
			}
		}
		return returnSlice
	} else if reflect.ValueOf(data).Kind() == reflect.Map {
		d := reflect.ValueOf(data)
		tmpData := make(map[string]interface{})
		for _, k := range d.MapKeys() {
			typeOfValue := reflect.TypeOf(d.MapIndex(k).Interface()).Kind()
			if typeOfValue == reflect.Map || typeOfValue == reflect.Slice {
				tmpData[k.String()] = markjson(d.MapIndex(k).Interface(), count, marks, marker)
			} else {
				tmpData[k.String()] = marker + strconv.Itoa(*count) + reflect.ValueOf(d.MapIndex(k).Interface()).String() + marker
				*marks = append(*marks, strconv.Itoa(*count))
				*count++
			}
		}
		return tmpData
	}

	return data
}

// CheckTarget takes a request object and a list of errorcodes returns false if response to the request matches the error code and true if it doesn't
func CheckTarget(req *HTTPRequest, successcodes []int) error {
	var checkReq HTTPRequest
	var err error
	if req.IsMarked() {
		pattern := regexp.MustCompile(`§.*?§`)
		newReqStr := pattern.ReplaceAllString(req.RequestText, "")
		checkReq, err = NewHTTPRequestFromBytes([]byte(newReqStr), req.ForceTLS)
		if err != nil {
			return err
		}
	} else {
		checkReq = *req
	}

	allowed := false
	var transport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	httpclient := http.Client{
		Timeout:   time.Duration(120 * time.Second),
		Transport: transport,
	}

	resp, err := httpclient.Do(checkReq.Request)
	if err != nil {
		fmt.Println(err)
		return err
	}

	for _, successcode := range successcodes {
		if resp.StatusCode == successcode {
			allowed = true
		}
	}
	if allowed {
		return nil
	}

	return errors.New(strconv.Itoa(resp.StatusCode))
}

// ResultsToFile will write the results of a fuzzing Task to a file
func ResultsToFile(projectName string, task SerializedTask) error {
	fd, err := os.OpenFile(projectName+".json", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Printf("ResultsToFile error: %s\n", err)
		return err
	}
	defer fd.Close()

	results, err := json.Marshal(task)
	if err != nil {
		log.Printf("ResultsToFile error: %s\n", err)
		return err
	}

	_, err = fd.Write(results)
	if err != nil {
		log.Printf("ResultsToFile error: %s\n", err)
		return err
	}

	if err := fd.Close(); err != nil {
		log.Printf("ResultsToFile error: %s\n", err)
		return err
	}
	return nil
}

// ResultsToMongoDB will write the results of a fuzzing Task to MongoDB
func ResultsToMongoDB(mongodbURI string, task SerializedTask) error {
	mclient, err := mongo.NewClient(options.Client().ApplyURI(mongodbURI))
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = mclient.Connect(ctx)
	if err != nil {
		return err
	}
	err = mclient.Ping(ctx, nil)
	if err != nil {
		return err
	}
	defer mclient.Disconnect(ctx)
	defer ctx.Done()
	pandushiDB := mclient.Database("pandushi")
	taskCollection := pandushiDB.Collection("tasks")
	taskResult, err := taskCollection.InsertOne(ctx, task)
	if err != nil {
		return err
	}

	log.Println(taskResult.InsertedID)
	return nil
}

// StorageConfig contains information about where to store results of a fuzzer Task
type StorageConfig struct {
	UseMongoDB       bool
	MongoDBURI       string
	UseFile          bool
	FileURI          string
	UseElasticSearch bool
	ElasticSeachURI  string
}

// CreateStorageConfigFromURI takes an array of URI strings and return a StorageConfig type
func CreateStorageConfigFromURI(StorageURIs []string) StorageConfig {
	config := StorageConfig{
		UseMongoDB:       false,
		UseElasticSearch: false,
		UseFile:          false,
	}
	for _, URI := range StorageURIs {
		if strings.HasPrefix(URI, "file://") {
			config.FileURI = strings.Replace(URI, "file://", "", 1)
			config.UseFile = true
		}
		if strings.HasPrefix(URI, "mongodb://") {
			config.MongoDBURI = URI
			config.UseMongoDB = true
		}
		if strings.HasPrefix(URI, "elastic://") {
			config.ElasticSeachURI = strings.Replace(URI, "elastic://", "http://", 1)
			config.UseElasticSearch = true
		}
	}
	return config
}
