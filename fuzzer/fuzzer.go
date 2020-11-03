package fuzzer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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
	req.CountInjectionPoints()
	return req, nil
}

// ByteToJSONInterface takes a byte array as input and returns JSON inteface
func ByteToJSONInterface(r io.ReadCloser) (interface{}, error) {
	var JSONInterface interface{}
	input, err := ioutil.ReadAll(r)
	if err != nil {
		return 0, err
	}
	fmt.Println(input)
	err = json.Unmarshal(input, &JSONInterface)
	if err != nil {
		return JSONInterface, err
	}
	return JSONInterface, nil
}

//CountJSONBody take http.Request and return total amount of parameters
func CountJSONBody(jsoni interface{}) int8 {
	count := int8(0)
	m := jsoni.(map[string]interface{})
	for k, v := range m {
		//fmt.Printf("default: key:%s, value:%v, type:%T\n", k, v, v)
		switch vv := v.(type) {
		case string:
			//fmt.Printf("String: %s:%s\n", k, v)
			count++
		case int:
			//fmt.Printf("Int: %s:%d\n", k, v)
			count++
		case float64:
			//fmt.Printf("Float: %s:%f\n", k, v)
			count++
		case []interface{}:
			for _, vi := range vv {
				//fmt.Printf("default: %s:%v:%T\n", k, vi, v)
				//fmt.Printf("default: key:%s, value:%v, type:%T\n", k, v, v)
				switch vi.(type) {
				case map[string]interface{}:
					count += CountJSONBody(vi)
				}
				count++

			}
		case bool:
			fmt.Printf("Bool: %s:%T\n", k, v)
			count++
		case map[string]interface{}:
			count += CountJSONBody(v)
		default:
			fmt.Printf("default: key:%s, value:%v, type:%T\n", k, v, v)
		}
	}

	//fmt.Println(body)
	//fmt.Println(len(body))
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
		err := r.ParseForm()
		if err == nil {
			req.TotalBodyInjectionPoints = int8(len(r.PostForm))
			req.TotalInjectionPoints += req.TotalBodyInjectionPoints
		}
	} else if strings.Contains(ContentType, "multipart/form-data") {
		err := r.ParseMultipartForm(4096000)
		if err == nil {
			req.TotalBodyInjectionPoints += int8(len(r.MultipartForm.File))
			req.TotalBodyInjectionPoints += int8(len(r.MultipartForm.Value))
			req.TotalInjectionPoints += req.TotalBodyInjectionPoints
		}
	} else if strings.Contains(ContentType, "application/json") {
		JSONInterface, err := ByteToJSONInterface(r.Body)
		if err != nil {
			fmt.Println("ContInjectionPoints", err)
		} else {
			jsoncount := CountJSONBody(JSONInterface)
			req.TotalBodyInjectionPoints += jsoncount
			req.TotalInjectionPoints += jsoncount
		}
	} else if strings.Contains(ContentType, "text/plain") {
		JSONInterface, err := ByteToJSONInterface(r.Body)
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
func NewHTTPRequestFromRequest(r *http.Request) (req HTTPRequest) {
	req.Request = r
	RequestText, err := RequestToString(req.Request)
	if err != nil {
		req.RequestText = ""
	} else {
		req.RequestText = RequestText
	}
	req.CountInjectionPoints()
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
	if r.ContentLength != -1 {
		r.Header.Set("Content-Lenght", strconv.FormatInt(int64(len(body)), 10))
	}
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
	/*
		MarkerPositions := Marker.FindAllIndex([]byte(req.RequestText), 0)
		log.Println(len(MarkerPositions))
		for _, pos := range MarkerPositions {
			log.Println(pos)
		}
	*/
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
	Request        HTTPRequest
	Response       HTTPResponse
	Injection      string
	InjectionType  string
	InjectionPoint string
	Duration       string
	Status         string
}

// Task represents a Fuzzer task
type Task struct {
	InjectionTypes []string
	BaseRequest    HTTPRequest
	Start          time.Time
	End            time.Time
	State          string
	TestCases      []TestCase
}

// NewTask takes a list of InjectionTypes and HTTPRequest and returns a FuzzerTask
func NewTask(InjectionTypes []string, BaseRequest HTTPRequest) Task {
	task := Task{
		InjectionTypes: InjectionTypes,
		BaseRequest:    BaseRequest,
	}

	return task
}

// Run starts and run a fuzzer Task
func (f Task) Run() {
	f.Start = time.Now()
	var mutex = &sync.Mutex{}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		mutex.Lock()
		go func() {
			defer wg.Done()
			mclient, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
			if err != nil {
				panic(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = mclient.Connect(ctx)
			if err != nil {
				panic(err)
			}
			defer mclient.Disconnect(ctx)
			defer cancel()

			pandushiDB := mclient.Database("pandushi")
			taskCollection := pandushiDB.Collection("tasks")

			httpclient := http.Client{
				Timeout: time.Duration(5 * time.Second),
			}
			reqstr, err := RequestToString(f.BaseRequest.Request)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Printf("REQSTR:\n\n%s\n", reqstr)

			resp, err := httpclient.Do(f.BaseRequest.Request)
			if err != nil {
				fmt.Println(err)
			} else {
				httpres, err := NewHTTPResponse(resp)
				if err != nil {
					fmt.Println(err)
				} else {
					//fmt.Printf("REQSTR:\n\n%s\n", reqstr)
					//fmt.Println(httpres.ResponseText)
					taskResult, err := taskCollection.InsertOne(ctx, bson.D{
						{Key: "Request", Value: reqstr},
						{Key: "Response", Value: httpres.ResponseText},
					})
					if err != nil {
						log.Println(err)
					} else {
						log.Println(taskResult.InsertedID)
					}
				}
			}
		}()
		mutex.Unlock()
	}
	wg.Wait()
	f.End = time.Now()
}

// InjectQueryParameters Injects and array of payloads into a HTTPRequest's query parameters
func (req *HTTPRequest) InjectQueryParameters(injections []string) []HTTPRequest {
	var InjectedRequests []HTTPRequest
	query := req.Request.URL.Query()
	for _, injection := range injections {
		for k := range query {
			NewQuery := url.Values{}
			for ik, v := range query {
				NewQuery.Set(ik, strings.Join(v, ""))
			}
			NewQuery.Set(k, injection)
			rawquery := NewQuery.Encode()
			NewHTTPRequest, err := NewHTTPRequestFromBytes([]byte(req.RequestText))
			if err != nil {
				fmt.Printf("Error Creating HTTPRequest: %s", err)
			} else {
				NewHTTPRequest.Request.URL.RawQuery = rawquery
				NewRequestText, err := RequestToString(NewHTTPRequest.Request)
				if err == nil {
					NewHTTPRequest.RequestText = NewRequestText
				}
				fmt.Printf("Request rawquery: %s\n", NewHTTPRequest.Request.URL.RawQuery)
				fmt.Printf("Request rawquery addr: %p\n", &NewHTTPRequest.Request.URL.RawQuery)
				fmt.Printf("Request addr: %p\n", NewHTTPRequest.Request)
				//fmt.Printf("Original raw query: %s\n", req.Request.URL.RawQuery)
				//fmt.Printf("Request rawquery: %s\n", NewHTTPRequest.Request.URL.RawQuery)
				//fmt.Printf("Request text: %s\n", NewHTTPRequest.RequestText)
				InjectedRequests = append(InjectedRequests, NewHTTPRequest)
			}

		}
	}

	return InjectedRequests
}
