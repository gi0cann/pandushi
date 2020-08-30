package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gi0cann/gscanner/fuzzer"
)

func main() {

	requestFname := flag.String("r", "", "Load HTTP request from file")
	flag.Parse()

	fmt.Println("gscanner")
	fd, err := os.Open(*requestFname)
	if err != nil {
		panic(err)
	}

	text, err := ioutil.ReadAll(fd)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", text)

	request, err := fuzzer.NewHTTPRequestFromBytes(text)
	if err != nil {
		panic(err)
	}
	request.Request.RequestURI = ""
	fmt.Printf("HTTPRequest.RequestText: %s\n", request.RequestText)
	fmt.Printf("HTTPRequest.Request: %s\n", request.Request.Method)
	fmt.Printf("RequestURI: %s\n", request.Request.RequestURI)
	fmt.Printf("Proto: %s\n", request.Request.Proto)
	fmt.Printf("URL: %s\n", request.Request.URL)

	reqstr, err := fuzzer.RequestToString(request.Request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("REQSTR:\n\n%s\n", reqstr)

	tr := &http.Transport{
		DisableCompression: false,
	}
	client := http.Client{
		Timeout:   time.Duration(5 * time.Second),
		Transport: tr,
	}
	resp, err := client.Do(request.Request)
	if err != nil {
		panic(err)
	}

	httpres, err := fuzzer.NewHTTPResponse(resp)
	if err != nil {
		panic(err)
	}

	fmt.Println(httpres.ResponseText)
}
