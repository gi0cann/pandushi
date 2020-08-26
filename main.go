package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/gi0cann/gscanner/fuzzer"
)

func main() {
	fmt.Println("gscanner")
	fd, err := os.Open("twitter_event_post.req")
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

	fmt.Printf("HTTPRequest.RequestText: %s\n", request.RequestText)
	fmt.Printf("HTTPRequest.Request: %s\n", request.Request.Method)

	reqstr, err := fuzzer.RequestToString(request.Request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("REQSTR:\n\n%s\n", reqstr)
}
