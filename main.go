package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/gi0cann/pandushi/fuzzer"
	"github.com/gi0cann/pandushi/payloads"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {

	parser := argparse.NewParser("pandushi", "Pandushi web scanner")

	requestFname := parser.String("r", "request-file", &argparse.Options{Required: false, Help: "Load HTTP request from file"})
	payloadFname := parser.String("p", "payload-file", &argparse.Options{Required: false, Help: "Load payload file"})
	payloadType := parser.String("t", "payload-type", &argparse.Options{Required: false, Help: "Payload type"})

	fmt.Println("gscanner")
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	if len(*requestFname) > 0 {
		fmt.Printf("Request Fname: %s\n", *requestFname)

		fd, err := os.Open(*requestFname)
		if err != nil {
			panic(err)
		}
		defer fd.Close()

		text, err := ioutil.ReadAll(fd)
		if err != nil {
			panic(err)
		}

		//fmt.Printf("%s\n", text)

		request, err := fuzzer.NewHTTPRequestFromBytes(text)
		if err != nil {
			panic(err)
		}
		request.Request.RequestURI = ""
		//fmt.Printf("HTTPRequest.RequestText: %s\n", request.RequestText)
		//fmt.Printf("HTTPRequest.Request: %s\n", request.Request.Method)
		//fmt.Printf("RequestURI: %s\n", request.Request.RequestURI)
		//fmt.Printf("Proto: %s\n", request.Request.Proto)
		//fmt.Printf("URL: %s\n", request.Request.URL)

		/*
			reqstr, err := fuzzer.RequestToString(request.Request)
			if err != nil {
				panic(err)
			}

			fmt.Printf("REQSTR:\n\n%s\n", reqstr)

			client := http.Client{
				Timeout: time.Duration(5 * time.Second),
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
		*/
		log.Println(request.IsMarked())
		//fuzzerTask := fuzzer.NewTask([]string{"XSS"}, request)
		//fuzzerTask.Run()

		payloadArr := []payloads.Payload{
			{
				Value:     "<script>alert(1)</script>",
				InputType: "xss",
			},
		}

		InjectedTestCases := request.InjectHeaders(payloadArr)
		QueryCases := request.InjectQueryParameters(payloadArr)
		InjectedTestCases = append(InjectedTestCases, QueryCases...)
		URLEncodeBodyCases := request.InjectFormURLEncodedBody(payloadArr)
		InjectedTestCases = append(InjectedTestCases, URLEncodeBodyCases...)
		JSONTestCases := request.InjectJSONParameters(payloadArr)
		InjectedTestCases = append(InjectedTestCases, JSONTestCases...)
		for _, InjectedTestCase := range InjectedTestCases {
			// fmt.Printf("Request rawquery: %s\n", InjectedRequest.Request.URL.RawQuery)
			// fmt.Printf("Request addr: %p\n", InjectedRequest.Request)
			fmt.Printf("Request text: %s\n", InjectedTestCase.Request.RequestText)

			client := http.Client{
				Timeout: time.Duration(5 * time.Second),
			}
			resp, err := client.Do(InjectedTestCase.Request.Request)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				continue
			}

			httpres, err := fuzzer.NewHTTPResponse(resp)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				continue
			}

			fmt.Printf("response:\n%s\n", httpres.ResponseText)

		}
		fmt.Printf("JSON cases: %d\n", len(JSONTestCases))

	} else if len(*payloadFname) > 0 && len(*payloadType) > 0 {
		fmt.Printf("Payload Fname: %s\n", *payloadFname)
		fmt.Printf("Payload Type: %s\n", *payloadType)
		payloadfd, err := os.Open(*payloadFname)
		if err != nil {
			panic(err)
		}
		defer payloadfd.Close()

		client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
		if err != nil {
			panic(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = client.Connect(ctx)
		if err != nil {
			panic(err)
		}
		defer client.Disconnect(ctx)
		defer cancel()

		pandushiDB := client.Database("pandushi")
		injectionsCollection := pandushiDB.Collection("injections")

		payloadsRaw, err := ioutil.ReadAll(payloadfd)
		if err != nil {
			panic(err)
		}

		fmt.Printf("PayloadRAW: %s\n", payloadsRaw)
		fmt.Printf("PayloadType: %s\n", *payloadType)

		var testPayloads []payloads.Payload
		injectionsCount := 0

		for _, line := range strings.Split(string(payloadsRaw), "\n") {
			testPayloads = append(testPayloads,
				payloads.Payload{
					InputType: *payloadType,
					Value:     line,
				})
			injectionsResult, err := injectionsCollection.InsertOne(ctx, bson.D{
				{Key: "type", Value: *payloadType},
				{Key: "value", Value: line},
			})
			if err != nil {
				log.Fatal(err)
			} else {
				injectionsCount++
				fmt.Printf("inserted document with ID %v\n", injectionsResult.InsertedID)
			}
		}

		fmt.Printf("Inserted %v documents into injections collection!\n", injectionsCount)
		outfd, err := os.OpenFile("payloads.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer outfd.Close()
		enc := json.NewEncoder(outfd)
		enc.SetEscapeHTML(false)
		enc.Encode(testPayloads)
	} else {
		fmt.Print(parser.Usage(err))
	}

}
