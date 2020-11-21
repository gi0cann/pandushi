package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
	projectName := parser.String("P", "project", &argparse.Options{Required: false, Help: "Project name", Default: "default"})
	scanName := parser.String("S", "scan-name", &argparse.Options{Required: false, Help: "Scan name", Default: "default"})
	threadCount := parser.Int("T", "thread-count", &argparse.Options{
		Required: false,
		Help:     "Total number of threads to use for sending requests",
		Default:  10,
	})
	errorcodes := parser.IntList("e", "error-codes", &argparse.Options{
		Required: false,
		Help:     "List of allowed http error codes",
		Default:  fuzzer.SuccessCodes,
	})

	fmt.Println("gscanner")
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	if len(*requestFname) > 0 {
		fmt.Printf("Request Fname: %s\n", *requestFname)
		fmt.Printf("Thread Count: %d\n", *threadCount)
		if len(*errorcodes) > 0 {
			*errorcodes = append(*errorcodes, fuzzer.SuccessCodes...)
		}
		fmt.Printf("Allowed %v\n", *errorcodes)

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
		err = fuzzer.CheckTarget(&request, *errorcodes)
		if err != nil {
			fmt.Printf("There was an error communication with the target: %s\n", err)
			os.Exit(1)
		}
		request.Request.RequestURI = ""
		log.Println(request.IsMarked())
		fuzzerTask, err := fuzzer.NewTask(*projectName, *scanName, []string{"XSS"}, fuzzer.SupportedInjectionPointTypes, request, "mongodb://localhost:27017")
		if err != nil {
			panic(err)
		}
		fuzzerTask.Run(*threadCount)
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
					InputType: strings.ToUpper(*payloadType),
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
