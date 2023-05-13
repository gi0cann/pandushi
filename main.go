package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
    "net/url"

	"github.com/akamensky/argparse"
	"github.com/gi0cann/pandushi/fuzzer"
	"github.com/gi0cann/pandushi/payloads"
)

func main() {

	parser := argparse.NewParser("pandushi", "Pandushi web scanner")

	requestFname := parser.String("r", "request-file", &argparse.Options{Required: false, Help: "Load HTTP request from file"})
	payloadFname := parser.String("p", "payload-file", &argparse.Options{Required: false, Help: "Load payload file"})
	payloadType := parser.String("t", "payload-type", &argparse.Options{Required: false, Help: "Payload type"})
	projectName := parser.String("P", "project", &argparse.Options{Required: false, Help: "Project name", Default: "default"})
	payloadStorageURI := parser.String("x", "payload-storage", &argparse.Options{
		Required: false,
		Help:     "Payload Storage URI. Supported URIs prefixes are file:// for file storage or mongodb:// for mongodb.",
		Default:  "default",
	})
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
	storageURIs := parser.StringList("C", "storage-config", &argparse.Options{
		Required: false,
		Help:     "List of storage URIs. Supported URIs prefixes are file:// for file storage, and mongodb:// for mongdb.",
	})
	forceTLS := parser.Flag("l", "force-tls", &argparse.Options{Required: false, Help: "Force the use TLS/SSL", Default: false})
    proxy := parser.String("s", "http-proxy", &argparse.Options{Required: false, Help: "http proxy format: (http,https)://<address>:<port>"})

	fmt.Println("gscanner")
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	if len(*requestFname) > 0 && len(*storageURIs) > 0 {
		storageconfig := fuzzer.CreateStorageConfigFromURI(*storageURIs)
        var proxyURL *url.URL
        proxyURL = nil
        if len(*proxy) > 0 {
            proxyURL, err = url.Parse(*proxy)
        }
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

		request, err := fuzzer.NewHTTPRequestFromBytes(text, *forceTLS)
		if err != nil {
			panic(err)
		}
		err = fuzzer.CheckTarget(&request, *errorcodes)
		if err != nil {
			fmt.Printf("There was an error communication with the target: %s\n", err)
			os.Exit(1)
		}
		request.Request.RequestURI = ""
		if request.IsMarked() {
			fmt.Println("Marked")
			fuzzerTask, err := fuzzer.NewTask(*projectName, *scanName, []string{"XSS"}, []string{"MARKED"}, request, "mongodb://localhost:27017")
			if err != nil {
				panic(err)
			}
			fuzzerTask.Run(*threadCount, storageconfig, proxyURL)
		} else {
			fmt.Println("Not Marked")
			fuzzerTask, err := fuzzer.NewTask(*projectName, *scanName, []string{"XSS"}, fuzzer.SupportedInjectionPointTypes, request, "mongodb://localhost:27017")
			if err != nil {
				panic(err)
			}
			fuzzerTask.Run(*threadCount, storageconfig, proxyURL)
		}
	} else if len(*payloadFname) > 0 && len(*payloadType) > 0 && len(*payloadStorageURI) > 0 {
		fmt.Printf("Payload Fname: %s\n", *payloadFname)
		fmt.Printf("Payload Type: %s\n", *payloadType)
		fmt.Printf("Payload Storage: %s\n", *payloadStorageURI)

		payloadfd, err := os.Open(*payloadFname)
		if err != nil {
			panic(err)
		}
		defer payloadfd.Close()

		outFilename := "payload.json"
		if strings.HasPrefix(*payloadStorageURI, "file://") {
			outFilename = strings.Split(*payloadStorageURI, "file://")[1]
			_, err = payloads.NewPayloadsFromFileToJSONFile(*payloadType, *payloadFname, outFilename)
			if err != nil {
				log.Fatalln(err)
			}
		}

		mongoURI := "mongodb://localhost:27017"
		if strings.HasPrefix(*payloadStorageURI, "mongodb://") {
			mongoURI = *payloadStorageURI
			_, err = payloads.NewPayloadsFromFileToMongoDB(*payloadType, *payloadFname, mongoURI, "pandushi")
			if err != nil {
				log.Fatalln(err)
			}
		}

	} else {
		fmt.Print(parser.Usage(err))
	}

}
