package payloads

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Payload represents a fuzzer input
type Payload struct {
	InputType string `json:"type"`
	Value     string `json:"value"`
}

// New take payload type and value returns a Payload
func New(inputtype string, value string) Payload {
	return Payload{
		InputType: inputtype,
		Value:     value,
	}
}

// CreatePayloadsFromInputTypes takes an array of Payload InputTypes and an mongodb uri and returns an array of Payloads of that type from mongodb
func CreatePayloadsFromInputTypes(InputTypes []string, mongodbURI string) ([]Payload, error) {
	var payloads []Payload
	var temppayloads []Payload
	client, err := mongo.NewClient(options.Client().ApplyURI(mongodbURI))
	if err != nil {
		return payloads, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("payloads.CreatePayloadsFromInputTypes mongodb connection error: %s\n", err)
	}
	defer client.Disconnect(ctx)
	defer cancel()

	for _, inputtype := range InputTypes {

		filter := bson.M{"type": strings.ToUpper(inputtype)}
		pandushiDB := client.Database("pandushi")
		injectionsCollection := pandushiDB.Collection("injections")

		cursor, err := injectionsCollection.Find(ctx, filter)
		if err != nil {
			continue
		}

		if err = cursor.All(ctx, &temppayloads); err != nil {
			continue
		} else {
			payloads = append(payloads, temppayloads...)
		}

	}
	return payloads, nil
}

// PayloadFromFileByInputTypes takes an array of Payload InputTypes and a file uri and returns an array of Payload of that type from the payloads included in the file
/*
func PayloadFromFileByInputTypes(InputTypes []string, fileURI string) ([]Payload, error) {
}
*/

// NewPayloadsFromFileToMongoDB creates and stores payload to mongodb
func NewPayloadsFromFileToMongoDB(payloadType string, InputFname string, mongodbURI string, dbName string) ([]Payload, error) {
	var testPayloads []Payload
	injectionsCount := 0

	client, err := mongo.NewClient(options.Client().ApplyURI(mongodbURI))
	if err != nil {
		return testPayloads, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		cancel()
		return testPayloads, err
	}
	defer client.Disconnect(ctx)
	defer cancel()

	pandushiDB := client.Database(dbName)
	injectionsCollection := pandushiDB.Collection("injections")

	payloadfd, err := os.Open(InputFname)
	if err != nil {
		return testPayloads, err
	}
	defer payloadfd.Close()

	payloadsRaw, err := ioutil.ReadAll(payloadfd)
	if err != nil {
		return testPayloads, err
	}

	fmt.Printf("PayloadRAW: %s\n", payloadsRaw)
	fmt.Printf("PayloadType: %s\n", payloadType)

	for _, line := range strings.Split(string(payloadsRaw), "\n") {
		testPayloads = append(testPayloads,
			Payload{
				InputType: strings.ToUpper(payloadType),
				Value:     line,
			})
		injectionsResult, err := injectionsCollection.InsertOne(ctx, bson.D{
			{Key: "type", Value: payloadType},
			{Key: "value", Value: line},
		})
		if err != nil {
			return testPayloads, err
		} else {
			injectionsCount++
			fmt.Printf("inserted document with ID %v\n", injectionsResult.InsertedID)
		}
	}
	fmt.Printf("Inserted %v documents into injections collection!\n", injectionsCount)

	return testPayloads, nil
}

// NewPayloadsFromFileToJSONFile creates and stores payload to a json file
func NewPayloadsFromFileToJSONFile(payloadType string, InputFname string, outFilename string) ([]Payload, error) {
	var testPayloads []Payload
	injectionsCount := 0

	payloadfd, err := os.Open(InputFname)
	if err != nil {
		return testPayloads, err
	}
	defer payloadfd.Close()

	payloadsRaw, err := ioutil.ReadAll(payloadfd)
	if err != nil {
		return testPayloads, err
	}

	fmt.Printf("PayloadRAW: %s\n", payloadsRaw)
	fmt.Printf("PayloadType: %s\n", payloadType)

	for _, line := range strings.Split(string(payloadsRaw), "\n") {
		testPayloads = append(testPayloads,
			Payload{
				InputType: strings.ToUpper(payloadType),
				Value:     line,
			})
		injectionsCount++
	}
	fmt.Printf("Inserted %v documents into injections collection!\n", injectionsCount)
	outfd, err := os.OpenFile(outFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer outfd.Close()
	enc := json.NewEncoder(outfd)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	enc.Encode(testPayloads)

	return testPayloads, nil
}
