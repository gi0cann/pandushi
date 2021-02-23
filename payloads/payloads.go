package payloads

import (
	"context"
	"log"
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

// CreatePayloadsFromInputTypes takes and array of Payload InputTypes and an mongodb uri and returns an array of Payloads of that type from mongodb
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
