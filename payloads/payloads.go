package payloads

// Payload represents a fuzzer input
type Payload struct {
	InputType string `json:"type"`
	Value     string `json:"value"`
}
