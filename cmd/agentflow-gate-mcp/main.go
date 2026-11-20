package main

import (
	"encoding/json"
	"log"
	"os"

	"agentflow/internal/gatemcp"
)

func main() {
	output := gatemcp.OutputConfig{
		Path:   os.Getenv("AGENTFLOW_OUTPUT_PATH"),
		Schema: json.RawMessage(os.Getenv("AGENTFLOW_OUTPUT_SCHEMA")),
	}
	if err := gatemcp.RunWithOutput(os.Stdin, os.Stdout, os.Getenv("AGENTFLOW_GATE_RESULT_PATH"), output); err != nil {
		log.Fatal(err)
	}
}
