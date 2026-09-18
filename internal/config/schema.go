package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed juggernaut.schema.json
var schemaJSON []byte

// SchemaJSON returns the embedded JSON Schema for juggernaut.yaml.
func SchemaJSON() []byte { return schemaJSON }

var (
	schemaOnce sync.Once
	schemaVal  *jsonschema.Schema
	schemaErr  error
)

func compiledSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
		if err != nil {
			schemaErr = fmt.Errorf("parse embedded schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		const id = "https://juggernaut.io/schemas/v1alpha1/juggernaut.schema.json"
		if err := c.AddResource(id, doc); err != nil {
			schemaErr = err
			return
		}
		schemaVal, schemaErr = c.Compile(id)
	})
	return schemaVal, schemaErr
}

// SchemaID is exported for tooling that wants to print the schema.
func SchemaID() string {
	var m struct {
		ID string `json:"$id"`
	}
	_ = json.Unmarshal(schemaJSON, &m)
	return m.ID
}
