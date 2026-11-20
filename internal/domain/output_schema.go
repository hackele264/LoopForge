package domain

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// MaxNodeDataBytes bounds a node's structured output.
const MaxNodeDataBytes = 64 << 10

// ValidateNodeOutput parses raw as a node's structured output and checks it
// against schema. The output must be a JSON object. Only a subset of JSON
// Schema is enforced: type, required, properties (recursively), items and
// enum. Other keywords are accepted and ignored, so a richer schema still
// documents intent without failing validation.
func ValidateNodeOutput(schema json.RawMessage, raw []byte) (RawJSON, error) {
	if len(raw) > MaxNodeDataBytes {
		return "", fmt.Errorf("structured output exceeds %d bytes", MaxNodeDataBytes)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("structured output is not valid JSON: %v", err)
	}
	if _, ok := value.(map[string]any); !ok {
		return "", fmt.Errorf("structured output must be a JSON object")
	}
	if len(schema) > 0 {
		var s map[string]any
		if err := json.Unmarshal(schema, &s); err != nil {
			return "", fmt.Errorf("outputSchema is not a JSON object: %v", err)
		}
		if err := checkSchema(s, value, "$"); err != nil {
			return "", err
		}
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return RawJSON(compact), nil
}

func checkSchema(schema map[string]any, value any, path string) error {
	if t, ok := schema["type"]; ok {
		if !matchesType(t, value) {
			return fmt.Errorf("%s: expected type %v, got %s", path, t, jsonTypeName(value))
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, candidate := range enum {
			if jsonEqual(candidate, value) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: value is not one of the allowed values", path)
		}
	}
	if object, ok := value.(map[string]any); ok {
		if required, ok := schema["required"].([]any); ok {
			for _, key := range required {
				name, _ := key.(string)
				if _, present := object[name]; !present {
					return fmt.Errorf("%s: missing required field %q", path, name)
				}
			}
		}
		if props, ok := schema["properties"].(map[string]any); ok {
			for name, sub := range props {
				subSchema, ok := sub.(map[string]any)
				if !ok {
					continue
				}
				if child, present := object[name]; present {
					if err := checkSchema(subSchema, child, path+"."+name); err != nil {
						return err
					}
				}
			}
		}
	}
	if list, ok := value.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, item := range list {
				if err := checkSchema(items, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func matchesType(t any, value any) bool {
	switch v := t.(type) {
	case string:
		return matchesOneType(v, value)
	case []any:
		for _, candidate := range v {
			if s, ok := candidate.(string); ok && matchesOneType(s, value) {
				return true
			}
		}
		return false
	}
	return true
}

func matchesOneType(t string, value any) bool {
	switch strings.ToLower(t) {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		_, ok := value.(float64)
		return ok
	case "integer":
		f, ok := value.(float64)
		return ok && f == math.Trunc(f)
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	}
	return true
}

func jsonTypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	}
	return fmt.Sprintf("%T", value)
}

func jsonEqual(a, b any) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ra) == string(rb)
}
