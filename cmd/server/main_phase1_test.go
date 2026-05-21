package main

import "testing"

func TestMarshalJSONText_UsesFallbackForNil(t *testing.T) {
	got, err := marshalJSONText(nil, "[]")
	if err != nil {
		t.Fatalf("marshalJSONText returned error: %v", err)
	}
	if got != "[]" {
		t.Fatalf("got %q want []", got)
	}
}

func TestMarshalJSONText_MarshalsStructuredValue(t *testing.T) {
	got, err := marshalJSONText([]string{"ai.task", "command.echo"}, "[]")
	if err != nil {
		t.Fatalf("marshalJSONText returned error: %v", err)
	}
	if got != `["ai.task","command.echo"]` {
		t.Fatalf("got %q", got)
	}
}

func TestMarshalJSONText_UsesFallbackForNilMap(t *testing.T) {
	var value map[string]float64
	got, err := marshalJSONText(value, "{}")
	if err != nil {
		t.Fatalf("marshalJSONText returned error: %v", err)
	}
	if got != "{}" {
		t.Fatalf("got %q want {}", got)
	}
}
