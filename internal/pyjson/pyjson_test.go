package pyjson

import (
	"encoding/json"
	"testing"
)

type rec struct {
	A string  `json:"a"`
	B *string `json:"b"`
	C []int   `json:"c"`
	D bool    `json:"d,omitempty"`
}

func TestMatchesPythonDumps(t *testing.T) {
	// json.dumps({"a": "é\n\"x\"\U0001F600", "b": None, "c": [1, 2]})
	out, _ := Marshal(rec{A: "é\n\"x\"\U0001F600", C: []int{1, 2}}, 0)
	want := "{\"a\": \"\\u00e9\\n\\\"x\\\"\\ud83d\\ude00\", \"b\": null, \"c\": [1, 2]}"
	if string(out) != want {
		t.Fatalf("got %s want %s", out, want)
	}
}

func TestIndentOne(t *testing.T) {
	out, _ := Marshal([]rec{{A: "x", C: nil}}, 1)
	want := "[\n {\n  \"a\": \"x\",\n  \"b\": null,\n  \"c\": []\n }\n]"
	if string(out) != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestOrderedMapRoundTripKeepsOrderAndNumbers(t *testing.T) {
	var m OrderedMap
	if err := json.Unmarshal([]byte(`{"source": "x", "ranges": ">=1", "n": 10.0, "l": ["a"]}`), &m); err != nil {
		t.Fatal(err)
	}
	out, _ := Marshal(&m, 0)
	if string(out) != `{"source": "x", "ranges": ">=1", "n": 10.0, "l": ["a"]}` {
		t.Fatalf("got %s", out)
	}
}
