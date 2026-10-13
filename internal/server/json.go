package server

import (
	"encoding/json"
	"io"
)

func jsonEncode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }
