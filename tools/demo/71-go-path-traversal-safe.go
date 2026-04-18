package demo

import (
    "net/http"
    "os"
    "path/filepath"
)

func ReadFile(w http.ResponseWriter, r *http.Request) {
    target := filepath.Join("/srv/files", "logo.png")
    os.ReadFile(target)
    w.WriteHeader(http.StatusNoContent)
}
