package demo

import (
    "net/http"
    "os"
    "path/filepath"
)

func ReadFile(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    target := filepath.Join("/srv/files", name)
    os.ReadFile(target)
    w.WriteHeader(http.StatusNoContent)
}
