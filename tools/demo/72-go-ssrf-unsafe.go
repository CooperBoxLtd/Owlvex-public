package demo

import (
    "net/http"
)

func FetchAvatar(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    http.Get(url)
    w.WriteHeader(http.StatusNoContent)
}
