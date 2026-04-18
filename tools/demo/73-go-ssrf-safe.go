package demo

import (
    "net/http"
)

func FetchAvatar(w http.ResponseWriter, r *http.Request) {
    http.Get("https://example.com/avatar.png")
    w.WriteHeader(http.StatusNoContent)
}
