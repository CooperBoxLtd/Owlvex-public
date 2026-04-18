package demo

import (
    "net/http"
    "os/exec"
)

func RunCommand(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    exec.Command("grep", name).Run()
    w.WriteHeader(http.StatusNoContent)
}
