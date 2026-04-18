package demo

import (
    "net/http"
    "os/exec"
)

func RunCommand(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", cmd).Run()
    w.WriteHeader(http.StatusNoContent)
}
