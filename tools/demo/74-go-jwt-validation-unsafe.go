package demo

import (
    "net/http"

    "github.com/golang-jwt/jwt/v5"
)

func ParseToken(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
    w.WriteHeader(http.StatusNoContent)
}
