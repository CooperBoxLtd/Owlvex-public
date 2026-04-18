package demo

import (
    "net/http"

    "github.com/golang-jwt/jwt/v5"
)

func ParseToken(w http.ResponseWriter, r *http.Request, secret []byte) {
    token := r.Header.Get("Authorization")
    jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
        return secret, nil
    })
    w.WriteHeader(http.StatusNoContent)
}
