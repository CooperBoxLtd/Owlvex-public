package demo

import (
    "database/sql"
    "net/http"
)

func LoadUser(db *sql.DB, r *http.Request) {
    userID := r.URL.Query().Get("id")
    query := "SELECT * FROM users WHERE id = '" + userID + "'"
    db.Query(query)
}
