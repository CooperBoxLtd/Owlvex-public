package demo

import (
    "database/sql"
    "net/http"
)

func LoadUser(db *sql.DB, r *http.Request) {
    userID := r.URL.Query().Get("id")
    db.Query("SELECT * FROM users WHERE id = ?", userID)
}
