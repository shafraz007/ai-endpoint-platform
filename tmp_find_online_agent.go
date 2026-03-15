//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if strings.TrimSpace(dbURL) == "" {
		dbURL = "postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fmt.Println("ERR")
		os.Exit(1)
	}
	defer pool.Close()
	var id string
	err = pool.QueryRow(ctx, `SELECT agent_id FROM agents ORDER BY last_seen DESC LIMIT 1`).Scan(&id)
	if err != nil || strings.TrimSpace(id) == "" {
		fmt.Println("ERR")
		os.Exit(1)
	}
	fmt.Println(id)
}
