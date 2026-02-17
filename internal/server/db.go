package server

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func InitDB(connString string) error {
	var err error

	DB, err = pgxpool.New(context.Background(), connString)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %w", err)
	}

	err = DB.Ping(context.Background())
	if err != nil {
		return fmt.Errorf("database not reachable: %w", err)
	}

	log.Println("PostgreSQL connected successfully")
	return nil
}

func CloseDB() {
	if DB != nil {
		DB.Close()
		log.Println("Database connection closed")
	}
}
