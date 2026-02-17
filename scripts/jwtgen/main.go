package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/auth"
)

func main() {
	var subject string
	var role string
	var secret string
	var ttlSeconds int

	flag.StringVar(&subject, "subject", "", "JWT subject (agent_id for agents)")
	flag.StringVar(&role, "role", "", "JWT role (agent or admin)")
	flag.StringVar(&secret, "secret", "", "JWT secret")
	flag.IntVar(&ttlSeconds, "ttl", 300, "Token TTL in seconds")
	flag.Parse()

	if subject == "" {
		fmt.Fprintln(os.Stderr, "missing -subject")
		os.Exit(1)
	}
	if role == "" {
		fmt.Fprintln(os.Stderr, "missing -role")
		os.Exit(1)
	}
	if secret == "" {
		fmt.Fprintln(os.Stderr, "missing -secret")
		os.Exit(1)
	}

	token, err := auth.GenerateToken(subject, role, secret, time.Duration(ttlSeconds)*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Println(token)
}
