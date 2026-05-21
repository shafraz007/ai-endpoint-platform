//go:build !windows

package main

import "github.com/shafraz007/ai-endpoint-platform/internal/config"

func tryRunWindowsService(_ config.AgentConfig) bool {
	return false
}
