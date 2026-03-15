//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

var errAgentAlreadyRunning = errors.New("another agent instance is already running on this device")

func acquireProcessSingleton(name string) (func(), error) {
	trimmed := "Local\\" + name
	namePtr, err := windows.UTF16PtrFromString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to create singleton name: %w", err)
	}

	handle, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			if handle != 0 {
				_ = windows.CloseHandle(handle)
			}
			return nil, errAgentAlreadyRunning
		}
		return nil, fmt.Errorf("failed to create singleton mutex: %w", err)
	}

	release := func() {
		_ = windows.CloseHandle(handle)
	}

	return release, nil
}
