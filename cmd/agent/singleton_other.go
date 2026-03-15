//go:build !windows

package main

func acquireProcessSingleton(_ string) (func(), error) {
	return func() {}, nil
}
