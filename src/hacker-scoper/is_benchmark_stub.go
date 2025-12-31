//go:build !benchmark

package main

func StartBenchmark(profileFilenamePrefix string) bool {
	return true
}

func StopBenchmark() bool {
	return true
}
