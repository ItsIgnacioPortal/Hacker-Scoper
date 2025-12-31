//go:build benchmark

package main

import (
	"os"
	"runtime"
	"runtime/pprof"
)

var cpufile *os.File
var ramfile *os.File

func StartBenchmark(profileFilenamePrefix string) bool {
	cpufile, err := os.Create(`.\benchmarking\profiling-output\cpu` + profileFilenamePrefix + `.prof`)
	if err != nil {
		crash("could not create CPU profile: ", err)
	}

	ramfile, err = os.Create(`.\benchmarking\profiling-output\ram` + profileFilenamePrefix + `.prof`)
	if err != nil {
		crash("could not create CPU profile: ", err)
	}

	err = pprof.StartCPUProfile(cpufile)
	if err != nil {
		crash("could not start CPU profile: ", err)
	}

	return true
}

func StopBenchmark() bool {
	pprof.StopCPUProfile()
	cpufile.Close()

	// Get a RAM profile
	runtime.GC() // get up-to-date statistics
	// Lookup("allocs") creates a profile similar to go test -memprofile.
	// Alternatively, use Lookup("heap") for a profile
	// that has inuse_space as the default index.
	err := pprof.Lookup("allocs").WriteTo(ramfile, 0)
	if err != nil {
		crash("could not write memory profile: ", err)
	}

	ramfile.Close()

	return true
}
