package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"runtime"
)

// payload.bin is generated during the Docker build (dd if=/dev/urandom ...).
// Embedding it here makes the compiled binary large (~60 MiB on disk) so that
// the FUSE page-cache charge is clearly visible in cgroup memory counters.
//
//go:embed payload.bin
var payload []byte

func main() {
	// Touch every page of the embedded payload so that *executing* the binary
	// faults the whole thing into the page cache — mimicking a real large
	// binary whose code/data is actually used at runtime. Without this, the Go
	// runtime would only fault the code pages it executes (~1 MiB), and the
	// embedded data would stay non-resident, understating the per-container
	// page-cache charge. We keep a running sum so the compiler can't elide it.
	var sum byte
	for i := 0; i < len(payload); i += 4096 {
		sum += payload[i]
	}

	fmt.Fprintf(os.Stderr, "nydus-reproducer: pid=%d, embedded=%d bytes (faulted, cksum=%d), GOMAXPROCS=%d\n",
		os.Getpid(), len(payload), sum, runtime.GOMAXPROCS(0))

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok payload_size=%d\n", len(payload))
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
