# Synchronous checkpoint SHA-256 batches

`Sum256` accepts up to 16 independent messages, computes ordinary SHA-256, and returns synchronously without retaining input references. It has fixed scratch space, no worker goroutines, and a standard-library fallback. Packed publication uses this package only with the experimental `cn-publish -pack-batch-hash` option (`Options.PackBatchHash`), which defaults to false. Hash microbenchmarks do not establish full publication latency improvements.

The compression assembly and round constants are derived from `github.com/minio/sha256-simd` **v1.0.1** (module sum `h1:6kaan5IFmwTNynnKKpDHe6FWHohJOHhCPchzK49dzMM=`). The assembly instruction body is unchanged. Its Go build constraint and provenance comment were updated. The synchronous padding, bounded mask windows, API, and feature guard are new. The asynchronous upstream server is not included. No linkname or dependency on an unexported upstream Go symbol is used.

See `LICENSE` for MinIO Apache-2.0 terms and `upstream/sha256blockAvx512_amd64.asm` for the readable assembly and retained Intel BSD copyright/disclaimer. Preserve both when redistributing. This copied assembly must be reviewed and retested when updating Go or the upstream implementation.

Feature detection uses the existing `golang.org/x/sys/cpu` dependency and honors CPU feature disables. `noasm`, `appengine`, non-amd64, and non-gc builds use the standard library. A batch smaller than four uses the standard library. The assembly is not race-instrumented; immutable inputs are required and guard-page tests complement the Go race checks.
