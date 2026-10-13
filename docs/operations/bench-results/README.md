# Exported reference measurements

These are historical laptop measurements, including failing initial attempts and
passing corrections. See the [complete methodology and tables](../benchmarks.md)
before interpreting throughput, refusals, latency or soak windows.

This migration export preserves the measured numeric results and original
binary/source hashes. Sixteen files had local workspace/check-out paths replaced
by `$WORK` or `$CHECKOUT`; their original and exported SHA-256 values are in
[export-provenance.json](export-provenance.json). Artifact manifests describe
the exported copies and have been recalculated. Original private files remain
unchanged in the development checkout.

The results refer to their recorded development builds, not the repository
migration preview. They do not establish a release performance guarantee or a
recommended deployment size. Database, service and generator shared one laptop.
No secret-bearing seed file is published.
