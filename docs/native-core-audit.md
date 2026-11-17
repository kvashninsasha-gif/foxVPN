# Go binary advisory gate

The release build pins the upstream source archive, dependency overlay and Go toolchain. `govulncheck -mode=binary -format=json` is validated by `scripts/check-go-advisories.py`: malformed/incomplete streams, unknown events, incompatible metadata, missing SBOM/trace and a truncated or inconsistent paired `go list -deps -json` production graph fail closed.

For 0.1.38, the core uses Go 1.26.11, `golang.org/x/crypto v0.59.0`, Brotli v1.2.7 and compress v1.20.2. Fresh November advisory data blocked the old dependency graph. The OpenPGP advisory now identifies a fixed parent module version; the parent module is upgraded. The previous dated OpenPGP wildcard exception is no longer applied: every reported module, package or symbol advisory blocks the build. `reviewed_findings` remains an empty compatibility field. Old real-symbol, wildcard, mixed, module-only and malformed-stream fixtures continue to exercise refusal. A report with no findings and a complete paired graph can pass.

The output records scanner/database metadata and SHA256 for the exact binary report and production graph. Native startup, Windows browser/proxy and routing tests are separate gates; a vulnerability scan does not establish device acceptance.

Historical 0.1.28–0.1.37 releases used the then-current dated OpenPGP absence review. Those results are historical and do not authorize ignoring new advisory metadata.
