# Vendored JCS implementation

The two Go source files in this directory are vendored verbatim from the
maintained [`cyberphone/json-canonicalization`](https://github.com/cyberphone/json-canonicalization)
reference implementation at commit
`19d51d7fe467d4706a3ff08adf8a748f29fc21e0` on 2026-09-18 because the validation environment
could not authenticate `proxy.golang.org`.

- `jsoncanonicalizer.go` source: `go/src/webpki.org/jsoncanonicalizer/jsoncanonicalizer.go`
  SHA-256: `f77ac1b1e62ca9ab063cc558702ab830a0e6442fe71659d34d63897ea9c4e1ac`
- `es6numfmt.go` source: `go/src/webpki.org/jsoncanonicalizer/es6numfmt.go`
  SHA-256: `a5f31e4411d030c309b79d865329d02f90deeaabb9e926ceb0399cf053541e8c`

The upstream file headers license the implementation under Apache-2.0. These
files are an explicit library dependency, not a locally approximated JSON
sorting implementation.
