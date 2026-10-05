# Third-party notices for binary distributions

These files are unmodified license texts from the exact components linked into the v0.1.1 binaries. They are not covered by this repository's own copyright notice.

| Component | Version/source | Notice |
| --- | --- | --- |
| Go standard library/runtime | Go 1.26.2 | [Go-LICENSE](Go-LICENSE) |
| quic-go | `v0.63.1-0.20261005005602-431fe2e3946b` | [quic-go-LICENSE](quic-go-LICENSE) |
| golang.org/x/crypto | `v0.54.0` | [x-crypto-LICENSE](x-crypto-LICENSE) |
| golang.org/x/net | `v0.56.0` | [x-net-LICENSE](x-net-LICENSE) |
| golang.org/x/sys | `v0.47.0` | [x-sys-LICENSE](x-sys-LICENSE) |

The module versions are locked in `go.mod` and `go.sum`; the compiled module list can be checked with `go version -m` against each binary.
