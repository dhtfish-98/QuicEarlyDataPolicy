# Origin, attribution, and rights

- New policy, server wrapper, CLI, tests, and documentation: **dhtfish98**, version 0.1.1. The implementation was written for this repository. No upstream source file is copied or patched here.
- Pinned dependency: [`quic-go/quic-go` commit `431fe2e3946b8d75c6db436a6866a83a91a24a7d`](https://github.com/quic-go/quic-go/commit/431fe2e3946b8d75c6db436a6866a83a91a24a7d), resolved Go module `v0.63.1-0.20261005005602-431fe2e3946b`. Its [MIT license at that commit](https://github.com/quic-go/quic-go/blob/431fe2e3946b8d75c6db436a6866a83a91a24a7d/LICENSE) and upstream authorship remain intact. Dependency notices are not replaced by this repository's authorship.
- Protocol basis: [RFC 9001 §8 (0-RTT replay)](https://www.rfc-editor.org/rfc/rfc9001.html#section-8), [RFC 9000 §17.2 (packet headers)](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2), and [quic-go server documentation](https://quic-go.net/docs/quic/server/).

This is independent defensive application code using quic-go as a third-party dependency. It does not claim that quic-go has a vulnerability or that the dependency's copyright belongs to dhtfish98. See the separate [license for this repository's original material](LICENSE).

The binary archives include unmodified notices for the linked Go runtime and modules in [third-party licenses](第三方许可/README.md). Those rights remain with their original owners.
