# Native MitM drafts (B7 / B8) — backup, not built

Working drafts for TODO.md's B7 (TLS termination) and B8 (HTTP/1.1 parsing
& upstream), kept on this branch purely as a backup until the A line pushes
`feat/native-mitm` and the B6 flow API settles. Nothing here is referenced
by the Xcode project or compiled.

| File | Origin | Final home (per TODO.md) |
|---|---|---|
| `LeafCertIssuer.swift` | B7, rewritten on review (hand-rolled DER + SecKeyCreateSignature; see README-B7's correction note) | `PacketTunnel/NativeMitM/TLS*.swift` |
| `CertCache.swift` | B7, reviewed OK as-is | `PacketTunnel/NativeMitM/` |
| `README-B7.md` | B7 design doc (with review corrections applied) | — |
| `HTTPMessage.swift` | B8 draft | `PacketTunnel/NativeMitM/HTTP*.swift` |
| `HeaderRewrite.swift` | B8 draft | `PacketTunnel/NativeMitM/` |
| `Upstream.swift` | B8 draft | `PacketTunnel/NativeMitM/Upstream*.swift` |
| `README-B8.md` | B8 design doc, incl. B9 boundary notes and OPEN items for B6 | — |

When `feat/native-mitm` lands: move the Swift files to their final homes,
wire them against the B6 interfaces, get a first compile via ios.yml
build_only, then delete this branch.
