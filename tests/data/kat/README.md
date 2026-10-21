# Known-answer vectors

Each `<protocol>/vectors.json` holds inputs and the outputs the reference
implementation computed for them. The test beside the code it checks reads
the file (`src/kat.rs`) and compares bytes. A shoes-to-shoes round trip passes
when both halves share a misreading. A vector the reference computed does
not.

| Fixture | Reference | Checked by |
|---|---|---|
| `shadowsocks` | sing-shadowsocks v0.2.9: `shadowsocks.Key` (EVP_BytesToKey), `shadowaead.Kdf` (HKDF-SHA1 "ss-subkey"), `shadowaead_2022.SessionKey` (blake3) | `src/shadowsocks/default_key.rs`, `blake3_key.rs` |
| `snell` | open-snell 8d2645b: `NewAES128GCM`, `NewChacha20Poly1305`, `Encrypter` (Argon2id) | `src/snell/snell_handler.rs` |
| `vmess` | sing-vmess v0.2.8: `Key`, `KDF`, `AuthID`; Go `hash/crc32` | `src/vmess/vmess_handler.rs` |
| `salamander` | hysteria extras v2.13.0: `obfs.WrapPacketConnSalamander` | `src/quic_transport/obfs/salamander.rs` |
| `mieru` | mieru v3.38.2: `cipher.HashPassword`, `BlockCipherFromPassword` (PBKDF2) | `src/mieru/crypto.rs` |

Where a reference keeps its derived key private (Snell, salamander, mieru),
the vector holds bytes the reference put on the wire with that key. Shoes
must produce or open those exact bytes. That tests more than comparing keys
would.

The salamander and mieru vectors, and VMess's AuthID, contain random bytes or
the time they were made. So regenerating them changes the files without
anything being wrong.

## Regenerating

`gen/` is a Go program that imports the references at the versions pinned in
`gen/go.mod` and rewrites every `vectors.json`. It downloads those modules,
so it runs in a container with only this directory mounted, never from the
repository root:

```sh
container run --rm -v "$PWD/tests/data/kat:/kat" -w /kat/gen golang:1.27 go run .
```

(`docker run` takes the same arguments.) To move a reference to a newer
version, run `go get <module>@<version>` the same way, then regenerate.
Commit the vectors and `go.mod`/`go.sum` together.
