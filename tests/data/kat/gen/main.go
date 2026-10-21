// Command gen writes the known-answer vectors under tests/data/kat/ by
// calling the reference implementations themselves, so that shoes is checked
// against what they compute rather than against its own idea of it.
//
// It runs in a container, never from the repository root; see README.md.
package main

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/gofrs/uuid/v5"
	snell "github.com/icpz/open-snell/components/aead"
	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
)

type object = map[string]any

func h(b []byte) string { return hex.EncodeToString(b) }

// bytesOf is a deterministic input of length n, distinct per seed.
func bytesOf(seed byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i*7)
	}
	return out
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(protocol, source string, vectors object) {
	vectors["source"] = source
	data, err := json.MarshalIndent(vectors, "", "  ")
	must(err)
	dir := filepath.Join("..", protocol)
	must(os.MkdirAll(dir, 0o755))
	must(os.WriteFile(filepath.Join(dir, "vectors.json"), append(data, '\n'), 0o644))
	fmt.Println("wrote", filepath.Join(dir, "vectors.json"))
}

// Shadowsocks AEAD (EVP_BytesToKey, HKDF-SHA1 "ss-subkey") and 2022 (blake3
// session subkey).
func genShadowsocks() {
	var evp, subkeys, blake []object
	for _, c := range []struct {
		password string
		keyLen   int
	}{{"", 16}, {"password", 16}, {"password", 32}, {"a much longer password, past one digest", 32}} {
		evp = append(evp, object{
			"password": c.password,
			"key_len":  c.keyLen,
			"key":      h(shadowsocks.Key([]byte(c.password), c.keyLen)),
		})
	}
	for _, keyLen := range []int{16, 32} {
		key := shadowsocks.Key([]byte("password"), keyLen)
		salt := bytesOf(0x40, keyLen)
		out := buf.NewSize(keyLen)
		shadowaead.Kdf(key, salt, out)
		subkeys = append(subkeys, object{"key": h(key), "salt": h(salt), "subkey": h(out.Bytes())})
		out.Release()

		psk := bytesOf(0x10, keyLen)
		blake = append(blake, object{
			"psk":    h(psk),
			"salt":   h(salt),
			"subkey": h(shadowaead_2022.SessionKey(psk, salt, keyLen)),
		})
	}
	write("shadowsocks", "github.com/sagernet/sing-shadowsocks: shadowsocks.Key, shadowaead.Kdf, shadowaead_2022.SessionKey", object{
		"evp_bytes_to_key":      evp,
		"hkdf_sha1_subkey":      subkeys,
		"blake3_session_subkey": blake,
	})
}

// Snell: the Argon2id session key is internal to open-snell, so each vector
// is a message sealed with the AEAD it builds from psk and salt, under the
// all-zero nonce of a stream's first chunk.
func genSnell() {
	var sealed []object
	for _, c := range []struct {
		name string
		make func([]byte) snell.Cipher
	}{{"aes-128-gcm", snell.NewAES128GCM}, {"chacha20-ietf-poly1305", snell.NewChacha20Poly1305}} {
		psk := []byte("snell psk")
		salt := bytesOf(0x21, 16)
		plaintext := []byte("snell known answer")
		aead, err := c.make(psk).Encrypter(salt)
		must(err)
		nonce := make([]byte, aead.NonceSize())
		sealed = append(sealed, object{
			"cipher":     c.name,
			"psk":        string(psk),
			"salt":       h(salt),
			"plaintext":  h(plaintext),
			"ciphertext": h(aead.Seal(nil, nonce, plaintext, nil)),
		})
	}
	write("snell", "github.com/icpz/open-snell components/aead: NewAES128GCM, NewChacha20Poly1305, Encrypter", object{"sealed": sealed})
}

// VMess: the command key, the KDF, crc32 and a sealed AuthID.
func genVmess() {
	user := uuid.Must(uuid.FromString("b831381d-6324-4d53-ad4f-8cda48b30811"))
	cmdKey := vmess.Key(user)

	authID := bytesOf(0x30, 16)
	nonce := bytesOf(0x50, 8)
	var kdf []object
	for _, c := range []struct {
		salt string
		path [][]byte
	}{
		{vmess.KDFSaltConstAuthIDEncryptionKey, nil},
		{vmess.KDFSaltConstVMessHeaderPayloadLengthAEADKey, [][]byte{authID, nonce}},
		{vmess.KDFSaltConstVMessHeaderPayloadLengthAEADIV, [][]byte{authID, nonce}},
		{vmess.KDFSaltConstVMessHeaderPayloadAEADKey, [][]byte{authID, nonce}},
		{vmess.KDFSaltConstVMessHeaderPayloadAEADIV, [][]byte{authID, nonce}},
		{vmess.KDFSaltConstAEADRespHeaderLenKey, nil},
		{vmess.KDFSaltConstAEADRespHeaderLenIV, nil},
		{vmess.KDFSaltConstAEADRespHeaderPayloadKey, nil},
		{vmess.KDFSaltConstAEADRespHeaderPayloadIV, nil},
	} {
		path := []string{h([]byte(c.salt))}
		for _, p := range c.path {
			path = append(path, h(p))
		}
		kdf = append(kdf, object{
			"key":    h(cmdKey[:]),
			"path":   path,
			"output": h(vmess.KDF(cmdKey[:], c.salt, c.path...)),
		})
	}

	var crc []object
	for _, input := range [][]byte{{}, []byte("123456789"), bytesOf(0x01, 12)} {
		var sum [4]byte
		binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE(input))
		crc = append(crc, object{"input": h(input), "crc32": h(sum[:])})
	}

	// AuthID draws four random bytes, so the plaintext is recovered by
	// decrypting what it sealed: shoes must seal the same plaintext to the
	// same bytes and open the sealed bytes to the same timestamp.
	timestamp := time.Unix(1760000000, 0)
	sealedBuf := buf.NewSize(16)
	vmess.AuthID(cmdKey, timestamp, sealedBuf)
	sealed := append([]byte(nil), sealedBuf.Bytes()...)
	sealedBuf.Release()
	block, err := aes.NewCipher(vmess.KDF(cmdKey[:], vmess.KDFSaltConstAuthIDEncryptionKey)[:16])
	must(err)
	plaintext := make([]byte, 16)
	block.Decrypt(plaintext, sealed)

	write("vmess", "github.com/sagernet/sing-vmess: Key, KDF, AuthID; hash/crc32.ChecksumIEEE", object{
		"user_id": user.String(),
		"cmd_key": h(cmdKey[:]),
		"kdf":     kdf,
		"crc32":   crc,
		"auth_id": object{
			"timestamp": timestamp.Unix(),
			"plaintext": h(plaintext),
			"sealed":    h(sealed),
		},
	})
}

// capture is a PacketConn that records what is written to it.
type capture struct {
	net.PacketConn
	written [][]byte
}

func (c *capture) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

// Salamander: the key derivation is internal to the obfuscator, so each
// vector is a packet as the reference puts it on the wire, random salt and
// all, for shoes to deobfuscate.
func genSalamander() {
	psk := []byte("salamander psk")
	sink := &capture{}
	conn, err := obfs.WrapPacketConnSalamander(sink, psk)
	must(err)
	var packets []object
	for _, n := range []int{1, 32, 33, 100} {
		payload := bytesOf(byte(n), n)
		_, err := conn.WriteTo(payload, &net.UDPAddr{})
		must(err)
		packets = append(packets, object{
			"payload": h(payload),
			"wire":    h(sink.written[len(sink.written)-1]),
		})
	}
	write("salamander", "github.com/apernet/hysteria/extras/v2/obfs: WrapPacketConnSalamander", object{
		"psk":     string(psk),
		"packets": packets,
	})
}

// mieru: the PBKDF2 key is internal, and its salt is the current time, so the
// vectors are two messages of one direction sealed now, with the time that
// chose the key. The first carries its nonce; the second uses the next one.
func genMieru() {
	password, username := []byte("mieru password"), []byte("mieru-user")
	hashed := cipher.HashPassword(password, username)
	for {
		before := time.Now()
		block, err := cipher.BlockCipherFromPassword(hashed, false)
		must(err)
		after := time.Now()
		if before.Round(cipher.KeyRefreshInterval) != after.Round(cipher.KeyRefreshInterval) {
			continue // the key epoch turned over mid-call; it is not knowable
		}
		var messages []object
		for _, plaintext := range [][]byte{[]byte("first mieru message"), []byte("second")} {
			n := len(plaintext) + block.Overhead()
			if len(messages) == 0 {
				n += block.NonceSize()
			}
			dst := make([]byte, 0, n)
			must(block.Encrypt(dst, plaintext))
			messages = append(messages, object{"plaintext": h(plaintext), "sealed": h(dst[:n])})
		}
		write("mieru", "github.com/enfein/mieru/v3/pkg/cipher: HashPassword, BlockCipherFromPassword (implicit nonce)", object{
			"password":  string(password),
			"username":  string(username),
			"unix_time": before.Unix(),
			"messages":  messages,
		})
		return
	}
}

// Every generator by default; with arguments, only those named, so adding a
// fixture does not rewrite the ones whose bytes are random.
func main() {
	generators := map[string]func(){
		"shadowsocks":     genShadowsocks,
		"snell":           genSnell,
		"vmess":           genVmess,
		"salamander":      genSalamander,
		"mieru":           genMieru,
		"shadowtls":       genShadowTLS,
		"reality":         genReality,
		"frames-sing":     genFrames,
		"frames-sing-tls": genFramesTLS,
	}
	names := os.Args[1:]
	if len(names) == 0 {
		for name := range generators {
			names = append(names, name)
		}
	}
	for _, name := range names {
		generate, ok := generators[name]
		if !ok {
			panic("no generator " + name)
		}
		generate()
	}
}
