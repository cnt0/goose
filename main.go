package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	_ "github.com/cnt0/goose/init"
)

const (
	SignPkSize    = ed25519.PublicKeySize
	SignSkSize    = ed25519.PrivateKeySize
	SeedSize      = ed25519.SeedSize
	SignatureSize = ed25519.SignatureSize

	EncrHeader = "x25519:1:"
	EncrPkSize = 32
	EncrSkSize = 32
	NonceSize  = 24

	Usage = `Usage:

Generate secret key:
goose genkey -e > enc.priv.key
goose genkey -s > sign.priv.key

Generate public key:
goose pubkey < enc.priv.key > enc.pub.key
goose pubkey < sign.priv.key > sign.pub.key

Encrypt input:
goose encrypt enc.pub.key < cleartext.txt > ciphertext.bin

Decrypt input:
goose decrypt enc.priv.key < ciphertext.bin > cleartext.txt

Sign input:
goose sign sign.priv.key < cleartext.txt > cleartext.sig

Verify input signature:
goose verify sign.pub.key cleartext.sig < cleartext.txt
`
)

// nonce generation algorithm from libsodium
func NonceFromPks(ePk, pk *[EncrPkSize]byte) [NonceSize]byte {
	var nonce [NonceSize]byte
	hasher, err := blake2b.New(NonceSize, nil)
	if err != nil {
		panic(err)
	}
	if _, err := io.CopyN(hasher, bytes.NewBuffer(ePk[:]), EncrPkSize); err != nil {
		panic(err)
	}
	if _, err := io.CopyN(hasher, bytes.NewBuffer(pk[:]), EncrPkSize); err != nil {
		panic(err)
	}
	copy(nonce[:], hasher.Sum(nil))
	return nonce
}

func usage() {
	if _, err := io.WriteString(os.Stdout, Usage); err != nil {
		panic(err)
	}
	os.Exit(0)
}

// goose genkey -e > enc.priv.key
// goose genkey -s > sign.priv.key
func genkey() {
	if len(os.Args) < 3 {
		usage()
	}
	if os.Args[2] == "-e" {
		_, sk, err := box.GenerateKey(crypto_rand.Reader)
		if err != nil {
			panic(err)
		}
		if _, err = io.CopyN(os.Stdout, bytes.NewBuffer(sk[:]), EncrSkSize); err != nil {
			panic(err)
		}
		return
	}
	if os.Args[2] == "-s" {
		_, sk, err := ed25519.GenerateKey(crypto_rand.Reader)
		if err != nil {
			panic(err)
		}
		if _, err := io.CopyN(os.Stdout, bytes.NewBuffer(sk), SignSkSize); err != nil {
			panic(err)
		}
		return
	}
	usage()
}

// goose pubkey < enc.priv.key > enc.pub.key
// goose pubkey < sign.priv.key > sign.pub.key
func pubkey() {
	var sk [SignSkSize]byte
	n, err := os.Stdin.Read(sk[:])
	if err != nil {
		panic(err)
	}
	if n >= SignSkSize {
		// ed25519 secret key
		_, err := io.CopyN(os.Stdout, bytes.NewBuffer(sk[SeedSize:]), SignPkSize)
		if err != nil {
			panic(err)
		}
		return
	}
	if n >= EncrSkSize {
		// curve25519 secret key
		var curveSk [EncrSkSize]byte
		var curvePk [EncrPkSize]byte
		copy(curveSk[:], sk[:])
		curve25519.ScalarBaseMult(&curvePk, &curveSk)
		_, err := io.CopyN(os.Stdout, bytes.NewBuffer(curvePk[:]), EncrPkSize)
		if err != nil {
			panic(err)
		}
		return
	}
	panic("can't read private key from stdin")
}

// goose sign sign.priv.key < cleartext.txt > cleartext.sig
func sign() {
	if len(os.Args) < 3 {
		usage()
	}
	var sk [SignSkSize]byte

	// read secret key
	f, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err = io.ReadFull(f, sk[:]); err != nil {
		panic(err)
	}

	// read message
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	sig := bytes.NewBuffer(ed25519.Sign(sk[:], msg))
	if _, err = io.CopyN(os.Stdout, sig, SignatureSize); err != nil {
		panic(err)
	}
}

// goose verify pub.key cleartext.sig < cleartext.txt
func verify() {
	if len(os.Args) < 4 {
		usage()
	}
	var pk [SignPkSize]byte
	var sig [SignatureSize]byte

	// read public key
	fpk, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer fpk.Close()
	if _, err = io.ReadFull(fpk, pk[:]); err != nil {
		panic(err)
	}

	// read signature
	fsig, err := os.Open(os.Args[3])
	if err != nil {
		panic(err)
	}
	defer fsig.Close()
	if _, err = io.ReadFull(fsig, sig[:]); err != nil {
		panic(err)
	}

	// read message
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	if ed25519.Verify(pk[:], msg, sig[:]) {
		os.Stdout.WriteString("Correct signature.\n")
	} else {
		panic("Incorrect signature.\n")
	}
}

// goose encrypt pub.key < cleartext.txt > ciphertext.bin
func encrypt() {
	if len(os.Args) < 3 {
		usage()
	}

	var pk [EncrPkSize]byte

	// read public key
	fpk, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer fpk.Close()
	if _, err := io.ReadFull(fpk, pk[:]); err != nil {
		panic(err)
	}

	// ephemeral keypair
	ePk, eSk, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}

	// read message
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	nonce := NonceFromPks(ePk, &pk)
	enc := box.Seal(nil, msg, &nonce, &pk, eSk)

	// encrypted message structure:
	// [x25519:1:][ephemeral_pk][encrypted_data]
	if _, err := io.CopyN(os.Stdout, bytes.NewBufferString(EncrHeader), int64(len(EncrHeader))); err != nil {
		panic(err)
	}
	if _, err := io.CopyN(os.Stdout, bytes.NewBuffer(ePk[:]), EncrPkSize); err != nil {
		panic(err)
	}
	if _, err := io.CopyN(os.Stdout, bytes.NewBuffer(enc), int64(len(enc))); err != nil {
		panic(err)
	}
}

// goose decrypt secret.key < ciphertext.bin > cleartext.txt
func decrypt() {
	if len(os.Args) < 3 {
		usage()
	}
	var sk [EncrSkSize]byte
	var pk [EncrPkSize]byte
	var ePk [EncrPkSize]byte

	// read secret key
	fsk, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer fsk.Close()
	if _, err := io.ReadFull(fsk, sk[:]); err != nil {
		panic(err)
	}

	// public key from secret key to generate nonce
	curve25519.ScalarBaseMult(&pk, &sk)

	// should be "x25519:1:"
	header := make([]byte, len(EncrHeader))
	if _, err := io.ReadFull(os.Stdin, header); err != nil {
		panic(err)
	}
	if string(header) != EncrHeader {
		panic("unknown encrypted message header")
	}

	if _, err := io.ReadFull(os.Stdin, ePk[:]); err != nil {
		panic(err)
	}

	nonce := NonceFromPks(&ePk, &pk)
	enc, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	msg, ok := box.Open(nil, enc, &nonce, &ePk, &sk)
	if !ok {
		panic("can't decrypt message")
	}
	if _, err := io.CopyN(os.Stdout, bytes.NewBuffer(msg), int64(len(msg))); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "genkey":
		genkey()
	case "pubkey":
		pubkey()
	case "sign":
		sign()
	case "verify":
		verify()
	case "encrypt":
		encrypt()
	case "decrypt":
		decrypt()
	default:
		usage()
	}
}
