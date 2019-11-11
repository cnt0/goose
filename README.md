# goose

just like https://git.sr.ht/~sircmpwn/noseplumbs, but in go.  
Cross-platform, has no dependencies except of `golang.org/x/crypto/*`.

Uses `Ed25519` for signatures and `curve25519/XSalsa20/Poly1305` for encryption/decryption.

## Installation

```make
make
make install
make uninstall
```
## Usage

Generate secret key:
```
goose genkey -e > enc.priv.key
goose genkey -s > sign.priv.key
```

Generate public key:
```
goose pubkey < enc.priv.key > enc.pub.key
goose pubkey < sign.priv.key > sign.pub.key
```

Encrypt input:
```
goose encrypt enc.pub.key < cleartext.txt > ciphertext.bin
```

Decrypt input:
```
goose decrypt enc.priv.key < ciphertext.bin > cleartext.txt
```

Sign input:
```
goose sign sign.priv.key < cleartext.txt > cleartext.sig
```

Verify input signature:
```
goose verify sign.pub.key cleartext.sig < cleartext.txt
```


Enjoy!
