// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// http://ed25519.cr.yp.to/.

// Edits copyright 2015 Factom Foundation under the MIT license.
package ed25519

// This code is a port of the public domain, "ref10" implementation of ed25519
// from SUPERCOP.

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"io"

	"github.com/FactomProject/ed25519/edwards25519"
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 64
	SignatureSize  = 64
)

// GenerateKey generates a public/private key pair using randomness from rand.
func GenerateKey(rand io.Reader) (publicKey *[PublicKeySize]byte, privateKey *[PrivateKeySize]byte, err error) {
	privateKey = new([64]byte)
	_, err = io.ReadFull(rand, privateKey[:32])
	if err != nil {
		return nil, nil, err
	}

	publicKey = GetPublicKey(privateKey)
	return
}

// GetPublicKey returns a public key given a private key.
// in reference to this diagram http://i.stack.imgur.com/5afWK.png
// from this site http://crypto.stackexchange.com/questions/3596/is-it-possible-to-pick-your-ed25519-public-key
// Pass in a 64 byte slice with seed (k) as the private seed in the 32 MSBytes.
// The lower 32 bytes are overwritten with the calculated public key (A).
// The returned value is the same pubkey (A) in a 32 byte wide slice
func GetPublicKey(privateKey *[PrivateKeySize]byte) (publicKey *[PublicKeySize]byte) {
	publicKey = new([32]byte)

	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest)
	edwards25519.GeScalarMultBase(&A, &hBytes)
	A.ToBytes(publicKey)

	copy(privateKey[32:], publicKey[:])
	return
}

// Sign signs the message with privateKey and returns a signature.
func Sign(privateKey *[PrivateKeySize]byte, message []byte) *[SignatureSize]byte {
	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(privateKey[32:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := new([64]byte)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])
	return signature
}

// Verify returns true iff sig is a valid signature of message by publicKey.
func Verify(publicKey *[PublicKeySize]byte, message []byte, sig *[SignatureSize]byte) bool {
	if sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	if !A.FromBytes(publicKey) {
		return false
	}

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return subtle.ConstantTimeCompare(sig[:32], checkR[:]) == 1
}

// VerifyCanonical returns true iff sig is valid and it is in the canonical form.
func VerifyCanonical(publicKey *[PublicKeySize]byte, message []byte, sig *[SignatureSize]byte) bool {
	if CheckCanonicalSig(sig) {
		return Verify(publicKey, message, sig)
	}
	return false
}

// CheckCanonicalSig takes in an ed25519 signature
// with R being the first 32 bytes and S being the latter 32 bytes.
// It returns true if the signature is in the canonical form.
// This function checks to see if the S value of the signature is below
// the group order to prevent a malleated signature from
// being valid even though the Verify() function considers them valid.
// This is what Ripple does, and the algorithms are borrowed from here:
// https://github.com/ripple/rippled/blob/develop/src/ripple/protocol/impl/RippleAddress.cpp#L45
// The NXT community explains the rationale here:
// https://gist.github.com/doctorevil/9521116#signature-malleability-and-signature-canonicalization
// https://web.archive.org/web/20140815132834/https://nextcoin.org/index.php/topic,3884.0.html
// also see: http://crypto.stackexchange.com/questions/14712/non-standard-signature-security-definition-conforming-ed25519-malleability
// This code may not eliminate all forms of malleability.

func CheckCanonicalSig(sig *[SignatureSize]byte) bool {

	// The group order is 2^252 + 27742317777372353535851937790883648493 referred to as l
	// or 7237005577332262213973186563042994240857116359379907606001950938285454250989
	// or 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
	var groupOrder = [32]byte{
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED}

	// convert S from little endian to big endian
	sValueBigEndian := new([32]byte)
	for f, b := 0, (SignatureSize - 1); f < 32; f, b = f+1, b-1 {
		sValueBigEndian[f] = sig[b]
	}
	// the S value must be lower than the group order l to be canonical
	if bytes.Compare(sValueBigEndian[:], groupOrder[:]) < 0 {
		return true
	} else {
		return false
	}
}
