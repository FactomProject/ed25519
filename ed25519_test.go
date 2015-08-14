// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func TestSignVerify(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")
	sig := Sign(private, message)
	if !Verify(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if Verify(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestGolden(t *testing.T) {
	// sign.input.gz is a selection of test cases from
	// http://ed25519.cr.yp.to/python/sign.input
	testDataZ, err := os.Open("testdata/sign.input.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		t.Fatal(err)
	}
	defer testData.Close()

	in := bufio.NewReaderSize(testData, 1<<12)
	lineNo := 0
	for {
		lineNo++
		lineBytes, isPrefix, err := in.ReadLine()
		if isPrefix {
			t.Fatal("bufio buffer too small")
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("error reading test data: %s", err)
		}

		line := string(lineBytes)
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			t.Fatalf("bad number of parts on line %d", lineNo)
		}

		privBytes, _ := hex.DecodeString(parts[0])
		pubKeyBytes, _ := hex.DecodeString(parts[1])
		msg, _ := hex.DecodeString(parts[2])
		sig, _ := hex.DecodeString(parts[3])
		// The signatures in the test vectors also include the message
		// at the end, but we just want R and S.
		sig = sig[:SignatureSize]

		if l := len(pubKeyBytes); l != PublicKeySize {
			t.Fatalf("bad public key length on line %d: got %d bytes", lineNo, l)
		}

		var priv [PrivateKeySize]byte
		copy(priv[:], privBytes)
		copy(priv[32:], pubKeyBytes)

		sig2 := Sign(&priv, msg)
		if !bytes.Equal(sig, sig2[:]) {
			t.Errorf("different signature result on line %d: %x vs %x", lineNo, sig, sig2)
		}

		var pubKey [PublicKeySize]byte
		copy(pubKey[:], pubKeyBytes)
		if !Verify(&pubKey, msg, sig2) {
			t.Errorf("signature failed to verify on line %d", lineNo)
		}
	}
}

// see https://github.com/CodesInChaos/Chaos.NaCl/commit/2c861348dc45369508e718aa08611c53b53553db

func TestCanonical(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)
	var groupOrder = [32]byte{
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED}

	message := []byte("test message")
	sig := Sign(private, message)
	if !VerifyCanonical(public, message, sig) {
		t.Errorf("valid canonical signature rejected")
	}

	// convert S from little endian to big endian
	sValueBigEndian := new([32]byte)
	for f, b := 0, (SignatureSize - 1); f < 32; f, b = f+1, b-1 {
		sValueBigEndian[f] = sig[b]
	}
	// convert values into bignum so math can be done
	operator := big.NewInt(0)
	operator.SetBytes(sValueBigEndian[:])
	order := big.NewInt(0)
	order.SetBytes(groupOrder[:])

	// according to CodesInChaos in the above link, this should almost
	// always give a valid sig (tested true with 1 million random sigs).
	// This part malleates the signature
	operator = operator.Add(operator, order)
	malSBigEndian := operator.Bytes()

	// convert malleated S from big endian back to little endian
	malSLittleEndian := new([32]byte)
	for f, b := 0, 31; f < 32; f, b = f+1, b-1 {
		malSLittleEndian[f] = malSBigEndian[b]
	}

	// reconstruct the full signature with R and S
	malleatedSig := new([64]byte)
	copy(malleatedSig[:32], sig[:32])              // copy the R value
	copy(malleatedSig[32:], malSLittleEndian[:32]) // copy the S value

	if !Verify(public, message, malleatedSig) {
		t.Errorf("non-canonical (malleated) signature did not validate when it normally does (might be ok)")
	}
	if VerifyCanonical(public, message, malleatedSig) {
		t.Errorf("non-canonical (malleated) signature validate when it shouldn't")
	}
}
