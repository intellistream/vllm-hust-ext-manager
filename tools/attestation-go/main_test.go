package main

import "testing"

func TestSharedVectors(t *testing.T) {
	if err := run("../../spec/0.1/attestation-vectors.json"); err != nil {
		t.Fatal(err)
	}
}
