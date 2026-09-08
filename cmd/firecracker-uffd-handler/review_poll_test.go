package main

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestReviewPollRejectsInvalidDescriptor(t *testing.T) {
	wake, err := newCancelWake()
	if err != nil {
		t.Fatal(err)
	}
	defer wake.close()
	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := unix.Close(fds[0]); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = pollUffdOrCancel(fds[0], wake, 0)
	if err == nil {
		t.Fatal("POLLNVAL swallowed: main would immediately repoll forever")
	}
}
