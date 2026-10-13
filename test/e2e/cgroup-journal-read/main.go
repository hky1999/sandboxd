// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

// cgroup-journal-read only observes the explicitly enabled fixture database.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/inclusionAI/sandboxd/config"
	bolt "go.etcd.io/bbolt"
	"os"
	"time"
)

func read() error {
	const path = "/test-state/store/metadata.db"
	if os.Getenv("SANDBOXD_DAEMON_RETIREMENT_FIXTURE") != "1" || len(os.Args) != 1 {
		return fmt.Errorf("explicit owned fixture required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("original regular fixture database required")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(config.CgroupBucket))
		if bucket == nil {
			return fmt.Errorf("original cgroup bucket absent")
		}
		data := bucket.Get([]byte(config.CgroupBucket))
		if len(data) == 0 || len(data) > 4*1024*1024 || !json.Valid(data) {
			return fmt.Errorf("bounded original cgroup JSON required")
		}
		_, err := os.Stdout.Write(append(append([]byte(nil), data...), '\n'))
		return err
	})
}
func main() {
	if err := read(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
