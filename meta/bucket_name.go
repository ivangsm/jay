// Package meta is jay's metadata layer: accounts, buckets, objects, tokens and
// multipart uploads, all persisted in a single embedded bbolt database.
//
// It owns the ACID boundary. Object bytes live on disk (see package store) and
// are only ever referenced from here by LocationRef, so metadata and data can
// disagree after a crash — reconciling that is package recovery's job.
package meta

import (
	"net"
	"regexp"
	"strings"
)

var validBucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// ValidBucketName returns true if name is a legal S3-style bucket name.
func ValidBucketName(name string) bool {
	if !validBucketNameRe.MatchString(name) {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	if strings.Contains(name, "--") {
		return false
	}
	if net.ParseIP(name) != nil {
		return false
	}
	return true
}
