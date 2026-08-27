package meta

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"log/slog"

	bolt "go.etcd.io/bbolt"

	"github.com/ivangsm/jay/internal/jsonx"
)

// This file holds the CRUD core for bbolt's JSON records: accounts, tokens,
// buckets, multipart uploads. There used to be roughly fifteen methods that were
// byte-for-byte identical apart from the type and the bbolt bucket; now there is
// one core.
//
// The *Tx variants below exist for the cases that need several reads inside the
// SAME transaction — GetBucketByID, for instance, resolves the id→name reverse
// index and then reads the record, and splitting that across two transactions
// would lose atomicity.

// SetDecodeFailureHook registers a callback fired whenever a metadata record
// fails to decode. main.go's wiring points it at the
// contador MetadataDecodeFailures de maintenance.Metrics.
//
// meta cannot import maintenance — maintenance already imports meta — so the
// dependency is inverted with a hook, exactly like tokenInvalidateHook.
// Pasar nil lo limpia.
func (db *DB) SetDecodeFailureHook(fn func(bucket, key string)) {
	db.hookMu.Lock()
	db.decodeFailureHook = fn
	db.hookMu.Unlock()
}

// reportDecodeFailure deja constancia de un registro ilegible.
//
// A corrupt record is skipped — one rotten row must not take down a whole
// listing — but NOT silently: it is logged at error level with the key and
// se incrementa un contador expuesto en /metrics. Un jay.db degradándose tiene
// has to be visible. This used to be a bare `return nil` that handed back a
// "successful" listing with rows missing from it.
func (db *DB) reportDecodeFailure(bucket []byte, key string, err error) {
	slog.Error("meta: registro de metadata ilegible, se omite",
		"bucket", string(bucket), "key", key, "err", err)
	db.hookMu.RLock()
	fn := db.decodeFailureHook
	db.hookMu.RUnlock()
	if fn != nil {
		fn(string(bucket), key)
	}
}

// getRecordTx reads and decodes a record inside an open transaction. Returns
// notFound when the key does not exist.
func getRecordTx[T any](tx *bolt.Tx, bucket, key []byte, notFound error) (*T, error) {
	bk := tx.Bucket(bucket)
	if bk == nil {
		return nil, notFound
	}
	data := bk.Get(key)
	if data == nil {
		return nil, notFound
	}
	var v T
	if err := jsonv2.Unmarshal(data, &v, jsonx.Wire); err != nil {
		return nil, fmt.Errorf("meta: decode %s/%s: %w", bucket, key, err)
	}
	return &v, nil
}

// putRecordTx encodes and writes a record inside an open transaction.
func putRecordTx[T any](tx *bolt.Tx, bucket, key []byte, v *T) error {
	bk := tx.Bucket(bucket)
	if bk == nil {
		return fmt.Errorf("meta: bbolt bucket %s missing", bucket)
	}
	data, err := jsonv2.Marshal(v, jsonx.Wire)
	if err != nil {
		return fmt.Errorf("meta: encode %s/%s: %w", bucket, key, err)
	}
	return bk.Put(key, data)
}

// getRecord lee un registro en su propia transacción de lectura.
func (db *DB) getRecord[T any](bucket []byte, key string, notFound error) (*T, error) {
	var out *T
	err := db.bolt.View(func(tx *bolt.Tx) error {
		v, err := getRecordTx[T](tx, bucket, []byte(key), notFound)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// putRecord escribe un registro en su propia transacción de escritura.
func (db *DB) putRecord[T any](bucket []byte, key string, v *T) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return putRecordTx[T](tx, bucket, []byte(key), v)
	})
}

// listRecords walks a whole bbolt bucket and returns the records keep accepts —
// a nil keep means all of them. Unreadable records are skipped and reported via
// reportDecodeFailure; see that function's comment.
func (db *DB) listRecords[T any](bucket []byte, keep func(*T) bool) ([]T, error) {
	var out []T
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucket)
		if bk == nil {
			return nil
		}
		return bk.ForEach(func(k, v []byte) error {
			var rec T
			if err := jsonv2.Unmarshal(v, &rec, jsonx.Wire); err != nil {
				db.reportDecodeFailure(bucket, string(k), err)
				return nil
			}
			if keep == nil || keep(&rec) {
				out = append(out, rec)
			}
			return nil
		})
	})
	return out, err
}

// updateRecord applies a read-modify-write to a record in a single write
// transaction. mutate receives the decoded record and can abort by returning an
// error, which propagates and rolls the transaction back.
func (db *DB) updateRecord[T any](bucket []byte, key string, notFound error, mutate func(*T) error) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		rec, err := getRecordTx[T](tx, bucket, []byte(key), notFound)
		if err != nil {
			return err
		}
		if err := mutate(rec); err != nil {
			return err
		}
		return putRecordTx[T](tx, bucket, []byte(key), rec)
	})
}
