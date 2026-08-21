package meta

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"log/slog"

	bolt "go.etcd.io/bbolt"

	"github.com/ivangsm/jay/internal/jsonx"
)

// Este archivo concentra el CRUD de los registros JSON de bbolt (cuentas,
// tokens, buckets, multipart). Antes había ~15 métodos byte por byte iguales
// salvo el tipo y el bbolt bucket; ahora hay un solo núcleo.
//
// Los métodos con parámetros de tipo propios (`func (db *DB) getRecord[T any]`)
// son legales desde Go 1.27. El par `*Tx` de más abajo existe para los casos
// que necesitan hacer varias lecturas dentro de la MISMA transacción —
// GetBucketByID, por ejemplo, resuelve el índice inverso id→nombre y después
// lee el registro, y separar eso en dos transacciones perdería atomicidad.

// SetDecodeFailureHook registra un callback que se dispara cada vez que un
// registro de metadata no deserializa. El wiring de main.go lo apunta al
// contador MetadataDecodeFailures de maintenance.Metrics.
//
// meta no puede importar maintenance (maintenance ya importa meta), así que la
// dependencia se invierte con un hook, igual que tokenInvalidateHook.
// Pasar nil lo limpia.
func (db *DB) SetDecodeFailureHook(fn func(bucket, key string)) {
	db.hookMu.Lock()
	db.decodeFailureHook = fn
	db.hookMu.Unlock()
}

// reportDecodeFailure deja constancia de un registro ilegible.
//
// El registro corrupto se omite (una sola fila podrida no puede tumbar el
// listado entero), pero NO en silencio: se loguea a nivel error con la clave y
// se incrementa un contador expuesto en /metrics. Un jay.db degradándose tiene
// que ser visible; antes esto era un `return nil` pelado que devolvía una lista
// "exitosa" a la que le faltaban filas.
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

// getRecordTx lee y deserializa un registro dentro de una transacción abierta.
// Devuelve notFound si la clave no existe.
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

// putRecordTx serializa y escribe un registro dentro de una transacción abierta.
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

// listRecords recorre un bbolt bucket entero y devuelve los registros que keep
// acepta (keep nil = todos). Los registros ilegibles se omiten y se reportan
// vía reportDecodeFailure; ver el comentario de esa función.
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

// updateRecord aplica un read-modify-write sobre un registro en una sola
// transacción de escritura. mutate recibe el registro ya deserializado y puede
// abortar devolviendo un error (que se propaga y revierte la transacción).
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
