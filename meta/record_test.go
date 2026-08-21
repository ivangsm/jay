package meta

import (
	"errors"
	"testing"
	"uuid"

	bolt "go.etcd.io/bbolt"
)

// errAbortForTest es un centinela para probar el rollback de updateRecord.
var errAbortForTest = errors.New("abortar a propósito")

// corruptRecord mete basura cruda bajo una clave para simular un registro de
// bbolt ilegible (bit rot, un downgrade que escribió otro formato, etc).
func corruptRecord(t *testing.T, db *DB, bucket []byte, key string) {
	t.Helper()
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put([]byte(key), []byte("{no soy json"))
	})
	if err != nil {
		t.Fatalf("corromper %s/%s: %v", bucket, key, err)
	}
}

// TestListRecords_CorruptRecordIsLoudNotSilent fija la decisión del refactor:
// un registro corrupto se omite del listado (una sola fila podrida no puede
// tumbar la operación entera), pero NUNCA en silencio — dispara el hook de
// fallo de decodificación, que main.go apunta al contador
// MetadataDecodeFailures del admin API.
//
// Antes esto era un `return nil` pelado: la lista salía "exitosa" con filas
// de menos y no quedaba rastro en ningún lado.
func TestListRecords_CorruptRecordIsLoudNotSilent(t *testing.T) {
	db := openExtraTestDB(t)

	var reported []string
	db.SetDecodeFailureHook(func(bucket, key string) {
		reported = append(reported, bucket+"/"+key)
	})

	good := &Token{TokenID: uuid.New().String(), AccountID: "acc", Name: "bueno"}
	if err := db.CreateToken(good); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	corruptRecord(t, db, bucketTokens, "token-podrido")

	tokens, err := db.ListTokens("")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].TokenID != good.TokenID {
		t.Fatalf("quiero solo el token sano, tengo %+v", tokens)
	}
	if len(reported) != 1 || reported[0] != "tokens/token-podrido" {
		t.Fatalf("el registro corrupto tiene que reportarse; reportados: %v", reported)
	}
}

// TestGetRecord_CorruptRecordIsAnError comprueba la otra mitad: pedir *ese*
// registro en concreto no puede devolver un cero silencioso, tiene que fallar.
func TestGetRecord_CorruptRecordIsAnError(t *testing.T) {
	db := openExtraTestDB(t)
	corruptRecord(t, db, bucketAccounts, "cuenta-podrida")

	if _, err := db.GetAccount("cuenta-podrida"); err == nil {
		t.Fatal("GetAccount sobre un registro ilegible tiene que devolver error")
	}
}

// TestUpdateRecord_MutateErrorRollsBack: si el mutate aborta, la transacción
// se revierte y el registro queda como estaba.
func TestUpdateRecord_MutateErrorRollsBack(t *testing.T) {
	db := openExtraTestDB(t)
	acc := &Account{AccountID: uuid.New().String(), Name: "original"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	boom := errAbortForTest
	err := db.updateRecord(bucketAccounts, acc.AccountID, ErrAccountNotFound, func(a *Account) error {
		a.Name = "pisado"
		return boom
	})
	if err != boom {
		t.Fatalf("quiero el error del mutate, tengo %v", err)
	}

	got, err := db.GetAccount(acc.AccountID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got.Name != "original" {
		t.Fatalf("la transacción no se revirtió: Name=%q", got.Name)
	}
}

// TestGetRecord_MissingBucketIsNotFound: un handle de DB sin el bbolt bucket
// (fixture armado a mano) devuelve el error de "no encontrado", no un panic
// por nil-deref como pasaba antes del refactor.
func TestGetRecord_MissingBucketIsNotFound(t *testing.T) {
	db := openExtraTestDB(t)
	if _, err := db.getRecord[Token]([]byte("bucket-que-no-existe"), "x", ErrTokenNotFound); err != ErrTokenNotFound {
		t.Fatalf("quiero ErrTokenNotFound, tengo %v", err)
	}
}
