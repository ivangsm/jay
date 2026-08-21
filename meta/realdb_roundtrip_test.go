package meta

import (
	"bytes"
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ivangsm/jay/internal/jsonx"
)

// realDBFixture es la ruta a un jay.db ESCRITO POR LA VERSIÓN ANTERIOR (la que
// usaba encoding/json v1). Se puede sobreescribir con JAY_TEST_REAL_DB para
// apuntar a un jay.db de producción.
//
// Cómo se regenera (ver el reporte de la migración a Go 1.27):
//
//	git archive HEAD~1 | tar -x -C /tmp/old && (cd /tmp/old && go build -o /tmp/jay-old .)
//	JAY_DATA_DIR=/tmp/rt ... /tmp/jay-old        # sembrar cuentas/tokens/buckets/multipart
//	cp /tmp/rt/meta/jay.db testdata/jay.db.v1
const realDBFixture = "testdata/jay.db.v1"

// TestRealDB_RoundTripByteIdentical es la verificación que los fixtures
// sintéticos NO pueden dar: agarra un jay.db de verdad, escrito por el binario
// anterior con encoding/json v1, lo lee con el código nuevo (json/v2 +
// jsonx.Wire), lo vuelve a serializar y exige que los bytes sean IDÉNTICOS.
//
// Para jay esto no es cosmético: JSON es su formato en disco. Si los bytes
// cambiaran, un rollback al binario anterior encontraría registros que ya no
// entiende, y el scrubber reescribiría toda la base sin necesidad.
func TestRealDB_RoundTripByteIdentical(t *testing.T) {
	path := os.Getenv("JAY_TEST_REAL_DB")
	if path == "" {
		path = realDBFixture
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no hay jay.db de referencia en %s (%v); ver el comentario de realDBFixture", path, err)
	}

	// Se trabaja sobre una copia: bbolt toma un lock exclusivo y el fixture es
	// un archivo versionado.
	work := filepath.Join(t.TempDir(), "jay.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("leer fixture: %v", err)
	}
	if err := os.WriteFile(work, raw, 0o600); err != nil {
		t.Fatalf("copiar fixture: %v", err)
	}

	db, err := Open(work)
	if err != nil {
		t.Fatalf("abrir el jay.db real: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetSigningSecret("secreto-de-firma-de-prueba-32-chars")

	// checkBucket lee cada registro crudo del bbolt bucket, lo deserializa con
	// el código nuevo, lo vuelve a serializar y compara byte a byte.
	checkBucket := func(t *testing.T, name []byte, decode func([]byte) (any, error)) int {
		t.Helper()
		seen := 0
		err := db.bolt.View(func(tx *bolt.Tx) error {
			bk := tx.Bucket(name)
			if bk == nil {
				return nil
			}
			return bk.ForEach(func(k, v []byte) error {
				seen++
				rec, err := decode(v)
				if err != nil {
					t.Errorf("%s/%s: el código nuevo no pudo leer un registro escrito por v1: %v",
						name, k, err)
					return nil
				}
				again, err := jsonv2.Marshal(rec, jsonx.Wire)
				if err != nil {
					t.Errorf("%s/%s: reserializar: %v", name, k, err)
					return nil
				}
				if !bytes.Equal(v, again) {
					t.Errorf("%s/%s: los bytes cambiaron — ESTO ES UN CAMBIO DE FORMATO EN DISCO\n en disco (v1): %s\n reescrito (v2): %s",
						name, k, v, again)
				}
				return nil
			})
		})
		if err != nil {
			t.Fatalf("recorrer %s: %v", name, err)
		}
		return seen
	}

	t.Run("accounts", func(t *testing.T) {
		n := checkBucket(t, bucketAccounts, func(b []byte) (any, error) {
			var a Account
			return &a, jsonv2.Unmarshal(b, &a, jsonx.Wire)
		})
		if n == 0 {
			t.Fatal("el fixture no tiene cuentas: no está verificando nada")
		}
		t.Logf("%d cuentas verificadas", n)
	})

	t.Run("tokens", func(t *testing.T) {
		n := checkBucket(t, bucketTokens, func(b []byte) (any, error) {
			var tk Token
			return &tk, jsonv2.Unmarshal(b, &tk, jsonx.Wire)
		})
		if n == 0 {
			t.Fatal("el fixture no tiene tokens: no está verificando nada")
		}
		t.Logf("%d tokens verificados", n)
	})

	t.Run("buckets", func(t *testing.T) {
		n := checkBucket(t, bucketBuckets, func(b []byte) (any, error) {
			var bk Bucket
			return &bk, jsonv2.Unmarshal(b, &bk, jsonx.Wire)
		})
		if n == 0 {
			t.Fatal("el fixture no tiene buckets: no está verificando nada")
		}
		t.Logf("%d buckets verificados", n)
	})

	t.Run("multipart", func(t *testing.T) {
		n := checkBucket(t, bucketMultipart, func(b []byte) (any, error) {
			var u MultipartUpload
			return &u, jsonv2.Unmarshal(b, &u, jsonx.Wire)
		})
		if n == 0 {
			t.Fatal("el fixture no tiene multipart uploads: no está verificando nada")
		}
		t.Logf("%d multipart uploads verificados", n)
	})

	// Y por la API pública: leer, reescribir y volver a leer tiene que dar lo
	// mismo, con el secreto de token descifrándose igual que antes.
	t.Run("lectura-reescritura-lectura", func(t *testing.T) {
		tokens, err := db.ListTokens("")
		if err != nil {
			t.Fatalf("ListTokens: %v", err)
		}
		if len(tokens) == 0 {
			t.Fatal("el fixture no tiene tokens")
		}
		for _, tk := range tokens {
			full, err := db.GetToken(tk.TokenID)
			if err != nil {
				t.Fatalf("GetToken(%s): %v", tk.TokenID, err)
			}
			if full.SecretKey == "" {
				t.Fatalf("token %s: el secreto cifrado por v1 no se descifró", tk.TokenID)
			}
			// Reescribir con el código nuevo y releer.
			if err := db.RevokeToken(tk.TokenID); err != nil {
				t.Fatalf("RevokeToken(%s): %v", tk.TokenID, err)
			}
			again, err := db.GetToken(tk.TokenID)
			if err != nil {
				t.Fatalf("GetToken tras reescribir: %v", err)
			}
			if again.SecretKey != full.SecretKey || again.AccountID != full.AccountID ||
				again.Name != full.Name || !again.CreatedAt.Equal(full.CreatedAt) {
				t.Fatalf("token %s cambió al reescribirse:\n antes: %+v\n ahora: %+v", tk.TokenID, full, again)
			}
			if again.Status != "revoked" {
				t.Fatalf("token %s: la reescritura no aplicó", tk.TokenID)
			}
		}
	})
}

// TestRealDB_LegacyJSONObjectBranch cubre la rama '{' de meta/codec.go, que es
// la única parte del formato en disco que el fixture NO trae: los registros de
// Object de hoy usan el envelope binario (gob), y el JSON pelado solo aparece
// en bases anteriores al codec.
//
// El test inyecta un registro legacy REAL —los bytes exactos que producía
// encoding/json v1— en el bbolt bucket de objetos del jay.db de referencia, y
// exige que el código nuevo lo lea y lo reproduzca idéntico.
func TestRealDB_LegacyJSONObjectBranch(t *testing.T) {
	path := os.Getenv("JAY_TEST_REAL_DB")
	if path == "" {
		path = realDBFixture
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no hay jay.db de referencia en %s (%v)", path, err)
	}

	work := filepath.Join(t.TempDir(), "jay.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("leer fixture: %v", err)
	}
	if err := os.WriteFile(work, raw, 0o600); err != nil {
		t.Fatalf("copiar fixture: %v", err)
	}

	db, err := Open(work)
	if err != nil {
		t.Fatalf("abrir el jay.db real: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	buckets, err := db.ListBuckets("")
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) == 0 {
		t.Fatal("el fixture no tiene buckets")
	}
	bucketID := buckets[0].ID

	legacyObj := &Object{
		BucketID: bucketID, Key: "legacy/ñandú &<>.bin", ObjectID: "obj-legacy-1",
		State: "active", SizeBytes: 4321, ContentType: "image/png",
		ETag: `"abc123"`, ChecksumSHA256: "cafebabe", LocationRef: "ab/cd/obj-legacy-1",
		CreatedAt: time.Date(2024, 3, 4, 5, 6, 7, 89000000, time.UTC),
		UpdatedAt: time.Date(2024, 3, 4, 5, 6, 8, 0, time.UTC),
		MetadataHeaders: map[string]string{
			"x-amz-meta-autor": "ñandú", "x-amz-meta-nota": "a&b <c>",
		},
	}

	// Bytes EXACTOS del formato legacy: json.Marshal de v1, sin envelope.
	legacyBytes, err := jsonv1.Marshal(legacyObj)
	if err != nil {
		t.Fatalf("v1 Marshal: %v", err)
	}
	if legacyBytes[0] != '{' {
		t.Fatalf("el registro legacy debe empezar con '{', empieza con 0x%02x", legacyBytes[0])
	}

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(objectsBucketName(bucketID)).Put([]byte(legacyObj.Key), legacyBytes)
	}); err != nil {
		t.Fatalf("inyectar registro legacy: %v", err)
	}

	// El código nuevo lo lee por la rama '{' de decodeObject.
	got, err := db.GetObjectMeta(bucketID, legacyObj.Key)
	if err != nil {
		t.Fatalf("GetObjectMeta sobre registro legacy: %v", err)
	}
	if got.ObjectID != legacyObj.ObjectID || got.SizeBytes != legacyObj.SizeBytes ||
		got.ETag != legacyObj.ETag || !got.CreatedAt.Equal(legacyObj.CreatedAt) ||
		got.MetadataHeaders["x-amz-meta-autor"] != "ñandú" {
		t.Fatalf("el registro legacy se leyó mal: %+v", got)
	}

	// Y reserializarlo con json/v2 + Wire da los mismos bytes que había en
	// disco: la rama legacy sigue siendo estable, no solo legible.
	reencoded, err := jsonv2.Marshal(got, jsonx.Wire)
	if err != nil {
		t.Fatalf("reserializar: %v", err)
	}
	if !bytes.Equal(legacyBytes, reencoded) {
		t.Fatalf("la rama legacy JSON cambió de bytes\n en disco: %s\n reescrito: %s", legacyBytes, reencoded)
	}
}
