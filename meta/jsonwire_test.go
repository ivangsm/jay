package meta

import (
	"bytes"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/ivangsm/jay/internal/jsonx"
)

// TestJSONWireCompatV1V2 es la red de seguridad del cambio de encoding/json v1
// a encoding/json/v2: para jay, JSON *es* el formato en disco (registros bbolt
// de cuentas, tokens, buckets y multipart, más los registros de objeto con el
// envelope legacy). Si v2 + jsonx.Wire emitiera un solo byte distinto al de v1,
// un jay.db escrito con la versión nueva dejaría de ser legible por la vieja y
// al revés.
//
// Por eso este test importa encoding/json v1 a propósito y lo deja importado:
// es la única referencia confiable de "cómo se veían los bytes antes".
//
// El corpus cubre, por cada tipo persistido: valor cero, slice nil y slice
// vacío, mapa nil y mapa vacío, string vacío, no-ASCII, los caracteres que v1
// escapa por omisión (`&`, `<`, `>`, U+2028/U+2029) y campos time.Time.
func TestJSONWireCompatV1V2(t *testing.T) {
	ts := time.Date(2026, 8, 21, 15, 4, 5, 123456789, time.UTC)
	tsLocal := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("MX", -6*3600))
	expires := ts.Add(48 * time.Hour)

	// Cadena con todo lo que v1 escapa: HTML, JS line separators y no-ASCII.
	nasty := "a&b <tag> \"quoted\"    ñandú 漢字 \\ / \b\f\n\r\t"

	cases := []struct {
		name string
		val  any
	}{
		{"Account/cero", &Account{}},
		{"Account/lleno", &Account{AccountID: "acc-1", Name: nasty, CreatedAt: ts, Status: "active"}},
		{"Account/fecha-con-zona", &Account{AccountID: "acc-2", Name: "", CreatedAt: tsLocal, Status: "suspended"}},

		{"Bucket/cero", &Bucket{}},
		{"Bucket/policy-nil", &Bucket{ID: "b1", Name: "fotos", OwnerAccountID: "acc-1", CreatedAt: ts, Visibility: "private", Status: "active"}},
		{"Bucket/policy-objeto", &Bucket{ID: "b3", Name: nasty, PolicyJSON: jsontext.Value(`{"Statement":[{"Effect":"Allow","Action":"*"}]}`), CreatedAt: ts, Status: "active"}},
		{"Bucket/policy-null", &Bucket{ID: "b4", Name: "y", PolicyJSON: jsontext.Value(`null`), CreatedAt: ts}},

		{"Object/cero", &Object{}},
		{"Object/headers-nil", &Object{BucketID: "b1", Key: "a/b.png", ObjectID: "o1", State: "active", SizeBytes: 0, CreatedAt: ts, UpdatedAt: ts}},
		{"Object/headers-vacios", &Object{BucketID: "b1", Key: "k", ObjectID: "o2", State: "active", MetadataHeaders: map[string]string{}, CreatedAt: ts, UpdatedAt: ts}},
		{"Object/headers-multi", &Object{
			BucketID: "b1", Key: nasty, ObjectID: "o3", State: "quarantined",
			SizeBytes: -1, ContentType: "image/webp", ETag: `"abc"`, ChecksumSHA256: "deadbeef",
			LocationRef: "ab/cd/o3", CreatedAt: ts, UpdatedAt: tsLocal,
			// Varias llaves fuerzan el orden determinístico de mapas.
			MetadataHeaders: map[string]string{"z": "1", "a": nasty, "m": "", "Ñ": "ü", "&<>": "v"},
		}},

		{"Token/cero", &Token{}},
		{"Token/acciones-nil", &Token{TokenID: "t1", AccountID: "acc-1", Name: "seed", SecretHash: "$2a$…", CreatedAt: ts, Status: "active"}},
		{"Token/acciones-vacias", &Token{TokenID: "t2", AllowedActions: []string{}, BucketScope: []string{}, PrefixScope: []string{}, CreatedAt: ts}},
		{"Token/lleno", &Token{
			TokenID: "t3", AccountID: "acc-1", Name: nasty,
			SecretHash: "hash", SecretKey: "enc:v1:AAAA",
			AllowedActions: AllActions, BucketScope: []string{"fotos", nasty}, PrefixScope: []string{"a/", ""},
			CreatedAt: ts, ExpiresAt: &expires, Status: "revoked",
		}},

		{"MultipartUpload/cero", &MultipartUpload{}},
		{"MultipartUpload/parts-nil", &MultipartUpload{UploadID: "u1", BucketID: "b1", ObjectKey: "k", InitiatedBy: "t1", CreatedAt: ts, State: "initiated"}},
		{"MultipartUpload/parts-vacias", &MultipartUpload{UploadID: "u2", BucketID: "b1", ObjectKey: "k", Parts: []MultipartPart{}, CreatedAt: ts, State: "aborted"}},
		{"MultipartUpload/parts-llenas", &MultipartUpload{
			UploadID: "u3", BucketID: "b1", ObjectKey: nasty, ContentType: "application/octet-stream",
			InitiatedBy: "t1", CreatedAt: ts, State: "completed",
			Parts: []MultipartPart{
				{},
				{PartNumber: 1, Size: 0, ETag: `"e1"`, ChecksumSHA256: "", LocationRef: "", CreatedAt: ts},
				{PartNumber: 2, Size: 5 << 30, ETag: nasty, ChecksumSHA256: "cafe", LocationRef: "p/2", CreatedAt: tsLocal},
			},
		}},

		{"MultipartPart/cero", &MultipartPart{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v1b, err1 := jsonv1.Marshal(tc.val)
			if err1 != nil {
				t.Fatalf("encoding/json v1 Marshal: %v", err1)
			}
			v2b, err2 := jsonv2.Marshal(tc.val, jsonx.Wire)
			if err2 != nil {
				t.Fatalf("encoding/json/v2 Marshal con jsonx.Wire: %v", err2)
			}
			if !bytes.Equal(v1b, v2b) {
				t.Fatalf("los bytes de v2 no coinciden con los de v1 — esto es un cambio de formato en disco\n v1: %s\n v2: %s", v1b, v2b)
			}
		})
	}
}

// TestJSONWireRoundTripV1V2 comprueba la otra dirección: lo que escribió v1 lo
// tiene que poder leer v2 y viceversa, incluido el envelope legacy JSON de
// meta/codec.go (registros de Object escritos antes del codec binario).
// TestBucketPolicyEmptyIsRejected fija el único estado de PolicyJSON donde v1
// y v2 discrepaban: un jsontext.Value vacío-pero-no-nil no es JSON válido.
// Con `omitzero` los dos codificadores lo rechazan igual (con omitempty, v1 lo
// omitía en silencio y v2 reventaba a mitad del documento), y UpdateBucketPolicy
// lo corta antes de abrir la transacción para que el error sea atribuible.
func TestBucketPolicyEmptyIsRejected(t *testing.T) {
	empty := jsontext.Value{}

	if _, err := jsonv1.Marshal(&Bucket{ID: "b", PolicyJSON: empty}); err == nil {
		t.Fatal("encoding/json v1 debería rechazar un policy_json vacío-no-nil")
	}
	if _, err := jsonv2.Marshal(&Bucket{ID: "b", PolicyJSON: empty}, jsonx.Wire); err == nil {
		t.Fatal("encoding/json/v2 debería rechazar un policy_json vacío-no-nil")
	}

	db := openExtraTestDB(t)
	b := &Bucket{ID: uuid.New().String(), Name: "policy-vacia", OwnerAccountID: "acc"}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := db.UpdateBucketPolicy(b.Name, empty); !errors.Is(err, ErrInvalidBucketPolicy) {
		t.Fatalf("UpdateBucketPolicy con policy vacío: quiero ErrInvalidBucketPolicy, tengo %v", err)
	}
	if err := db.UpdateBucketPolicy(b.Name, jsontext.Value(`{"Statement":`)); !errors.Is(err, ErrInvalidBucketPolicy) {
		t.Fatalf("UpdateBucketPolicy con JSON truncado: quiero ErrInvalidBucketPolicy, tengo %v", err)
	}
	// nil y un objeto válido sí pasan.
	if err := db.UpdateBucketPolicy(b.Name, nil); err != nil {
		t.Fatalf("UpdateBucketPolicy(nil): %v", err)
	}
	if err := db.UpdateBucketPolicy(b.Name, jsontext.Value(`{"statements":[]}`)); err != nil {
		t.Fatalf("UpdateBucketPolicy(válido): %v", err)
	}
}

func TestJSONWireRoundTripV1V2(t *testing.T) {
	ts := time.Date(2026, 8, 21, 15, 4, 5, 123456789, time.UTC)
	obj := &Object{
		BucketID: "b1", Key: "ñ/&<>.png", ObjectID: "o1", State: "active",
		SizeBytes: 1234, ContentType: "image/png", ETag: `"e"`, ChecksumSHA256: "abc",
		LocationRef: "ab/cd/o1", CreatedAt: ts, UpdatedAt: ts,
		MetadataHeaders: map[string]string{"x-amz-meta-a": "1", "x-amz-meta-b": "ü"},
	}

	// El registro legacy en disco es exactamente json.Marshal(*Object) de v1.
	legacy, err := jsonv1.Marshal(obj)
	if err != nil {
		t.Fatalf("v1 Marshal: %v", err)
	}
	if legacy[0] != '{' {
		t.Fatalf("el registro legacy debe empezar con '{', empieza con 0x%02x", legacy[0])
	}

	// decodeObject toma la rama '{' de meta/codec.go, que ahora usa v2.
	var viaCodec Object
	if err := decodeObject(legacy, &viaCodec); err != nil {
		t.Fatalf("decodeObject sobre registro legacy: %v", err)
	}

	// Y lo reserializado tiene que ser byte a byte el mismo registro legacy.
	reencoded, err := jsonv2.Marshal(&viaCodec, jsonx.Wire)
	if err != nil {
		t.Fatalf("v2 Marshal: %v", err)
	}
	if !bytes.Equal(legacy, reencoded) {
		t.Fatalf("round-trip legacy JSON no es estable\n antes: %s\n ahora: %s", legacy, reencoded)
	}

	// Y v1 tiene que poder leer lo que escribe v2.
	var viaV1 Object
	if err := jsonv1.Unmarshal(reencoded, &viaV1); err != nil {
		t.Fatalf("v1 Unmarshal de bytes escritos por v2: %v", err)
	}
	if !viaV1.CreatedAt.Equal(obj.CreatedAt) || viaV1.Key != obj.Key || viaV1.SizeBytes != obj.SizeBytes {
		t.Fatalf("round-trip v2→v1 perdió datos: %+v", viaV1)
	}
}
