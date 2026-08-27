package jsonx_test

import (
	"bytes"
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"testing"
	"time"

	"github.com/ivangsm/jay/internal/jsonx"
)

// TestWireMatchesV1 es la guarda del helper compartido. jsonx.Wire está copiado
// VERBATIM en los cinco repos del monorepo y su único trabajo es emitir los
// mismos bytes que emitía encoding/json v1; si una de sus cinco opciones se
// cae, todo lo que jay tiene persistido en bbolt cambia de formato.
//
// El corpus de meta/ prueba Wire contra los tipos reales, pero no puede cubrir
// las opciones que ningún tipo de jay ejercita hoy (por ejemplo un mapa nil sin
// `omitempty`). Este test cubre las cinco de frente, con tipos sintéticos, para
// que la copia del helper esté protegida aunque los tipos de jay cambien.
func TestWireMatchesV1(t *testing.T) {
	type todo struct {
		SliceNil   []string          `json:"slice_nil"`
		SliceVacio []string          `json:"slice_vacio"`
		MapaNil    map[string]int    `json:"mapa_nil"`
		MapaVacio  map[string]int    `json:"mapa_vacio"`
		MapaVarios map[string]string `json:"mapa_varios"`
		HTML       string            `json:"html"`
		JS         string            `json:"js"`
		NoASCII    string            `json:"no_ascii"`
		Vacio      string            `json:"vacio"`
		Numero     float64           `json:"numero"`
		Bandera    bool              `json:"bandera"`
		Momento    time.Time         `json:"momento"`
		Puntero    *string           `json:"puntero"`
		Anidado    struct {
			A []int `json:"a"`
		} `json:"anidado"`
	}

	text := "valor"
	cases := []todo{
		{}, // valor cero: cubre FormatNilSliceAsNull y FormatNilMapAsNull
		{
			SliceNil:   nil,
			SliceVacio: []string{},
			MapaNil:    nil,
			MapaVacio:  map[string]int{},
			// Varias llaves: cubre Deterministic (v1 ordena las llaves de mapa).
			MapaVarios: map[string]string{
				"z": "1", "a": "2", "m": "3", "B": "4", "ñ": "5", "0": "6", "&": "7",
			},
			HTML:    `a & b < c > d`, // cubre EscapeForHTML
			JS:      "línea y otra",  // cubre EscapeForJS
			NoASCII: "ñandú 漢字 🐦",
			Vacio:   "",
			Numero:  -0.5,
			Bandera: true,
			Momento: time.Date(2026, 8, 21, 15, 4, 5, 123456789, time.UTC),
			Puntero: &text,
		},
	}

	for i, c := range cases {
		v1b, err := jsonv1.Marshal(c)
		if err != nil {
			t.Fatalf("caso %d: v1 Marshal: %v", i, err)
		}
		v2b, err := jsonv2.Marshal(c, jsonx.Wire)
		if err != nil {
			t.Fatalf("caso %d: v2 Marshal con Wire: %v", i, err)
		}
		if !bytes.Equal(v1b, v2b) {
			t.Fatalf("caso %d: jsonx.Wire dejó de ser compatible con encoding/json v1\n v1: %s\n v2: %s", i, v1b, v2b)
		}
	}
}

// TestStrictRejectsUnknownFields fija lo que Strict promete: en los bodies
// de nuestras propias APIs un campo que no reconocemos es un bug del cliente,
// no algo para ignorar en silencio.
func TestStrictRejectsUnknownFields(t *testing.T) {
	type req struct {
		Nombre string `json:"nombre"`
	}

	var r req
	if err := jsonv2.Unmarshal([]byte(`{"nombre":"ok"}`), &r, jsonx.Strict); err != nil {
		t.Fatalf("Strict rechazó un body válido: %v", err)
	}
	if r.Nombre != "ok" {
		t.Fatalf("Strict no pobló el campo: %+v", r)
	}
	if err := jsonv2.Unmarshal([]byte(`{"nombre":"ok","nomrbe":"typo"}`), &r, jsonx.Strict); err == nil {
		t.Fatal("Strict tiene que rechazar un campo desconocido (acá, un nombre mal escrito)")
	}
}

// TestLenientAceptaLoQueV1AceptabaSinChistar fija por qué las políticas de
// bucket se leen con Lenient y no con los defaults de v2: v1 hacía matching de
// nombres CASE-INSENSITIVE. Con los defaults de v2 una política escrita al
// estilo AWS ("Effect") dejaría de parsearse y su Deny desaparecería en
// silencio — que en jay significa dar acceso donde antes se negaba.
func TestLenientAcceptsWhatV1AcceptedSilently(t *testing.T) {
	type statement struct {
		Effect string `json:"effect"`
	}
	type policy struct {
		Statements []statement `json:"statements"`
	}

	estiloAWS := []byte(`{"Statements":[{"Effect":"deny"}]}`)

	var v1p policy
	if err := jsonv1.Unmarshal(estiloAWS, &v1p); err != nil {
		t.Fatalf("v1 Unmarshal: %v", err)
	}
	if len(v1p.Statements) != 1 || v1p.Statements[0].Effect != "deny" {
		t.Fatalf("premisa rota: v1 ya no hace matching case-insensitive: %+v", v1p)
	}

	// Defaults de v2: case-sensitive, el Deny se pierde.
	var estricto policy
	if err := jsonv2.Unmarshal(estiloAWS, &estricto); err != nil {
		t.Fatalf("v2 Unmarshal: %v", err)
	}
	if len(estricto.Statements) != 0 {
		t.Fatalf("premisa rota: los defaults de v2 ya no son case-sensitive: %+v", estricto)
	}

	// Lenient recupera el comportamiento de v1.
	var lenient policy
	if err := jsonv2.Unmarshal(estiloAWS, &lenient, jsonx.Lenient); err != nil {
		t.Fatalf("Lenient Unmarshal: %v", err)
	}
	if len(lenient.Statements) != 1 || lenient.Statements[0].Effect != "deny" {
		t.Fatalf("Lenient perdió el statement Deny: %+v", lenient)
	}

	// Y tolera llaves duplicadas y UTF-8 inválido, que v1 también aceptaba.
	var dup policy
	if err := jsonv2.Unmarshal([]byte(`{"statements":[],"statements":[{"effect":"deny"}]}`), &dup, jsonx.Lenient); err != nil {
		t.Fatalf("Lenient rechazó llaves duplicadas: %v", err)
	}
	var mojibake struct {
		S string `json:"s"`
	}
	if err := jsonv2.Unmarshal([]byte("{\"s\":\"\xff\xfe\"}"), &mojibake, jsonx.Lenient); err != nil {
		t.Fatalf("Lenient rechazó UTF-8 inválido: %v", err)
	}
}
