package jsonx

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// Wire produce bytes idénticos a los que emitía encoding/json v1.
// Úsalo para todo lo que se persiste o se publica: payloads NATS, filas de
// outbox, registros en disco. Cambiar estos bytes es un cambio de formato de
// datos, no de estilo.
var Wire = jsonv2.JoinOptions(
	jsonv2.FormatNilSliceAsNull(true),
	jsonv2.FormatNilMapAsNull(true),
	jsonv2.Deterministic(true),
	jsontext.EscapeForHTML(true),
	jsontext.EscapeForJS(true),
)

// Lenient acepta el JSON que los humanos y los terceros realmente escriben:
// mojibake, llaves duplicadas y mayúsculas que no coinciden con el tag. v2 es
// case-sensitive y v1 no lo era, así que TODO struct que venga de JSON escrito
// por alguien más necesita esto — no sólo las APIs externas. Un decode que
// falla en silencio sobre una policy es una falla abierta.
var Lenient = jsonv2.JoinOptions(
	jsontext.AllowInvalidUTF8(true),
	jsontext.AllowDuplicateNames(true),
	jsonv2.MatchCaseInsensitiveNames(true),
)

// Strict son los defaults de v2 más rechazo de campos desconocidos, para los
// bodies de nuestras propias APIs, donde un campo que no reconocemos es un bug
// del cliente.
var Strict = jsonv2.RejectUnknownMembers(true)
