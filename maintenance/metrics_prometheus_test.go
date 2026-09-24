package maintenance

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// The exposition is checked by parsing it back with a parser written from the
// format's description, independently of the writer. Asserting against the
// writer's own strings would only prove it agrees with itself.

type parsedSample struct {
	labels map[string]string
	value  float64
}

type parsedFamily struct {
	help    string
	typ     string
	samples []parsedSample
}

// parseExposition parses text in the Prometheus text format, version 0.0.4,
// failing the test on anything a scraper would reject or misread: a sample
// before its TYPE, a HELP or TYPE declared twice, a sample whose name is not
// its family's, a repeated series, a malformed label set or value.
func parseExposition(t *testing.T, text string) map[string]*parsedFamily {
	t.Helper()
	if text != "" && !strings.HasSuffix(text, "\n") {
		t.Fatalf("exposition does not end in a line feed: %q", text)
	}
	families := map[string]*parsedFamily{}
	seenSeries := map[string]bool{}
	family := func(name string) *parsedFamily {
		if families[name] == nil {
			families[name] = &parsedFamily{}
		}
		return families[name]
	}

	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name, help, ok := strings.Cut(strings.TrimPrefix(line, "# HELP "), " ")
			if !ok {
				t.Fatalf("line %d: HELP without text: %q", i+1, line)
			}
			f := family(name)
			if f.help != "" {
				t.Fatalf("line %d: second HELP for %s", i+1, name)
			}
			f.help = unescapeHelp(t, help)
		case strings.HasPrefix(line, "# TYPE "):
			name, typ, ok := strings.Cut(strings.TrimPrefix(line, "# TYPE "), " ")
			if !ok {
				t.Fatalf("line %d: TYPE without a type: %q", i+1, line)
			}
			f := family(name)
			if f.typ != "" {
				t.Fatalf("line %d: second TYPE for %s", i+1, name)
			}
			if len(f.samples) > 0 {
				t.Fatalf("line %d: TYPE for %s after its samples", i+1, name)
			}
			f.typ = typ
		case strings.HasPrefix(line, "#"), line == "":
			t.Fatalf("line %d: unexpected line %q", i+1, line)
		default:
			name, labels, value := parseSampleLine(t, i+1, line)
			f := families[name]
			if f == nil || f.typ == "" {
				t.Fatalf("line %d: sample of %s before its TYPE", i+1, name)
			}
			key := name + "{" + canonicalLabels(labels) + "}"
			if seenSeries[key] {
				t.Fatalf("line %d: series %s appears twice", i+1, key)
			}
			seenSeries[key] = true
			f.samples = append(f.samples, parsedSample{labels: labels, value: value})
		}
	}
	for name, f := range families {
		if f.help == "" || f.typ == "" || len(f.samples) == 0 {
			t.Fatalf("family %s is incomplete: help %q, type %q, %d samples", name, f.help, f.typ, len(f.samples))
		}
	}
	return families
}

// parseSampleLine splits `name{a="x",b="y"} value` into its parts.
func parseSampleLine(t *testing.T, n int, line string) (string, map[string]string, float64) {
	t.Helper()
	labels := map[string]string{}
	nameEnd := strings.IndexAny(line, "{ ")
	if nameEnd <= 0 {
		t.Fatalf("line %d: no metric name: %q", n, line)
	}
	name, rest := line[:nameEnd], line[nameEnd:]

	if strings.HasPrefix(rest, "{") {
		rest = rest[1:]
		for !strings.HasPrefix(rest, "}") {
			eq := strings.Index(rest, `="`)
			if eq <= 0 {
				t.Fatalf("line %d: malformed label set: %q", n, line)
			}
			label := rest[:eq]
			rest = rest[eq+2:]
			var value strings.Builder
			closed := false
			for i := 0; i < len(rest); i++ {
				c := rest[i]
				if c == '\\' && i+1 < len(rest) {
					switch rest[i+1] {
					case '\\':
						value.WriteByte('\\')
					case '"':
						value.WriteByte('"')
					case 'n':
						value.WriteByte('\n')
					default:
						t.Fatalf("line %d: unknown escape \\%c", n, rest[i+1])
					}
					i++
					continue
				}
				if c == '"' {
					rest = rest[i+1:]
					closed = true
					break
				}
				if c == '\n' {
					t.Fatalf("line %d: raw line feed in a label value", n)
				}
				value.WriteByte(c)
			}
			if !closed {
				t.Fatalf("line %d: unterminated label value: %q", n, line)
			}
			if _, dup := labels[label]; dup {
				t.Fatalf("line %d: label %s twice", n, label)
			}
			labels[label] = value.String()
			rest = strings.TrimPrefix(rest, ",")
		}
		rest = rest[1:]
	}

	if !strings.HasPrefix(rest, " ") {
		t.Fatalf("line %d: no space before the value: %q", n, line)
	}
	raw := rest[1:]
	var v float64
	switch raw {
	case "+Inf":
		v = math.Inf(1)
	case "-Inf":
		v = math.Inf(-1)
	case "NaN":
		v = math.NaN()
	default:
		var err error
		if v, err = strconv.ParseFloat(raw, 64); err != nil {
			t.Fatalf("line %d: value %q: %v", n, raw, err)
		}
	}
	return name, labels, v
}

func unescapeHelp(t *testing.T, s string) string {
	t.Helper()
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			t.Fatalf("help ends in a lone backslash: %q", s)
		}
		switch s[i+1] {
		case '\\':
			out.WriteByte('\\')
		case 'n':
			out.WriteByte('\n')
		default:
			t.Fatalf("unknown escape in help: \\%c", s[i+1])
		}
		i++
	}
	return out.String()
}

func canonicalLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + strconv.Quote(labels[k]) + ",")
	}
	return b.String()
}

func render(t *testing.T, families []MetricFamily) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WritePrometheus(&buf, families); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.String()
}

// counterFields returns every atomic counter of Metrics, found by reflection,
// so the test below needs no list of names that could fall out of date with
// the struct.
func counterFields(m *Metrics) map[string]*atomic.Int64 {
	out := map[string]*atomic.Int64{}
	v := reflect.ValueOf(m).Elem()
	for i := range v.NumField() {
		field := v.Type().Field(i)
		if field.Type != reflect.TypeFor[atomic.Int64]() {
			continue
		}
		out[field.Name] = v.Field(i).Addr().Interface().(*atomic.Int64)
	}
	return out
}

// Every counter of Metrics reaches the exposition exactly once, as a counter.
// Each field gets a value no other field has, so finding that value tells
// which sample carries it — without the test knowing any metric's name. A
// counter added to Metrics and forgotten in PrometheusFamilies (or wired to
// the wrong field, or wired twice) fails here.
func TestPrometheusFamilies_ExposeEveryCounterOnce(t *testing.T) {
	m := NewMetrics()
	fields := counterFields(m)
	if len(fields) < 10 {
		t.Fatalf("found only %d counters by reflection; the test has lost sight of the struct", len(fields))
	}
	valueOf := map[float64]string{}
	i := 0
	for name, counter := range fields {
		i++
		v := int64(1_000_003 * i)
		counter.Store(v)
		valueOf[float64(v)] = name
	}

	families := parseExposition(t, render(t, m.Snapshot().PrometheusFamilies()))

	found := map[string]int{}
	counterSamples := 0
	for name, f := range families {
		if f.typ != string(CounterType) {
			continue
		}
		if !strings.HasPrefix(name, "jay_") || !strings.HasSuffix(name, "_total") {
			t.Errorf("counter %s does not follow jay_…_total", name)
		}
		for _, s := range f.samples {
			counterSamples++
			field, ok := valueOf[s.value]
			if !ok {
				t.Errorf("%s%v = %v comes from no counter of Metrics", name, s.labels, s.value)
				continue
			}
			found[field]++
		}
	}
	for field := range fields {
		if found[field] != 1 {
			t.Errorf("Metrics.%s appears %d times in the exposition, want exactly 1", field, found[field])
		}
	}
	if counterSamples != len(fields) {
		t.Errorf("%d counter samples for %d counters", counterSamples, len(fields))
	}
}

// The start time is a gauge holding the exact Unix time the process started,
// which is how Prometheus expects uptime: time() - jay_start_time_seconds.
func TestPrometheusFamilies_StartTimeIsTheProcessStart(t *testing.T) {
	m := NewMetrics()
	families := parseExposition(t, render(t, m.Snapshot().PrometheusFamilies()))
	f := families["jay_start_time_seconds"]
	if f == nil || f.typ != string(GaugeType) || len(f.samples) != 1 {
		t.Fatalf("jay_start_time_seconds = %+v, want one gauge sample", f)
	}
	want := float64(m.startedAt.UnixNano()) / 1e9
	if got := f.samples[0].value; math.Abs(got-want) > 1e-3 {
		t.Fatalf("start time = %v, want %v", got, want)
	}
}

// Moving a counter moves the exposed value; the rendering does not freeze a
// copy anywhere.
func TestPrometheusFamilies_FollowTheCounters(t *testing.T) {
	m := NewMetrics()
	value := func() float64 {
		t.Helper()
		for _, s := range parseExposition(t, render(t, m.Snapshot().PrometheusFamilies()))["jay_auth_failures_total"].samples {
			if s.labels["surface"] == "admin" {
				return s.value
			}
		}
		t.Fatal("no admin sample in jay_auth_failures_total")
		return 0
	}
	before := value()
	m.RecordAdminAuthFailure()
	m.RecordAdminAuthFailure()
	if got := value(); got != before+2 {
		t.Fatalf("admin auth failures exposed %v after two failures from %v", got, before)
	}
}

func TestWritePrometheus_EscapesLabelValuesAndHelp(t *testing.T) {
	const help = "a help with a \\ backslash\nand a second line"
	const tricky = "quote \" backslash \\ newline \n end"
	families := parseExposition(t, render(t, []MetricFamily{{
		Name: "jay_test_gauge", Help: help, Type: GaugeType,
		Samples: []Sample{
			{Labels: []Label{{Name: "value", Value: tricky}, {Name: "plain", Value: "x"}}, Value: 1.5},
			{Labels: []Label{{Name: "value", Value: ""}, {Name: "plain", Value: "y"}}, Value: -2},
		},
	}}))

	f := families["jay_test_gauge"]
	if f.help != help {
		t.Fatalf("help round-tripped as %q, want %q", f.help, help)
	}
	if got := f.samples[0].labels["value"]; got != tricky {
		t.Fatalf("label value round-tripped as %q, want %q", got, tricky)
	}
	if f.samples[0].value != 1.5 || f.samples[1].value != -2 || f.samples[1].labels["value"] != "" {
		t.Fatalf("samples = %+v", f.samples)
	}
}

// Integers print as integers — a counter reads as the count it is — and the
// special values use the spellings the format defines.
func TestWritePrometheus_Values(t *testing.T) {
	for _, c := range []struct {
		v    float64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{1 << 40, "1099511627776"},
		{0.25, "0.25"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
	} {
		out := render(t, []MetricFamily{Gauge("jay_value", "v", c.v)})
		if !strings.Contains(out, "\njay_value "+c.want+"\n") {
			t.Errorf("value %v rendered as:\n%s\nwant %q", c.v, out, c.want)
		}
	}
}

// A family the format would reject, or that Prometheus would misread, is an
// error — and nothing at all is written, so a handler can still answer 500
// instead of a 200 carrying half the metrics.
func TestWritePrometheus_RefusesBadFamiliesAndWritesNothing(t *testing.T) {
	good := Counter("jay_good_total", "ok", 1)
	for name, families := range map[string][]MetricFamily{
		"invalid metric name":     {good, Gauge("jay-dash", "h", 1)},
		"name starting in digit":  {Gauge("1jay", "h", 1)},
		"counter without _total":  {Counter("jay_requests", "h", 1)},
		"family declared twice":   {good, good},
		"unknown type":            {{Name: "jay_x", Help: "h", Type: "histogram", Samples: []Sample{{Value: 1}}}},
		"no samples":              {{Name: "jay_x", Help: "h", Type: GaugeType}},
		"repeated series":         {{Name: "jay_x", Help: "h", Type: GaugeType, Samples: []Sample{{Value: 1}, {Value: 2}}}},
		"invalid label name":      {{Name: "jay_x", Help: "h", Type: GaugeType, Samples: []Sample{{Labels: []Label{{Name: "a-b", Value: "v"}}, Value: 1}}}},
		"reserved label name":     {{Name: "jay_x", Help: "h", Type: GaugeType, Samples: []Sample{{Labels: []Label{{Name: "__name__", Value: "v"}}, Value: 1}}}},
		"colon in a label name":   {{Name: "jay_x", Help: "h", Type: GaugeType, Samples: []Sample{{Labels: []Label{{Name: "a:b", Value: "v"}}, Value: 1}}}},
		"repeated labelled value": {{Name: "jay_x", Help: "h", Type: GaugeType, Samples: []Sample{{Labels: []Label{{Name: "op", Value: "a"}}, Value: 1}, {Labels: []Label{{Name: "op", Value: "a"}}, Value: 2}}}},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WritePrometheus(&buf, families); err == nil {
				t.Fatalf("accepted:\n%s", buf.String())
			}
			if buf.Len() != 0 {
				t.Fatalf("wrote %d bytes before failing: %q", buf.Len(), buf.String())
			}
		})
	}

	t.Run("a colon is valid in a metric name", func(t *testing.T) {
		render(t, []MetricFamily{Gauge("jay:recorded", "h", 1)})
	})
}

// The JSON export of GET /_jay/metrics keeps its keys: jay-admin prints it
// and scripts read it. The Prometheus export added one counter to it and
// nothing else; the start time it needed stays out of the JSON.
func TestSnapshotJSON_KeepsItsKeys(t *testing.T) {
	raw, err := jsonv2.Marshal(NewMetrics().Snapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := jsonv2.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var keys []string
	for k := range doc {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{
		"admin_auth_failures", "auth_failures", "bytes_downloaded", "bytes_uploaded",
		"checksum_failures", "create_bucket_total", "delete_bucket_total", "delete_object_total",
		"fsync_failures", "get_object_total", "head_object_total", "list_objects_total",
		"metadata_decode_failures", "objects_quarantined", "panics_recovered", "put_object_total",
		"uptime_seconds",
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("JSON keys = %v\nwant       %v", keys, want)
	}
}

// Nil-safe like the other Record helpers: the admin handler runs in fixtures
// that have no metrics.
func TestRecordAdminAuthFailure_NilSafe(t *testing.T) {
	var m *Metrics
	m.RecordAdminAuthFailure()
}
