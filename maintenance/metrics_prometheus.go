package maintenance

// The Prometheus text exposition format, version 0.0.4, written by hand.
//
// jay has four direct dependencies and the client library would be a fifth
// for what amounts to a dozen lines of text per scrape. The format is small
// and stable: a `# HELP` and a `# TYPE` line per family, then one line per
// sample, with three characters escaped in label values and two in help text.

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// PrometheusContentType is the Content-Type of the text exposition format.
const PrometheusContentType = "text/plain; version=0.0.4; charset=utf-8"

// MetricType is the TYPE of a metric family. jay exposes only these two:
// everything it counts only ever grows, and everything else is a reading.
type MetricType string

// The metric types jay exposes.
const (
	CounterType MetricType = "counter"
	GaugeType   MetricType = "gauge"
)

// Label is one name="value" pair of a sample.
type Label struct {
	Name  string
	Value string
}

// Sample is one line of a family: its labels and its value.
type Sample struct {
	Labels []Label
	Value  float64
}

// MetricFamily is one metric: its name, help, type and samples.
type MetricFamily struct {
	Name    string
	Help    string
	Type    MetricType
	Samples []Sample
}

// Counter builds a single-sample counter family.
func Counter(name, help string, value int64) MetricFamily {
	return MetricFamily{Name: name, Help: help, Type: CounterType, Samples: []Sample{{Value: float64(value)}}}
}

// Gauge builds a single-sample gauge family.
func Gauge(name, help string, value float64) MetricFamily {
	return MetricFamily{Name: name, Help: help, Type: GaugeType, Samples: []Sample{{Value: value}}}
}

// labelled builds a sample carrying one label.
func labelled(name, value string, v int64) Sample {
	return Sample{Labels: []Label{{Name: name, Value: value}}, Value: float64(v)}
}

// PrometheusFamilies maps the snapshot onto Prometheus metric families. This
// is the ONE place that decides what each counter is called there; a counter
// added to MetricsSnapshot and not here fails TestPrometheusFamilies_ExposeEveryCounterOnce.
//
// Naming follows Prometheus conventions: the jay_ prefix, base units, and the
// _total suffix on every counter (after the unit: _bytes_total). The
// operation counters are one family with an `op` label rather than seven
// metrics, because summing across operations means something — total
// operations served — and that is the test for when labels are the right tool.
// The label values are the snapshot's own field names, so the JSON and the
// Prometheus exports read alike.
func (s MetricsSnapshot) PrometheusFamilies() []MetricFamily {
	return []MetricFamily{
		{
			Name: "jay_operations_total",
			Help: "Object and bucket operations served, by operation. S3 API and native protocol combined.",
			Type: CounterType,
			Samples: []Sample{
				labelled("op", "put_object", s.PutObjectTotal),
				labelled("op", "get_object", s.GetObjectTotal),
				labelled("op", "head_object", s.HeadObjectTotal),
				labelled("op", "delete_object", s.DeleteObjectTotal),
				labelled("op", "list_objects", s.ListObjectsTotal),
				labelled("op", "create_bucket", s.CreateBucketTotal),
				labelled("op", "delete_bucket", s.DeleteBucketTotal),
			},
		},
		Counter("jay_uploaded_bytes_total",
			"Object bytes stored by uploads. S3 API and native protocol combined.", s.BytesUploaded),
		Counter("jay_downloaded_bytes_total",
			"Object bytes served in download responses, ranges included. S3 API and native protocol combined.", s.BytesDownloaded),
		{
			Name: "jay_auth_failures_total",
			Help: "Requests refused for their credentials, by listener: s3 is the S3 API, admin is the admin listener (/_jay, /metrics, pprof).",
			Type: CounterType,
			Samples: []Sample{
				labelled("surface", "s3", s.AuthFailures),
				labelled("surface", "admin", s.AdminAuthFailures),
			},
		},
		Counter("jay_checksum_failures_total",
			"Objects whose bytes on disk no longer matched their recorded SHA-256 when the scrubber verified them.", s.ChecksumFailures),
		Counter("jay_fsync_failures_total",
			"fsync calls that failed while making a write durable. Treat any as a disk problem.", s.FsyncFailures),
		Counter("jay_objects_quarantined_total",
			"Objects moved to quarantine by startup recovery or by the scrubber.", s.ObjectsQuarantined),
		Counter("jay_metadata_decode_failures_total",
			"Metadata records in bbolt that could not be decoded and were skipped.", s.MetadataDecodeFailures),
		Counter("jay_panics_recovered_total",
			"Handler panics recovered by the HTTP listeners or the native protocol. The process kept running with state that may be inconsistent.", s.PanicsRecovered),
		Gauge("jay_start_time_seconds",
			"Unix time at which the jay process started.", unixSeconds(s)),
	}
}

// unixSeconds is StartedAt as fractional Unix seconds. A snapshot built by
// hand (a zero StartedAt) reports 0 rather than a date in year 1.
func unixSeconds(s MetricsSnapshot) float64 {
	if s.StartedAt.IsZero() {
		return 0
	}
	return float64(s.StartedAt.UnixNano()) / 1e9
}

// WritePrometheus renders families in the text exposition format.
//
// Everything is validated before the first byte goes out: a name that is not a
// valid metric name, a counter without the _total suffix, a family declared
// twice or a series repeated inside a family is an error, and w receives
// nothing. A scraper that gets half an exposition and a 200 would record the
// half as the whole.
func WritePrometheus(w io.Writer, families []MetricFamily) error {
	if err := validateFamilies(families); err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, f := range families {
		fmt.Fprintf(&buf, "# HELP %s %s\n", f.Name, escapeHelp(f.Help))
		fmt.Fprintf(&buf, "# TYPE %s %s\n", f.Name, f.Type)
		for _, s := range f.Samples {
			buf.WriteString(f.Name)
			writeLabels(&buf, s.Labels)
			buf.WriteByte(' ')
			buf.WriteString(formatValue(s.Value))
			buf.WriteByte('\n')
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func validateFamilies(families []MetricFamily) error {
	seen := map[string]bool{}
	for _, f := range families {
		if !validMetricName(f.Name) {
			return fmt.Errorf("prometheus: invalid metric name %q", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("prometheus: metric family %s declared twice", f.Name)
		}
		seen[f.Name] = true
		switch f.Type {
		case CounterType:
			if !strings.HasSuffix(f.Name, "_total") {
				return fmt.Errorf("prometheus: counter %s does not end in _total", f.Name)
			}
		case GaugeType:
		default:
			return fmt.Errorf("prometheus: %s has unsupported type %q", f.Name, f.Type)
		}
		if len(f.Samples) == 0 {
			return fmt.Errorf("prometheus: %s has no samples", f.Name)
		}
		series := map[string]bool{}
		for _, s := range f.Samples {
			var key strings.Builder
			for _, l := range s.Labels {
				if !validLabelName(l.Name) {
					return fmt.Errorf("prometheus: %s has invalid label name %q", f.Name, l.Name)
				}
				key.WriteString(l.Name + "\x00" + l.Value + "\x00")
			}
			if series[key.String()] {
				return fmt.Errorf("prometheus: %s repeats a series", f.Name)
			}
			series[key.String()] = true
		}
	}
	return nil
}

// validMetricName reports whether name matches [a-zA-Z_:][a-zA-Z0-9_:]*.
func validMetricName(name string) bool {
	return validName(name, "_:")
}

// validLabelName reports whether name matches [a-zA-Z_][a-zA-Z0-9_]* and is
// not one of the names reserved for Prometheus itself (a leading "__").
func validLabelName(name string) bool {
	return validName(name, "_") && !strings.HasPrefix(name, "__")
}

// validName reports whether name is non-empty, made of ASCII letters, digits
// and the punctuation in extra, and does not start with a digit.
func validName(name, extra string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', strings.ContainsRune(extra, c):
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func writeLabels(buf *bytes.Buffer, labels []Label) {
	if len(labels) == 0 {
		return
	}
	buf.WriteByte('{')
	for i, l := range labels {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(l.Name)
		buf.WriteString(`="`)
		buf.WriteString(labelValueEscaper.Replace(l.Value))
		buf.WriteByte('"')
	}
	buf.WriteByte('}')
}

// In a label value the format escapes backslash, double quote and line feed;
// in help text, only backslash and line feed.
var (
	labelValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper       = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeHelp(help string) string { return helpEscaper.Replace(help) }

// formatValue writes a sample value. Integers print without an exponent, so a
// counter reads as the count it is; the three special values use the
// spellings the format defines.
func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
