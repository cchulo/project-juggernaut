// Package telemetry exposes Prometheus metrics and OpenTelemetry tracing for
// the gateway and controller.
package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics are the gateway/controller metrics named in docs/DESIGN.md.
type Metrics struct {
	reg *prometheus.Registry

	PodsActive         *prometheus.GaugeVec
	ColdStartSeconds   *prometheus.HistogramVec
	IdleTerminations   *prometheus.CounterVec
	AuthFailures       *prometheus.CounterVec
	ToolCalls          *prometheus.CounterVec
	ToolCallSeconds    *prometheus.HistogramVec
	ConfigReloadErrors prometheus.Counter
	EgressDecisions    *prometheus.CounterVec
}

// New registers the metrics on a fresh registry (plus Go/process collectors).
func New(namespace string) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		PodsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: "pods_active",
			Help: "Session pods by server type and phase."}, []string{"server_type", "phase"}),
		ColdStartSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: namespace, Name: "cold_start_seconds",
			Help: "Time from Session creation to Ready.", Buckets: []float64{1, 2, 5, 10, 20, 30, 60, 120}}, []string{"server_type"}),
		IdleTerminations: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "idle_terminations_total",
			Help: "Session pods terminated by the reaper, by reason."}, []string{"reason"}),
		AuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "auth_failures_total",
			Help: "Rejected requests by reason (missing, invalid, scope, revoked)."}, []string{"reason"}),
		ToolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "tool_calls_total",
			Help: "Tool calls by server type and outcome."}, []string{"server_type", "outcome"}),
		ToolCallSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: namespace, Name: "tool_call_seconds",
			Help: "Tool call latency.", Buckets: prometheus.ExponentialBuckets(0.05, 2, 12)}, []string{"server_type"}),
		ConfigReloadErrors: prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: "config_reload_errors_total",
			Help: "Rejected juggernaut.yaml reloads."}),
		EgressDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "egress_decisions_total",
			Help: "Egress proxy decisions."}, []string{"decision"}),
	}
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.PodsActive, m.ColdStartSeconds, m.IdleTerminations, m.AuthFailures, m.ToolCalls, m.ToolCallSeconds, m.ConfigReloadErrors, m.EgressDecisions)
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
