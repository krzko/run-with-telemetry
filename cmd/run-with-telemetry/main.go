package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sethvargo/go-githubactions"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.opentelemetry.io/otel/trace"
)

const actionName = "run-with-telemetry"

var (
	BUILD_VERSION string
	BUILD_DATE    string
	COMMIT_ID     string
)

type InputParams struct {
	GithubToken             string
	OtelExporterEndpoint    string
	OtelResourceAttrs       map[string]string
	OtelServiceName         string
	Run                     string
	OtelExporterOtlpHeaders map[string]string
	StepName                string
}

type TextMapCarrier map[string]string

func (t TextMapCarrier) Get(key string) string {
	return t[key]
}

func (t TextMapCarrier) Set(key string, value string) {
	t[key] = value
}

func (t TextMapCarrier) Keys() []string {
	keys := make([]string, 0, len(t))
	for key := range t {
		keys = append(keys, key)
	}
	return keys
}

func createEventAttributes(baseAttributes []trace.EventOption, stdout, stderr string) []trace.EventOption {
	if len(stdout) > 0 {
		baseAttributes = append(baseAttributes, trace.WithAttributes(attribute.String("stdout", stdout)))
	}
	if len(stderr) > 0 {
		baseAttributes = append(baseAttributes, trace.WithAttributes(attribute.String("stderr", stderr)))
	}

	return baseAttributes
}

func executeCommand(shell string, command string, span trace.Span, headers map[string]string) (string, int, string, string, error) {
	var cmd *exec.Cmd
	switch shell {
	case "bash":
		cmd = exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command)
	case "pwsh":
		cmd = exec.Command("pwsh", "-command", command)
	default:
		shell = "bash"
		cmd = exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command)
	}

	// Get the trace context from the span
	sc := span.SpanContext()
	traceparent := fmt.Sprintf("00-%s-%s-01", sc.TraceID().String(), sc.SpanID().String())

	otelExporterOtlpEndpoint := githubactions.GetInput("otel-exporter-otlp-endpoint")
	otelServiceName := githubactions.GetInput("otel-service-name")
	otelResourceAttributes := githubactions.GetInput("otel-resource-attributes")

	headersStr := mapToCommaSeparatedString(headers)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TRACEPARENT=%s", traceparent),
		fmt.Sprintf("TRACEID=%s", sc.TraceID().String()),
		fmt.Sprintf("SPANID=%s", sc.SpanID().String()),
		fmt.Sprintf("OTEL_EXPORTER_OTLP_HEADERS=%s", headersStr),
		fmt.Sprintf("OTEL_EXPORTER_OTLP_ENDPOINT=%s", otelExporterOtlpEndpoint),
		fmt.Sprintf("OTEL_SERVICE_NAME=%s", otelServiceName),
	)

	if otelResourceAttributes != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("OTEL_RESOURCE_ATTRIBUTES=%s", otelResourceAttributes))
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return shell, 0, "", "", err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return shell, 0, "", "", err
	}

	if err := cmd.Start(); err != nil {
		return shell, 0, "", "", err
	}

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)
	stdoutBuf.ReadFrom(stdoutPipe)
	stderrBuf.ReadFrom(stderrPipe)

	// Print stdout and stderr to GitHub Actions console
	if stdout := stdoutBuf.String(); len(stdout) > 0 {
		githubactions.Infof("Standard Output: %s", stdout)
	}
	if stderr := stderrBuf.String(); len(stderr) > 0 {
		githubactions.Errorf("Standard Error: %s", stderr)
	}

	if err := cmd.Wait(); err != nil {
		return shell, cmd.Process.Pid, stdoutBuf.String(), stderrBuf.String(), err
	}

	return shell, cmd.Process.Pid, stdoutBuf.String(), stderrBuf.String(), nil
}

func generateTraceID(runID int64, runAttempt int) (trace.TraceID, error) {
	input := fmt.Sprintf("%d%dt", runID, runAttempt)
	hash := sha256.Sum256([]byte(input))
	traceIDHex := hex.EncodeToString(hash[:])

	var traceID trace.TraceID
	_, err := hex.Decode(traceID[:], []byte(traceIDHex[:32]))
	if err != nil {
		return trace.TraceID{}, err
	}

	return traceID, nil
}

func generateSpanID(input string) (trace.SpanID, error) {
	hash := sha256.Sum256([]byte(input))
	spanIDHex := hex.EncodeToString(hash[:])

	var spanID trace.SpanID
	_, err := hex.Decode(spanID[:], []byte(spanIDHex[16:32]))
	if err != nil {
		return trace.SpanID{}, err
	}

	return spanID, nil
}

func generateStepSpanID(runID int64, runAttempt int, jobName, stepName string, stepNumber ...int) (trace.SpanID, error) {
	var input string
	if len(stepNumber) > 0 && stepNumber[0] > 0 {
		input = fmt.Sprintf("%d%d%s%s%d", runID, runAttempt, jobName, stepName, stepNumber[0])
	} else {
		input = fmt.Sprintf("%d%d%s%s", runID, runAttempt, jobName, stepName)
	}
	hash := sha256.Sum256([]byte(input))
	spanIDHex := hex.EncodeToString(hash[:])

	var spanID trace.SpanID
	_, err := hex.Decode(spanID[:], []byte(spanIDHex[16:32]))
	if err != nil {
		return trace.SpanID{}, err
	}

	return spanID, nil
}

func initTracer(endpoint string, serviceName string, attrs map[string]string, headers map[string]string) func() {
	var attr []attribute.KeyValue
	for k, v := range attrs {
		attr = append(attr, attribute.String(k, v))
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		append(attr, attribute.String(string(semconv.ServiceNameKey), serviceName))...,
	)

	clientOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithHeaders(headers),
	}

	exp, err := otlptracegrpc.New(context.Background(), clientOpts...)
	if err != nil {
		githubactions.Fatalf("failed to initialise exporter: %v", err)
	}
	bsp := sdktrace.NewBatchSpanProcessor(exp)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	return func() {
		err := tracerProvider.Shutdown(context.Background())
		if err != nil {
			githubactions.Errorf("failed to shut down provider: %v", err)
		}
	}
}

func parseInputParams() InputParams {
	githubactions.Infof("Starting %s version: %s (%s) commit: %s", actionName, BUILD_VERSION, BUILD_DATE, COMMIT_ID)

	resourceAttrs := make(map[string]string)
	attrs := strings.Split(githubactions.GetInput("otel-resource-attributes"), ",")
	for _, attr := range attrs {
		keyValue := strings.Split(attr, "=")
		if len(keyValue) == 2 {
			resourceAttrs[keyValue[0]] = keyValue[1]
		} else {
			githubactions.Warningf("Invalid resource attribute: %s", attr)
		}
	}

	headers := make(map[string]string)
	hs := strings.Split(githubactions.GetInput("otel-exporter-otlp-headers"), ",")
	for _, header := range hs {
		keyValue := strings.Split(header, "=")
		if len(keyValue) == 2 {
			headers[keyValue[0]] = keyValue[1]
		} else {
			githubactions.Warningf("invalid header: %s", header)
		}
	}

	return InputParams{
		GithubToken:             githubactions.GetInput("github-token"),
		OtelExporterEndpoint:    githubactions.GetInput("otel-exporter-otlp-endpoint"),
		OtelResourceAttrs:       resourceAttrs,
		OtelServiceName:         githubactions.GetInput("otel-service-name"),
		Run:                     githubactions.GetInput("run"),
		OtelExporterOtlpHeaders: headers,
		StepName:                githubactions.GetInput("step-name"),
	}
}

func mapToCommaSeparatedString(m map[string]string) string {
	var result []string
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(result, ",")
}

func parseTraceParent(traceparent string) (trace.TraceID, trace.SpanID, error) {
	parts := strings.Split(traceparent, "-")
	if len(parts) < 3 {
		return trace.TraceID{}, trace.SpanID{}, fmt.Errorf("invalid traceparent: %s", traceparent)
	}

	traceID, err := hex.DecodeString(parts[1])
	if err != nil {
		return trace.TraceID{}, trace.SpanID{}, fmt.Errorf("invalid TraceID: %w", err)
	}

	spanID, err := hex.DecodeString(parts[2])
	if err != nil {
		return trace.TraceID{}, trace.SpanID{}, fmt.Errorf("invalid SpanID: %w", err)
	}

	var tid trace.TraceID
	var sid trace.SpanID
	copy(tid[:], traceID)
	copy(sid[:], spanID)

	return tid, sid, nil
}

func main() {
	var exitCode int

	params := parseInputParams()

	runID, err := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	if err != nil {
		githubactions.Fatalf("Failed to parse GITHUB_RUN_ID: %v", err)
	}
	runAttempt, err := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	if err != nil {
		githubactions.Fatalf("Failed to parse GITHUB_RUN_ATTEMPT: %v", err)
	}
	job := os.Getenv("GITHUB_JOB")

	traceID, err := generateTraceID(runID, runAttempt)
	if err != nil {
		githubactions.Fatalf("Failed to generate trace ID: %v", err)
	}

	shutdown := initTracer(params.OtelExporterEndpoint, params.OtelServiceName, params.OtelResourceAttrs, params.OtelExporterOtlpHeaders)
	defer shutdown()

	defer func() {
		shutdown()
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()

	stepSpanID, err := generateStepSpanID(runID, runAttempt, job, params.StepName)
	if err != nil {
		githubactions.Fatalf("Failed to generate step span ID: %v", err)
	}

	spanContextConfig := trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     stepSpanID,
		TraceFlags: trace.FlagsSampled,
	}

	ctx := trace.ContextWithRemoteSpanContext(
		context.Background(),
		trace.NewSpanContext(spanContextConfig),
	)

	tracer := otel.Tracer(actionName)

	var spanName string
	if strings.Count(params.Run, "\n") > 0 {
		spanName = "Executing multiple commands"
	} else {
		binaryName := strings.Fields(params.Run)[0] // Assumes the binary name has no spaces
		spanName = fmt.Sprintf("Executing %s", binaryName)
	}
	_, span := tracer.Start(ctx, spanName)
	defer span.End()

	shell := githubactions.GetInput("shell")
	githubactions.Infof("Executing command: %s with shell: %s", params.Run, shell)

	usedShell, pid, stdout, stderr, err := executeCommand(shell, params.Run, span, params.OtelExporterOtlpHeaders)

	if err != nil {
		githubactions.Errorf("Failed to execute command: %v", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		exitCode = 1

		// Prepare base attributes for span event
		baseAttributes := []trace.EventOption{
			trace.WithAttributes(
				attribute.String("exception.type", "ExecutionError"),
				attribute.String("exception.message", err.Error()),
			),
		}

		// Create a new span event to record the exception along with stdout and stderr
		span.AddEvent("Standard error", createEventAttributes(baseAttributes, stdout, stderr)...)

		return
	} else {
		githubactions.Infof("Command executed successfully")
		span.SetStatus(codes.Ok, "Command executed successfully")
	}

	span.AddEvent("Start executing command", trace.WithAttributes(attribute.String("command", params.Run)))

	// Add process attributes to the span
	span.SetAttributes(
		attribute.String("process.executable.name", usedShell),
		attribute.String("process.command", params.Run),
		attribute.Int("process.pid", pid),
	)

	span.AddEvent("Finished executing command", createEventAttributes(nil, stdout, stderr)...)
}
