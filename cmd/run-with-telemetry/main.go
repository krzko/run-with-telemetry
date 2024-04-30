package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/google/go-github/v60/github"
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
	JobName                 string
	JobAsParent             string
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

func emitStepSummary(params InputParams, traceID trace.TraceID, spanID trace.SpanID, success bool) {
	conclusion := "✅ success"
	if !success {
		conclusion = "❌ failure"
	}

	githubactions.Group("Step Summary")
	githubactions.Infof("Step Name: %s", params.StepName)
	githubactions.Infof("Trace ID: %s", traceID.String())
	githubactions.Infof("Span ID: %s", spanID.String())
	githubactions.Infof("Step Conclusion: %s", conclusion)
	githubactions.EndGroup()

	markdownSummary := fmt.Sprintf(
		"### 📋 Step Summary (%s)\n\n- Step Name: %s\n- Trace ID: %s\n- Span ID: %s\n- Step Conclusion: %s\n",
		actionName,
		params.StepName,
		traceID.String(),
		spanID.String(),
		conclusion,
	)

	githubactions.AddStepSummary(markdownSummary)
}

func executeCommand(shell string, command string, span trace.Span, headers map[string]string) (string, int, string, string, error) {
	var cmd *exec.Cmd
	switch shell {
	case "bash":
		cmd = exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command)
	case "pwsh":
		cmd = exec.Command("pwsh", "-command", command)
	case "python":
		cmd = exec.Command("python", "-c", command)
	case "sh":
		cmd = exec.Command("sh", "-e", "-c", command)
	case "cmd":
		cmd = exec.Command("cmd", "/D", "/E:ON", "/V:OFF", "/S", "/C", command)
	case "powershell":
		cmd = exec.Command("powershell", "-command", command)
	default:
		shell = "bash"
		cmd = exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command)
	}

	// Get the trace context from the span
	sc := span.SpanContext()
	traceparent := fmt.Sprintf("00-%s-%s-01", sc.TraceID().String(), sc.SpanID().String())

	otelExporterOtlpEndpoint := githubactions.GetInput("otel-exporter-otlp-endpoint")
	otelResourceAttributes := githubactions.GetInput("otel-resource-attributes")

	headersStr := mapToCommaSeparatedString(headers)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TRACEPARENT=%s", traceparent),
		fmt.Sprintf("TRACEID=%s", sc.TraceID().String()),
		fmt.Sprintf("SPANID=%s", sc.SpanID().String()),
		fmt.Sprintf("OTEL_EXPORTER_OTLP_HEADERS=%s", headersStr),
		fmt.Sprintf("OTEL_EXPORTER_OTLP_ENDPOINT=%s", otelExporterOtlpEndpoint),
	)

	if len(headers) > 0 {
		headersStr := mapToCommaSeparatedString(headers)
		cmd.Env = append(cmd.Env, fmt.Sprintf("OTEL_EXPORTER_OTLP_HEADERS=%s", headersStr))
	}

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

func generateJobSpanID(runID int64, runAttempt int, jobName string) (trace.SpanID, error) {
	input := fmt.Sprintf("%d%d%s", runID, runAttempt, jobName)
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

func getGitHubJobName(ctx context.Context, token, owner, repo string, runID, attempt int64) (string, error) {
	githubactions.Infof("Getting GitHub job name for run ID: %d and attempt: %d", runID, attempt)
	splitRepo := strings.Split(repo, "/")
	if len(splitRepo) != 2 {
		err := fmt.Errorf("GITHUB_REPOSITORY environment variable is malformed: %s", repo)
		githubactions.Errorf("Error: %v", err)
		return "", err
	}
	owner, repo = splitRepo[0], splitRepo[1]
	githubactions.Infof("Parsed GitHub repository owner: %s, repo: %s", owner, repo)

	client := github.NewClient(nil).WithAuthToken(token)
	opts := &github.ListWorkflowJobsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	githubactions.Infof("Fetching workflow jobs from GitHub API")
	runJobs, resp, err := client.Actions.ListWorkflowJobs(ctx, owner, repo, runID, opts)
	if err != nil {
		githubactions.Errorf("Failed to fetch workflow jobs: %v", err)
		if resp != nil {
			githubactions.Infof("GitHub API response status: %s", resp.Status)
			if resp.Body != nil {
				bodyBytes, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr != nil {
					githubactions.Errorf("Failed to read response body: %v", readErr)
				} else {
					githubactions.Debugf("GitHub API response body: %s", string(bodyBytes))
				}
			}
		}
		return "", err
	}

	runnerName := os.Getenv("RUNNER_NAME")
	githubactions.Infof("Looking for job with runner name: %s", runnerName)
	for _, job := range runJobs.Jobs {
		if job.RunnerName != nil && job.Name != nil && job.RunAttempt != nil {
			githubactions.Infof("Inspecting job: %s, runner: %s, attempt: %d", *job.Name, *job.RunnerName, *job.RunAttempt)
			if *job.RunAttempt == attempt && *job.RunnerName == runnerName {
				githubactions.Infof("Match found, job name: %s", *job.Name)
				return *job.Name, nil
			}
		}
	}

	err = fmt.Errorf("no job found matching the criteria")
	githubactions.Errorf("Error: %v", err)
	return "", err
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

	if githubactions.GetInput("github-token") == "" {
		githubactions.Fatalf("No GitHub token provided")
	}

	resourceAttrs := make(map[string]string)
	if githubactions.GetInput("otel-resource-attributes") == "" {
		githubactions.Infof("No resource attributes provided")
	} else {
		githubactions.Infof("Resource attributes provided")
		attrs := strings.Split(githubactions.GetInput("otel-resource-attributes"), ",")
		for _, attr := range attrs {
			keyValue := strings.Split(attr, "=")
			if len(keyValue) == 2 {
				resourceAttrs[keyValue[0]] = keyValue[1]
			} else {
				githubactions.Warningf("Invalid resource attribute: %s", attr)
			}
		}
	}

	headers := make(map[string]string)
	if githubactions.GetInput("otel-exporter-otlp-headers") == "" {
		githubactions.Infof("No OTLP headers provided")
	} else {
		hs := strings.Split(githubactions.GetInput("otel-exporter-otlp-headers"), ",")
		for _, header := range hs {
			keyValue := strings.Split(header, "=")
			if len(keyValue) == 2 {
				headers[keyValue[0]] = keyValue[1]
			} else {
				githubactions.Warningf("invalid header: %s", header)
			}
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
		JobName:                 githubactions.GetInput("job-name"),
		JobAsParent:             githubactions.GetInput("job-as-parent"),
	}
}

func mapToCommaSeparatedString(m map[string]string) string {
	var result []string
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(result, ",")
}

func updateResourceAttributesFromFile(filePath string, params *InputParams) (bool, error) {
	githubactions.Infof("Attempting to read file: %s", filePath)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("error checking file existence: %w", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			githubactions.Warningf("error closing file: %v", closeErr)
		}
		if removeErr := os.Remove(filePath); removeErr != nil {
			githubactions.Warningf("error removing file: %v", removeErr)
		}
	}()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			githubactions.Warningf("malformed line %d: %s", lineNumber, line)
			continue // Skip this line but keep processing the rest of the file
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			githubactions.Warningf("empty key on line %d: %s", lineNumber, line)
			continue // Skip this line but keep processing the rest of the file
		}
		params.OtelResourceAttrs[key] = value
	}

	if err := scanner.Err(); err != nil {
		githubactions.Errorf("Error scanning file: %v", err)
		return false, fmt.Errorf("error scanning file: %w", err)
	}

	githubactions.Infof("Successfully processed %d resource attributes from file: %s", len(params.OtelResourceAttrs), filePath)
	return true, nil
}

func main() {
	var exitCode int
	var success bool

	params := parseInputParams()
	ctx := context.Background()

	githubactions.Infof("Running step: %s", params.StepName)

	runID, err := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	if err != nil {
		githubactions.Fatalf("Failed to parse GITHUB_RUN_ID: %v", err)
	}
	runAttempt, err := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	if err != nil {
		githubactions.Fatalf("Failed to parse GITHUB_RUN_ATTEMPT: %v", err)
	}

	job := params.JobName
	if job == "" {
		githubactions.Infof("Job name not provided, fetching from GitHub API")
		job, err = getGitHubJobName(ctx, params.GithubToken, os.Getenv("GITHUB_REPOSITORY_OWNER"), os.Getenv("GITHUB_REPOSITORY"), runID, int64(runAttempt))
		if err != nil {
			githubactions.Fatalf("Failed to get job name: %v", err)
		}
	}
	githubactions.SetOutput("job-name", job)

	traceID, err := generateTraceID(runID, runAttempt)
	if err != nil {
		githubactions.Fatalf("Failed to generate trace ID: %v", err)
	}
	githubactions.SetOutput("trace-id", traceID.String())

	shutdown := initTracer(params.OtelExporterEndpoint, params.OtelServiceName, params.OtelResourceAttrs, params.OtelExporterOtlpHeaders)
	defer shutdown()

	defer func() {
		shutdown()
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()

	var parentSpandID trace.SpanID
	jobAsParentInput := params.JobAsParent
	if jobAsParentInput == "true" {
		githubactions.Infof("Using job as parent")
		parentSpandID, err = generateJobSpanID(runID, runAttempt, job)
		if err != nil {
			githubactions.Fatalf("Failed to generate step span ID: %v", err)
		}
	} else {
		githubactions.Infof("Using step as parent")
		parentSpandID, err = generateStepSpanID(runID, runAttempt, job, params.StepName)
		if err != nil {
			githubactions.Fatalf("Failed to generate step span ID: %v", err)
		}
	}

	spanContextConfig := trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     parentSpandID,
		TraceFlags: trace.FlagsSampled,
	}

	ctx = trace.ContextWithRemoteSpanContext(
		context.Background(),
		trace.NewSpanContext(spanContextConfig),
	)

	tracer := otel.Tracer(actionName)

	defer func() {
		emitStepSummary(params, traceID, parentSpandID, success)
		shutdown()
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()

	spanName := fmt.Sprintf("Run %s", strings.ToLower(params.StepName))

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
		success = false

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
		success = true
	}

	wasUpdated, err := updateResourceAttributesFromFile("otel_resource_attributes.txt", &params)
	if err != nil {
		githubactions.Fatalf("Failed to update resource attributes from file: %v", err)
	}

	if wasUpdated {
		for key, value := range params.OtelResourceAttrs {
			span.SetAttributes(attribute.String(key, value))
		}
	}

	for key, value := range params.OtelResourceAttrs {
		span.SetAttributes(attribute.String(key, value))
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
