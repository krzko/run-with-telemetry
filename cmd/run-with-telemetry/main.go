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
	"sync"
	"time"

	"github.com/google/go-github/v78/github"
	"github.com/sethvargo/go-githubactions"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
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
	StderrAsInfo            string
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

func executeCommand(shell string, command string, span trace.Span, headers map[string]string, stderrAsInfo bool) (string, int, string, string, error) {
	var cmd *exec.Cmd
	var args []string

	switch shell {
	case "bash":
		args = []string{"--noprofile", "--norc", "-eo", "pipefail", "-c", command}
	case "pwsh", "powershell":
		args = []string{"-command", command}
	case "python":
		args = []string{"-c", command}
	case "sh":
		args = []string{"-e", "-c", command}
	case "cmd":
		args = []string{"/D", "/E:ON", "/V:OFF", "/S", "/C", command}
	default:
		shell = "bash"
		args = []string{"--noprofile", "--norc", "-eo", "pipefail", "-c", command}
	}

	cmd = exec.Command(shell, args...)

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

	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			githubactions.Infof("%s", line)
			stdoutBuf.WriteString(line + "\n")
		}
	}()

	if stderrAsInfo {
		githubactions.Infof("Redirecting stderr to info: %t", stderrAsInfo)
	}
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if stderrAsInfo {
				githubactions.Infof("%s", line)
			} else {
				githubactions.Errorf("%s", line)
			}
			stderrBuf.WriteString(line + "\n")
		}
	}()

	if err := cmd.Start(); err != nil {
		return shell, 0, "", "", err
	}

	wg.Wait()

	if err := cmd.Wait(); err != nil {
		return shell, cmd.ProcessState.Pid(), stdoutBuf.String(), stderrBuf.String(), err
	}

	return shell, cmd.ProcessState.Pid(), stdoutBuf.String(), stderrBuf.String(), nil
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

// generateJobSpanID derives a job span ID from the job's GitHub check-run ID
// (WorkflowJob.ID), matching the scheme used by the OpenTelemetry Collector
// GitHub Actions Receiver (receiver.githubreceiver.UseCheckRunID) so that
// this action's spans attach to the receiver's job span rather than the
// legacy runID+attempt+jobName hash.
func generateJobSpanID(checkRunID int64) (trace.SpanID, error) {
	return spanIDFromCheckRun(fmt.Sprintf("%d-j", checkRunID))
}

// generateStepSpanID derives a step span ID from the job's check-run ID and
// step name, matching the receiver's scheme. If a job has two steps with the
// same name, the receiver disambiguates them by appending "-N"; this action
// only knows about its own step, so duplicate step names within a job are not
// supported here (use unique step names, as recommended by the receiver).
func generateStepSpanID(checkRunID int64, stepName string) (trace.SpanID, error) {
	return spanIDFromCheckRun(fmt.Sprintf("%d-%s-s", checkRunID, stepName))
}

func spanIDFromCheckRun(input string) (trace.SpanID, error) {
	hash := sha256.Sum256([]byte(input))
	spanIDHex := hex.EncodeToString(hash[:])

	var spanID trace.SpanID
	_, err := hex.Decode(spanID[:], []byte(spanIDHex[16:32]))
	if err != nil {
		return trace.SpanID{}, err
	}

	return spanID, nil
}

// resolveWorkflowJob looks up the currently running job via the GitHub API
// and returns its display name and its ID (the "check run ID" GitHub assigns
// to the job, used to derive deterministic span IDs). If preferredJobName is
// set (the job-name input), it is used to match the job instead of the
// runner-name heuristic.
func resolveWorkflowJob(ctx context.Context, token, repo, preferredJobName string, runID, attempt int64) (string, int64, error) {
	githubactions.Infof("Resolving GitHub job for run ID: %d and attempt: %d", runID, attempt)
	splitRepo := strings.Split(repo, "/")
	if len(splitRepo) != 2 {
		err := fmt.Errorf("GITHUB_REPOSITORY environment variable is malformed: %s", repo)
		githubactions.Errorf("Error: %v", err)
		return "", 0, err
	}
	owner, repoName := splitRepo[0], splitRepo[1]

	client := github.NewClient(nil).WithAuthToken(token)
	opts := &github.ListWorkflowJobsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	const attempts = 3 // Number of attempts for retrying API call
	runnerName := os.Getenv("RUNNER_NAME")

	for i := 0; i < attempts; i++ {
		githubactions.Infof("Fetching workflow jobs from GitHub API, attempt %d/%d", i+1, attempts)
		runJobs, resp, err := client.Actions.ListWorkflowJobs(ctx, owner, repoName, runID, opts)
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
		} else {
			for _, job := range runJobs.Jobs {
				if job.GetRunAttempt() != attempt {
					continue
				}
				if preferredJobName != "" {
					if job.GetName() == preferredJobName {
						githubactions.Infof("Match found, job name: %s, id: %d", job.GetName(), job.GetID())
						return job.GetName(), job.GetID(), nil
					}
					continue
				}
				if job.GetRunnerName() == runnerName {
					githubactions.Infof("Match found, job name: %s, id: %d", job.GetName(), job.GetID())
					return job.GetName(), job.GetID(), nil
				}
			}
			githubactions.Infof("No matching job found on attempt %d", i+1)
		}

		if i < attempts-1 {
			time.Sleep(3 * time.Second) // Wait before retrying
		}
	}

	return "", 0, fmt.Errorf("no workflow job found for run ID %d attempt %d after %d attempts", runID, attempt, attempts)
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
		StderrAsInfo:            githubactions.GetInput("stderr-as-info"),
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

	job, checkRunID, err := resolveWorkflowJob(ctx, params.GithubToken, os.Getenv("GITHUB_REPOSITORY"), params.JobName, runID, int64(runAttempt))
	if err != nil {
		githubactions.Fatalf("Failed to resolve GitHub job: %v", err)
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
		parentSpandID, err = generateJobSpanID(checkRunID)
		if err != nil {
			githubactions.Fatalf("Failed to generate job span ID: %v", err)
		}
	} else {
		parentSpandID, err = generateStepSpanID(checkRunID, params.StepName)
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

	stderrAsInfo := strings.ToLower(params.StderrAsInfo) == "true"
	usedShell, pid, stdout, stderr, err := executeCommand(shell, params.Run, span, params.OtelExporterOtlpHeaders, stderrAsInfo)

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
