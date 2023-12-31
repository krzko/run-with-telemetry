# run-with-telemetry

⚠️⚠️⚠️ WORK IN PROGRESS - DO NOT USE ⚠️⚠️⚠️

The **Run with Telemetry** GitHub Action allows you to execute a command on a GitHub Actions runner and export the associated OpenTelemetry trace data to a specified endpoint. This action aims to provide monitoring and observability within your CI/CD pipelines by leveraging OpenTelemetry's tracing capabilities.

## Features

* **Execute Commands:** Run a specified command on the GitHub Actions runner.
* **OpenTelemetry Tracing:** Export trace data related to the command execution to a specified OpenTelemetry endpoint.
* **Shell Override:** Choose the shell in which the command will be executed.
* **Resource Attributes:** Define key-value pairs as resource attributes which will be associated with the trace data.
* **Custom Headers:** Define custom headers to be sent along with the OTLP (OpenTelemetry Protocol) gRPC exporter.
* **Environment Variable Injection:** Ability to inject environment variables into the shells, aiding in dynamic command executions.
* **OpenTelemetry Resource Attributes File:** Ability to read a file (`otel_resource_attributes.txt`) for additional OpenTelemetry resource attributes that will be added to the spans generated.

## Input Input Parameters

* **`github-token` (Optional):** A token for interacting with the GitHub API. Default is the GitHub token provided by the GitHub Actions runtime.
* **`is-root` (Optional):** Denotes if this is the root span, marking the beginning of an operation.
* **`otel-exporter-otlp-endpoint` (Required):** The base endpoint URL (with an optionally-specified port number) for sending trace data.
* **`otel-exporter-otlp-headers` (Optional):** Custom headers for the OTLP gRPC exporter, formatted as comma-separated values: header1=value1,header2=value2.
* **`otel-resource-attributes` (Optional):** Key-value pairs as resource attributes, formatted as comma-separated values: key1=value1,key2=value2.
* **`otel-service-name` (Required):** The logical name of the service which sets the value of the service.name resource attribute.
* **`run` (Required):** The command to be executed.
* **`shell` (Optional):** Override the default shell settings in the runner's operating system. Supported options are `bash`, `pwsh`, `python`, `sh`, `cmd`, `pwsh`, and `powershell`. Default is `bash`.
* **`step-name` (Required):** The name of the step.

## Integration with GitHub Actions Event Receiver

The **Run with Telemetry** action is ideally used in conjunction with the [GitHub Actions Event Receiver](#). This receiver processes GitHub Actions webhook events to observe workflows and jobs, handling [`workflow_job`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_job) and [`workflow_run`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_run) event payloads, and transforming them into trace telemetry.

Each GitHub Action workflow or job, along with its steps, are converted into trace spans, enabling the observation of workflow execution times, success, and failure rates.

The GitHub Actions Event Receiver ensures data integrity by validating the payload if a secret is configured, as recommended. This validation aligns with GitHub's payload validation process.

Additionally, the **Run with Telemetry** action also supports stand-alone mode when using the `is-root` input parameter, providing flexibility in setup based on your observability requirements.

<img
  src="/assets/images/trace-with-ghaer.png"
  alt="Trace with Github Actions Event Receiver"
  title="Trace with Github Actions Event Receiver"
  style="display: inline-block; margin: 0 auto; max-width: 300px">

## Usage

Define a step in your GitHub Actions workflow YAML file and specify the necessary input parameters to use the **Run with Telemetry** action:

```yaml
name: Build

on:
  workflow_dispatch

env:
  OTEL_EXPORTER_OTLP_ENDPOINT: https://otelcol:4317
  OTEL_RESOURCE_ATTRIBUTES: deployment.environent=dev,service.version=1.0.0
  OTEL_SERVICE_NAME: o11y-tools

jobs:
  build-stuff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run a single-line command with telemetry
        uses: krzko/run-with-telemetry@main
        with:
          otel-exporter-otlp-endpoint: ${{ env.OTEL_EXPORTER_OTLP_ENDPOINT }}
          otel-resource-attributes: ${{ env.OTEL_RESOURCE_ATTRIBUTES }}
          otel-service-name: ${{ env.OTEL_SERVICE_NAME }}
          step-name: Run a single-line command with telemetry
          run: make build

      - name: Run multi-line commands with telemetry
        uses: krzko/run-with-telemetry@main
        with:
          otel-exporter-otlp-endpoint: ${{ env.OTEL_EXPORTER_OTLP_ENDPOINT }}
          otel-resource-attributes: ${{ env.OTEL_RESOURCE_ATTRIBUTES }}
          otel-service-name: ${{ env.OTEL_SERVICE_NAME }}
          step-name: Run multi-line commands with telemetry
          run: |
            cd src
            make build
```
## Environment Variables Injection

The action automatically injects certain environment variables into the shell where the command is being executed. These variables can be utilised by other observability tools to correlate traces across different systems and services. Here are the injected variables:

* **`OTEL_*` Variables:** All `OTEL_*` environment variables specified in the workflow are injected into the shell. These variables are used to configure the OpenTelemetry instrumentation and exporting behavior.

* **`TRACEPARENT`:** This variable contains the trace context of the current span, following the [W3C Trace Context specification](https://www.w3.org/TR/trace-context/). It's a crucial variable for distributed tracing as it enables trace propagation across different systems.

```
TRACEPARENT=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
```

* **`TRACEID:`** This variable holds the trace identifier, a 32-character hexadecimal string which is unique for each trace.

```
TRACEID=0af7651916cd43dd8448eb211c80319c
```

* **`SPANID`:** This variable holds the span identifier, a 16-character hexadecimal string which is unique for each span within a trace.

```
SPANID=b7ad6b7169203331
```

### Example Usage

This example illustrates how the injected environment variables can be utilised within your workflow, particularly with [otel-cli](https://github.com/equinix-labs/otel-cli), to emit additional telemetry:

```yaml
- name: Turtles with otel-cli
  uses: krzko/run-with-telemetry@main
  with:
    otel-exporter-otlp-endpoint: ${{ env.OTEL_EXPORTER_OTLP_ENDPOINT }}
    otel-exporter-otlp-headers: ${{ env.OTEL_EXPORTER_OTLP_HEADERS }}
    otel-resource-attributes: ${{ env.OTEL_RESOURCE_ATTRIBUTES }}
    otel-service-name: ${{ env.OTEL_SERVICE_NAME }}
    step-name: Turtles with otel-cli
    run: |
      pwd
      echo $TRACEPARENT
      otel-cli exec --name "curl httpbin" curl "https://httpbin.org/get"
```

The `otel-cli exec` command captures the `TRACEPARENT` value without requiring explicit setting, enabling seamless additional telemetry emission within the multi-line command. This extended telemetry, aligned with the automatically generated traces from the `run-with-telemetry` action, enriches the observability of the workflow, facilitating better insights into the execution of individual steps and commands.
