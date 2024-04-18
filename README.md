# run-with-telemetry

The **Run with Telemetry** GitHub Action allows you to execute a command on a GitHub Actions runner and export the associated OpenTelemetry trace data to a specified endpoint. This action aims to provide monitoring and observability within your CI/CD pipelines by leveraging OpenTelemetry's tracing capabilities.

This action is intended to be used in conjunction with the [OpenTelemetry Collector GitHub Actions Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/27460). This receiver processes GitHub Actions webhook events to observe workflows and jobs, converting them into trace telemetry for detailed observability.

## Features

* **Execute Commands:** Run a specified command on the GitHub Actions runner.
* **OpenTelemetry Tracing:** Export trace data related to the command execution to a specified OpenTelemetry endpoint.
* **Shell Override:** Choose the shell in which the command will be executed.
* **Resource Attributes:** Define key-value pairs as resource attributes which will be associated with the trace data.
* **Custom Headers:** Define custom headers to be sent along with the OTLP (OpenTelemetry Protocol) gRPC exporter.
* **Environment Variable Injection:** Ability to inject environment variables into the shells, aiding in dynamic command executions.
* **OpenTelemetry Resource Attributes File:** Ability to read a file (`otel_resource_attributes.txt`) for additional OpenTelemetry resource attributes that will be added to the spans generated.

## Usage

### Inputs

| Name                         | Description                                                                                                            | Required |
|------------------------------|------------------------------------------------------------------------------------------------------------------------|----------|
| `job-as-parent`              | If set to `true`, the job will be used as the parent span for the command execution.                                   | Optional |
| `job-name`                   | The name of the job.                                                                                                   | Optional |
| `github-token`               | A token for interacting with the GitHub API.                                                                           | Optional |
| `otel-exporter-otlp-endpoint`| The base endpoint URL (with an optionally-specified port number) for sending trace data.                               | Required |
| `otel-exporter-otlp-headers` | Custom headers for the OTLP gRPC exporter, formatted as comma-separated values: `header1=value1,header2=value2`.       | Optional |
| `otel-resource-attributes`   | Key-value pairs as resource attributes, formatted as comma-separated values: `key1=value1,key2=value2`.                | Optional |
| `otel-service-name`          | The logical name of the service which sets the value of the service.name resource attribute.                           | Required |
| `run`                        | The command to be executed.                                                                                            | Required |
| `shell`                      | Override the default shell settings in the runner's operating system. Supported options are `bash`, `pwsh`, `python`, `sh`, `cmd`, `pwsh`, and `powershell`. | Optional |
| `step-name`                  | The name of the step.                                                                                                  | Required |

### Outputs

| Name       | Description                                              |
|------------|----------------------------------------------------------|
| `trace-id` | The Trace ID generated for the OpenTelemetry trace.      |
| `job-name` | The name of the GitHub Actions job.                      |

## Integration with GitHub Actions Receiver

The **Run with Telemetry** action is ideally used in conjunction with the [OpenTelemetry Collector GitHub Actions Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/27460). This receiver processes GitHub Actions webhook events to observe workflows and jobs, handling [`workflow_job`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_job) and [`workflow_run`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_run) event payloads, and transforming them into trace telemetry.

Each GitHub Action workflow or job, along with its steps, are converted into trace spans, enabling the observation of workflow execution times, success, and failure rates.

The GitHub Actions Receiver ensures data integrity by validating the payload if a secret is configured, as recommended. This validation aligns with GitHub's payload validation process.

Additionally, the **Run with Telemetry** action also supports stand-alone mode when using the `is-root` input parameter, providing flexibility in setup based on your observability requirements.

<img
  src="/assets/images/trace-with-ghaer.png"
  alt="Trace with GitHub Actions Receiver"
  title="Trace with GitHub Actions Receiver"
  style="display: inline-block; margin: 0 auto; max-width: 300px">

## Usage

Define a step in your GitHub Actions workflow YAML file and specify the necessary input parameters to use the **Run with Telemetry** action:

```yaml
name: Build

on:
  workflow_dispatch

env:
  otel-exporter-otlp-endpoint: otelcol.foo.corp:443
  otel-service-name: o11y.workflows
  otel-resource-attributes: deployment.environent=dev,service.version=0.1.0

jobs:
  build-stuff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run a single-line command with telemetry
        uses: krzko/run-with-telemetry@v0.4.0
        with:
          otel-exporter-otlp-endpoint: ${{ env.otel-exporter-otlp-endpoint }}
          otel-resource-attributes: ${{ env.otel-resource-attributes }}
          otel-service-name: ${{ env.otel-service-name }}
          step-name: Run a single-line command with telemetry
          run: make build

      - name: Run multi-line commands with telemetry
        uses: krzko/run-with-telemetry@v0.4.0
        with:
          otel-exporter-otlp-endpoint: ${{ env.otel-exporter-otlp-endpoint }}
          otel-resource-attributes: ${{ env.otel-resource-attributes }}
          otel-service-name: ${{ env.otel-service-name }}
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
