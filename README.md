# run-with-telemetry

GitHub Action `run` action with OpenTelemetry instrumenation 


## Usage

**WORK IN PROGRESS - DO NOT USE**

A GitHub Action `run` command with OpenTelemetry instrumenation for distributed tracing.

## Usage

...

```yaml
name: Do Awesome Stuff

on:
  workflow_dispatch

env:
  OTEL_EXPORTER_OTLP_ENDPOINT: https://otelcol:4317
  OTEL_RESOURCE_ATTRIBUTES: foo=bar,baz=qux
  OTEL_SERVICE_NAME: o11y-tools

jobs:
  build-stuff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run with OTel (single line)
        uses: krzko/run-with-telemetry@main
        with:
          otel-exporter-otlp-endpoint: ${{ env.OTEL_EXPORTER_OTLP_ENDPOINT }}
          otel-resource-attributes: ${{ env.OTEL_RESOURCE_ATTRIBUTES }}
          otel-service-name: ${{ env.OTEL_SERVICE_NAME }}
          command: ls -la 

      - name: Run with OTel (multi line)
        uses: krzko/run-with-telemetry@main
        with:
          otel-exporter-otlp-endpoint: ${{ env.OTEL_EXPORTER_OTLP_ENDPOINT }}
          otel-resource-attributes: ${{ env.OTEL_RESOURCE_ATTRIBUTES }}
          otel-service-name: ${{ env.OTEL_SERVICE_NAME }}
          command: |
            export FOO="foo"
            echo "hello $FOO"
            echo "world"
```
