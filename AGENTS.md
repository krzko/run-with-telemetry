# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

A GitHub Action that runs a shell command and emits an OpenTelemetry trace for
the step, correlated with jobs/workflows via deterministic trace/span IDs. It
is designed to pair with the [OpenTelemetry Collector GitHub Actions
Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/githubreceiver),
which turns [`workflow_job`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_job)
and [`workflow_run`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_run)
webhook events into spans that must line up with the IDs this action generates.

Key references:

- [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector)
- [OpenTelemetry Semantic Conventions](https://github.com/open-telemetry/semantic-conventions)
- [OpenTelemetry Semantic Conventions for CI/CD](https://opentelemetry.io/docs/specs/semconv/registry/attributes/cicd/)
- [GitHub Actions Receiver (opentelemetry-collector-contrib)](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/githubreceiver)
- [GitHub Actions webhook events](https://docs.github.com/en/webhooks/webhook-events-and-payloads)
- [GitHub REST API: Workflow Jobs](https://docs.github.com/en/rest/actions/workflow-jobs)

## Architecture

- `action.yaml` — the Action manifest (`node20` runtime, calls `index.js`).
- `index.js` — a thin dispatcher: picks the OS/arch-matching binary from
  `bin/` and `spawnSync`s it. GitHub Actions cannot invoke a native binary
  directly, so this shim is required. Don't put logic here.
- `cmd/run-with-telemetry/main.go` — the entire program: input parsing,
  trace/span ID derivation, OTLP exporter setup, command execution, span/event
  emission. Single-file `main` package; keep it that way unless it grows
  enough to justify splitting into internal packages.
- `bin/` — prebuilt, UPX-compressed binaries per OS/arch, built via
  `Taskfile.yml` (`go build` + `upx --best --lzma`). Regenerate, don't
  hand-edit.

Trace/span IDs are **not** random — they're SHA-256 derivations of
`(run ID, run attempt, job name, step name)` so that this action and the
GitHub Actions Receiver independently compute the same IDs for the same
webhook payload. Any change to the hashing inputs/format in
`generateTraceID`/`generateJobSpanID`/`generateStepSpanID` is a breaking
change for correlation and must stay in lockstep with the receiver's ID
derivation.

## Principles for changes here

- **Single Responsibility**: keep input parsing, span-ID derivation, tracer
  init, and command execution as separate functions (as they are today) even
  inside one file. Don't collapse them for brevity.
- **Dependency direction**: `main.go` depends on the OTel SDK and GitHub API
  client, not the reverse. If this grows, extract an interface at that
  boundary (e.g. a small `github client` or `tracer` interface) before adding
  a second implementation — not preemptively.
- **Testable by construction**: functions that can be pure (ID generation,
  input parsing, attribute-map building) should stay pure — no direct
  `githubactions.*` I/O calls inside them — so they're unit-testable without
  a GitHub Actions runner. There are currently no `_test.go` files; new pure
  logic should ship with tests rather than growing that gap further.
- **No speculative abstraction**: this is a small, single-purpose binary. Don't
  introduce plugin systems, extra interfaces, or config layers for
  hypothetical future exporters/protocols.
- Keep `action.yaml` inputs/outputs, `README.md`, and `main.go`'s
  `InputParams`/`parseInputParams` in sync — they're the same contract
  described three times.

## Build & release

- `Taskfile.yml` cross-compiles for all supported OS/arch combos and runs
  `upx` on each binary before packaging. If `upx` isn't installed, per-target
  builds will fail at the compression step, not the build step.
- Version metadata (`BUILD_VERSION`, `BUILD_DATE`, `COMMIT_ID`) is injected via
  `-ldflags`, not hardcoded.
