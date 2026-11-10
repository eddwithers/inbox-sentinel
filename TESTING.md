# Testing Inbox Sentinel

Tests use fictional mail. No real account or model key is required. Integration
coverage uses the real Hermes isolated plugin host and real loopback IMAP/TLS
sockets; it does not certify an external provider or phone delivery.

## Prerequisites

- A Hermes source checkout with its test environment prepared using that
  checkout's documented package-management workflow.
- `openssl` on PATH for the local TLS certificate fixture.
- An interpreter with Hermes and the test dependencies available. The repository
  adds no runtime dependencies beyond Hermes and the Python standard library.

## Run

From the **Hermes source checkout**, use its canonical test runner with the
absolute path to this plugin's tests. Do not run these against a production home:

```bash
HERMES_CLI_ROOT="$PWD" \
HERMES_PYTHON="/absolute/path/to/test-environment/bin/python" \
HERMES_TEST_FILE_RETRIES=0 \
scripts/run_tests.sh /absolute/path/to/inbox-sentinel/tests -q
```

Then run the catalog/runtime gates:

```bash
hermes plugins validate /absolute/path/to/inbox-sentinel
hermes plugins doctor /absolute/path/to/inbox-sentinel --ci
```

The lifecycle fixture creates its own temporary home, blocks external network and
notification delivery, and prevents dependency provisioning in its child host.
The TLS fixture generates a throwaway local certificate and verifies both trusted
and untrusted cases. Test certificates and keys are never committed.

## What passing means

- Deterministic parsing, filtering, feedback, bounded message retries and drafting
  safeguards behaved as asserted with fictional model responses.
- Host registration, session-triggered task lifecycle and persistent state worked
  in the installed Hermes test runtime.
- IMAP wire semantics, TLS checks and failure paths worked against a scripted
  loopback server using real `imaplib` connections.

It does **not** prove a Gmail grant, a compatible external IMAP account, a real
model's judgement, delivery to a phone or a long-duration unattended soak. Those
are separate opt-in acceptance tests; keep personal mail and secrets out of
fixtures, logs, public commits and demo recordings.
