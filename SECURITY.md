# Security model

## Boundaries

Incoming email and model output are **untrusted data**, never authority to run
commands, change settings or send email. The importance gate and drafter receive
no plugin tools, account secrets, session transcript or memory contents. They see
bounded message text plus the configured priorities and user-entered sender notes.
A model can still be deceived: human review of any suggestion remains necessary.

The watcher only delivers out-of-band notifications through a configured
`hermes send` destination. **Live `ctx.inject_message` delivery and automatic
fallback to it are not supported.** The sample tool cannot send notifications.
Delivery children bind an explicit profile and strip inherited active-session and
YOLO routing variables. Their output is discarded, and cancellation/timeout kills
and reaps a still-running child. Text passed on argv may be visible to local
process inspection. Notification destinations can store/sync the alert, and some
may show previews on a lock screen; choose a private destination and device settings.

Opening an alert in an app is not the same as granting it trusted status. If you
ask an agent to work with the alert later, it must still treat its contents as
untrusted. This plugin cannot enforce the behaviour of other plugins or future
agent turns. It does not claim universal prompt-injection immunity.

## Accounts and transport

- Gmail declares only `gmail.readonly`. Hermes handles OAuth tokens, refresh and
  the API host allowlist. The plugin neither reads token files nor borrows another
  tool's credentials.
- IMAP passwords come through Hermes's active profile secret scope. Remote IMAP
  requires verified IMAPS/TLS. No `CERT_NONE`, STARTTLS downgrade or remote
  plaintext mode. Plaintext is limited to literal loopback IP test fixtures.
- IMAP uses read-only selection and `BODY.PEEK`, never `STORE` or `EXPUNGE`.
- IMAP socket operations run off the event loop. Cancellation waits for an
  in-flight operation before logout, preventing concurrent use of `imaplib`.
  Connect cancellation retrieves and closes a returned client even when worker
  completion races cancellation. Individual socket operations use a 30-second
  timeout; orderly cancellation can therefore be delayed, and this is not a
  total wall-clock guarantee against a malicious server or stalled resolver.
- A provider-issued IMAP password may still have broader rights: read-only code
  is not a server-enforced read-only grant. Use dedicated/revocable credentials.
- Local configuration is trusted: it selects the model, server, executable and
  notification target. Malicious local plugins/configuration or a compromised
  Hermes runtime are outside this plugin's security boundary.

## Input and resource limits

- Raw-message parsing limit: **262,144 bytes**. Oversized/unknown-size messages
  do not reach the model; one static resource warning/day asks you to review the
  mailbox. Messages skipped this way are not automatically reprocessed later.
- Parser construction caps multipart depth at 12 and total parts at 100, using a
  bounded stdlib feed parser. Test this against supported Python runtimes; the
  parser's internal extension seam is not a public Hermes API.
- Gmail preflights `sizeEstimate` and rejects oversize base64 before decoding.
  Google may still return a larger HTTP response before the plugin checks it;
  there is no streaming response cap in the managed request surface used here.
- IMAP preflights `RFC822.SIZE` and uses bounded partial fetches. These checks
  assume a protocol-compliant server. A malicious IMAP server can lie about
  literal sizes before `imaplib` gives the plugin bytes; don't configure an
  untrusted server.
- Classification defaults to **100 attempts/day**, maximum configurable 1,000.
  Failed calls consume the cap. At the limit, messages defer rather than being
  marked seen or burning transport retries. Review your mailbox while paused.
- Draft attempts default to 15/day (configurable up to 100); failed calls count.
  Reservations are serialised within one loaded plugin process, not a distributed
  lock across multiple independently launched Hermes processes. Run one watcher
  per account/profile. Processing is bounded to 20 messages/tick. These are
  call/token limits, not a fixed currency guarantee.
- Inbox listing/history discovery is not a streaming mailbox synchronisation
  engine. Huge listings/queues remain a resource limitation; use a scoped mailbox
  or folder and normal mail notifications for critical communication.

## Identity, rendering and privacy

Sender preferences match canonical exact addresses or explicit `@domain` values.
No display-name/substring matching, and domains do not implicitly match subdomains.
**A matching From header is not proof of identity**: this plugin does not perform
independent SPF/DKIM/DMARC verification or authorise actions based on preferences.

Gate output must match the expected object/verdict/string limits; unknown verdicts
and unexpected fields fail closed. Output controls strip control/bidirectional
characters and neutralise common Markdown, mention and link syntax. Display text
may differ from original punctuation; consult the original email before replying.
These controls reduce accidental rendering tricks; they do not certify every
notification renderer against every Unicode or markup edge case.

No automatic email sending, archive or delete. Unread attachments, empty and
truncated bodies prevent drafting. Model summaries may still be wrong.
Configured cloud models receive message text and may incur charges. Hermes state
retains sender preferences/cursors/counters; notification services retain alerts
under their policies. Plugin logs omit message subjects, sender addresses and raw
provider error bodies in the hardened paths. Hermes/provider logging has its own
policy. There is no plugin telemetry.

## Release checks

Require fictional adversarial regression tests, canonical Hermes test runner,
`hermes plugins validate`, `hermes plugins doctor --ci`, and a clean publication
snapshot with an explicit file manifest and credential-pattern review. Retain
private development history separately if old bytecode/local paths must not ship.
A passing scanner or model-assisted code review is not a professional independent
audit, penetration-test certificate or guarantee of safety.

Do not post suspected secret exposure or exploit payloads in public issues.
Privately contact the repository owner through a verified GitHub contact method
before public disclosure. No security-response SLA is promised for this beta.
