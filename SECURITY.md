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

## IS-ScamShield (scam signals)

A deterministic substring check (password-protected PDF attachment;
`undisclosed-recipients:;`) runs on subject, body and recipient headers before
the importance gate, at zero model cost. A hit forces a POSSIBLE SCAM warning
alert regardless of the model verdict — including when the gate is unavailable
or over budget — names the signals, includes the summary or an untrusted body
excerpt, and never drafts a reply. Authentication results are not scam evidence
and never clear a hit: compromised legitimate mailboxes pass SPF/DKIM/DMARC.
The check is pure detection, separate from alert shaping; the read-only contract
means a hit triggers no archive, label, report or delete action. It is a
heuristic for two known lure shapes with literal-substring and 4,000-character
body limits, not a general phishing detector. False positives (e.g. legitimate
password-protected bank statements) are expected; the warning re-labels mail,
it never suppresses it.

The check runs as a first-party module (`modules/scamshield.py`) behind a
host-enforced boundary: modules receive a bounded API — namespaced state,
declared shared-state reads, trusted config reads and pure host helpers. No
transport, credentials, delivery or raw `ctx.llm`: model calls go through the
host's budgeted seam only (`llm_complete`), which reserves the same daily
draft cap as the host draft path, counts failed calls, and returns nothing
over cap — a module can never spend unbudgeted. A failing or disabled module
degrades to host-default behaviour and never crashes the poll loop.
Third-party module loading is deliberately not supported.

IS-AttachmentGuard and IS-LinkGuard extend the same warning path with
deterministic attachment-metadata and URL heuristics: attachment contents are
never read, URL analysis is offline and bounded (50 URLs, no reputation
feeds), and both over-warn by design. IS-StormShield suppresses
identical-repeat alert storms (same sender, subject and body hash within a
configurable window); first arrivals always alert, transport retries never
count, different bodies never suppress each other, and security warnings
outrank suppression. Storm state is namespaced and bounded.

IS-Drafter and IS-AlertShaper run on the post_gate stage. The drafter's model
requests go through the budgeted seam above (one shared daily draft cap with
the host fallback path; exhaustion yields summary-only alerts, never a
bypass). The alert shaper is first-party code, but every untrusted field it
renders still passes the host's sanitisation helper, and its output is pinned
byte-identical to the host fallback. POSSIBLE SCAM shaping stays host-owned
and does not depend on any module. If either module is disabled or fails, the
host's proven draft/shaping path applies unchanged; the sample tool keeps the
host draft path.

## Multiple accounts and mode consent

The account registry contains connection metadata and declared credential
references, never credential values. Invalid nonblank settings stop polling;
blank settings alone select legacy mode. Explicit [] or all-disabled entries
poll nothing. Disabled accounts are enforced host-side even if InboxSwitch
is disabled or broken. Unknown fields and duplicate Gmail grant mappings are
rejected. Four Gmail declarations share readonly scopes and OAuth client
settings but use distinct profile-owned grants; extra IMAP secrets are resolved
only through the profile secret scope. A fixed four-account cap bounds this
release; no dynamic manifest mutation or cross-profile credential access occurs.

State is namespaced by validated account id. A stored connection fingerprint
rejects changing that id's connection; using a new id creates a new baseline.
The host cannot identify a mailbox silently substituted inside an OAuth grant:
when signing a grant into a different mailbox, use a new account id too.
Account labels are sanitised before delivery. Per-account targets are trusted
configuration, never email- or module-controlled routing. Modules cannot read
the registry, credentials or host connection settings through config_get.
These first-party Python modules are not an adversarial code sandbox.

Gate/draft budgets remain profile-global, including failed calls. Learned
sender rules also remain profile-global; separate profiles are required for
separate trust domains. Storm suppression keys include the account id.
Per-account failure/backoff does not mark another account's mail seen.

Mode presets only select shipped readonly modules. The desk_pa name is a
preview bundle, not calendar/archive/label capability or migration of existing
automation. Modules declaring scopes beyond gmail.readonly are refused until
an explicit consent mechanism exists. No mailbox write scope is requested.

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
