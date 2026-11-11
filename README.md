# Inbox Sentinel

**Inbox Sentinel surfaces email that matters in your Hermes workflow.**

Inbox Sentinel supports Gmail history polling and generic IMAP over TLS, with
optional draft replies for mail that deserves your attention.

Designed to work especially well with the **new Hermes app by Nous Research,
currently in beta**. Other configured `hermes send` targets (Telegram, Discord,
Slack, ...) are also supported.

## Providers

Two mail backends, pick whichever fits your account:

| Provider | Setup | Good for |
| --- | --- | --- |
| `gmail` *(default)* | Google Cloud OAuth client + one `hermes auth add` | Gmail users — polls history deltas every 15 seconds by default, then classifies and can draft a reply |
| `imap` | Host, user, and password/app password in the masked settings UI when available | Servers that accept password or app-password login over TLS, including Gmail with an [app password](https://myaccount.google.com/apppasswords) |

The IMAP backend is **experimental**: it is tested against a scripted local TLS
server, not yet against a real provider. Some servers report message sizes that
differ from what they send; this version skips such messages with a warning.
Keep your normal notifications on while you try it.

Both run the same pipeline — local noise filter → importance gate → draft reply → delivery.
Set `provider: imap` and the `imap_*` fields; the Gmail OAuth step is skipped
entirely.

## What you get

- **Filtered alerts.** The ping your phone receives can skip newsletters,
  marketing, and other routine mail — and each alert can arrive with a draft
  reply you can review.
- **Backend setup.** Gmail uses OAuth; IMAP uses host credentials or app
  passwords. Enter secrets in the masked host UI when it exists, never in chat.
- **Predictable polling.** Gmail history is checked every 15 seconds by default; IMAP
  uses the configured poll interval.
- **Local noise filtering.** Promotions and social labels are skipped locally before
  any model call.
- **An importance gate with taste.** What survives the local filter is classified by the
  model you already run — tuned by a plain-language description of *your* priorities.
- **Replies drafted for review.** Important messages can arrive with a first-person
  draft reply, ready to paste, edit or discard.
- **Bounded model calls.** Classification attempts default to 100 per day; pending
  mail defers when that cap is reached. Draft attempts have a separate cap. Failed
  model calls consume those limits too. Token prices still depend on your provider.

## Quick start

1. **Install first:**

   ```bash
   hermes plugins install eddwithers/inbox-sentinel
   hermes plugins enable inbox-sentinel
   ```

   Local development does not use `plugins install /path`: place a copy of the plugin
   under your test home's `plugins/inbox-sentinel/` directory, as described in the
   Hermes plugin developer guide, then validate and enable it there.
   Configure it before starting a new session; keep watcher setting `enabled`
   false until you are ready to connect and deliver alerts.

2. **Pick the backend.** Gmail needs your own Google Cloud OAuth client
   (type *Desktop app*). IMAP needs a server accepting password or app-password
   login over TLS. Choose `provider: gmail` or `provider: imap`.

   Full first-time Gmail setup lives in [GMAIL-SETUP.md](GMAIL-SETUP.md):
   Google Cloud project, consent/test users, Desktop client, masked host
   secrets, SSH callback tunnel, grant verification, refresh-token expiry,
   and push prerequisites.

3. **Enter secrets in the masked host UI, not chat.** Use the installed plugin's
   settings form where exposed. Gmail uses a client ID and client secret; IMAP
   uses host, username and password/app password. If your host does not expose
   masked secret fields, use its normal secure local configuration path.

   For **Gmail only**, run `hermes auth add inbox-sentinel:gmail` and complete
   Google's consent flow. On a remote host the callback listens on that host's
   loopback address; tunnel the printed callback port from your browser's machine
   to the Hermes host before opening the consent URL. See the
   [OAuth over SSH guide](https://hermes-agent.nousresearch.com/docs/guides/oauth-over-ssh).
   A phone-only SSH session may not provide the required tunnel. IMAP skips OAuth.
   Do not copy browser profiles or automate consent.

4. **Choose delivery and priorities.** `push` requires the mobile-push integration
   to be installed and configured for your Hermes app, in the same profile.
   It is a platform plugin, so that profile needs `plugins.isolation: in_process`
   (the Hermes default); a profile set to `host` cannot load push. Otherwise use another
   configured `hermes send` destination. Set priorities in the settings form or
   `config.yaml`, for example:

   ```yaml
   plugins:
     entries:
       inbox-sentinel:
         settings:
           enabled: false
           provider: gmail
           importance_profile: >-
             Client bookings, invoices, medical appointments, and parcels.
             Skip routine newsletters and social-media updates.
           delivery_target: push
   ```

5. **Enable and verify.** Set the watcher setting `enabled: true`, then start a
   session or send a new turn. Installing alone does not start polling. The first
   poll establishes a baseline; it does not alert on the existing backlog.
   Check `inbox_sentinel_status` and test with controlled demonstration mail.
   `inbox_sentinel_test` exercises classification/drafting only, not connectivity
   or notification delivery, and may make paid model calls. Keep normal critical
   email notifications on until the complete chain is proven for your account.

Email content is sent to whichever model service you configure in Hermes; a
cloud model means that provider processes the message text. Only use a local
model if you require local-only inference. Alerts and suggested replies may also
be stored in the destination's history and synced by its service.

## It learns from you

Tell your agent, in plain words, when it gets one wrong — right in the chat where the
alert landed:

- *"Mail from deals@example.test is noise"* → that exact address is filtered
  locally while its rule is retained (or until cleared).
- *"Mail from @example.test is important"* → that exact domain bypasses quiet
  labels, with your reason supplied to the gate. Subdomains are not included.
- *"Clear the rule for deals@example.test"* → rules for that identifier are cleared.

Display names and substrings are not accepted. Legacy substring rules no longer
match and must be re-entered as exact addresses or explicit `@domain` rules.
The `From` header is still spoofable: sender preferences are not authentication
and must never authorise payments, tool use or other actions.

Corrections live in your profile's plugin state, capped and tidy, and the counts show in
`inbox_sentinel_status`.

## How it works

```
Gmail history API or IMAP poll ──▶ local noise filter ──▶ LLM importance gate ──▶ your alerts
```

| Surface | Used for |
| --- | --- |
| `ctx.spawn_task` | supervised background poll loop (auto-cancelled on plugin unload) |
| `oauth:` + `credentialed_provider_request` | Gmail access with a Hermes-owned, profile-scoped grant — the plugin never touches a token |
| `ctx.llm` + `register_auxiliary_task` | importance gate (`complete_structured`) and reply drafts (`complete`) through two plugin-owned model slots that follow your main model until you pin them |
| `ctx.state` | atomic, profile-scoped durable state (cursor, seen-set, budget) that survives plugin updates |
| `hermes send --to push` | native mobile-app push delivery (any `hermes send` target works) |

Read-only by design: the plugin holds the `gmail.readonly` scope and never sends,
labels, archives or deletes your mail.

### Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Run the watcher (turn on after setup) |
| `provider` | `gmail` | `gmail` (OAuth history API) or `imap` (generic poll) |
| `gmail_query` | *(empty)* | Optional Gmail search scope checked before message metadata/body/model access; use a narrow label or subject query |
| `imap_host` | *(empty)* | IMAP server hostname (provider=imap) |
| `imap_port` | `993` | IMAP server port (993 = IMAPS) |
| `imap_ssl` | `true` | Use IMAPS (TLS); STARTTLS-only and remote plaintext setups are unsupported |
| `imap_user` | *(empty)* | IMAP username / full email address |
| `imap_password` | *(secret, env `INBOX_SENTINEL_IMAP_PASSWORD`)* | IMAP password or app password |
| `imap_folder` | `INBOX` | IMAP folder (mailbox) to watch |
| `poll_interval_seconds` | `15` | Seconds between polls (min 5) |
| `delivery_target` | `push` | Configured out-of-band `hermes send` target, or `none`; live session injection is refused |
| `importance_profile` | *(generic)* | Plain-language description of what matters to you |
| `draft_replies` | `true` | Pre-draft replies for important mail |
| `daily_gate_cap` | `100` | Classification attempts/day (0–1000); pending mail defers at the limit |
| `daily_draft_cap` | `15` | Draft attempts/day, including failures |
| `quiet_labels` | promotions, social | Gmail labels skipped before any model call (ignored for IMAP) |
| `keyword_overrides` | appointment, invoice, ... | Subject words that override the quiet labels |
| `skip_recipient_keywords` | *(empty)* | Recipient substrings to ignore (old aliases) |

### Choosing the models

The importance gate and the reply drafts each run in their own auxiliary model
slot: `inbox_sentinel_gate` and `inbox_sentinel_draft`. Unpinned, both use your
main Hermes model. To use a cheaper, faster model for the gate, pin it in the
`hermes model` auxiliary picker, the dashboard Models page, or `config.yaml`:

```yaml
auxiliary:
  inbox_sentinel_gate:
    provider: your-provider
    model: your-fast-model
```

The slots belong to this plugin. It cannot use another plugin's slots or the
built-in Hermes slots. Daily attempt caps apply whichever model you pick.

### Drafting limits

Attachment metadata is detected, but attachment contents are **not read** in this
version. If an attachment is present or referenced in the body or subject, the
plugin withholds the reply draft and marks the alert **No reply drafted — contents
not reviewed**. It does not claim the file is missing, ask the sender to resend it,
or claim it has read it. Empty and truncated bodies also withhold drafts. Transient
provider failures can enter the bounded retry path. Messages that exceed parsing
limits are not drafted; a general warning is attempted at most once per day.

This is a deterministic pre-model guard, not just a prompt instruction. It is
conservative: an attached signature image or an incidental attachment mention can
also withhold a draft. Body-only messages can still receive draft suggestions;
all suggestions require human review and are never sent automatically.

### Runtime verification

The isolated-host lifecycle test preserves the product registration and runs the
actual supervised watcher loop. It verifies session-triggered start, automatic
retry on a later poll, no duplicate watcher on repeat hooks, stopping on disable,
resuming after enable plus a lifecycle event, and cancellation on unload. Gmail
responses are fictional and network/notification paths are blocked in that test.
This does not prove external delivery, real IMAP operation, or a long-duration soak.

The watcher starts on a session lifecycle event, not merely installing the plugin.
Re-enabling it requires another session-start or turn event to start it again.
In process, it runs on its own long-lived event loop, so it keeps polling after
the chat turn that started it ends. After you update the plugin, restart the
gateway (`hermes gateway restart`): in-process hooks stay wired until then.

### Live test, 10 November 2026

On a dedicated test Gmail account, through the Hermes multiplex gateway, with
fictional mail sent from a separate address:

- Hermes-managed Gmail sign-in (`gmail.readonly`) with a user-owned Desktop client.
- First poll recorded a baseline; existing mail raised no alerts.
- New mail was discovered automatically through Gmail history. A newsletter
  stayed quiet; a booking request raised an alert with a suggested reply; a
  message that said it had an attachment raised an alert without a draft.
- One message went from arrival to a phone lock-screen notification in the
  Hermes app in about 14 seconds. Opening it showed the summary and the reply.

This is one account and a handful of messages over a short session, not a soak
test or a guarantee for every mailbox.

### Reliability notes

Born from a production system that has watched a real inbox daily, including a few
very educational failures:

- A message that fails processing is retried **at most 3 times**. The watcher
  then attempts a failure notification and marks it seen; if delivery itself is
  unavailable, that notification can fail too. Check your inbox and watcher status.
- Drafts are capped per day; over the cap you still get summaries, just no drafts.
- The Gmail history cursor is persisted and reinitialised on expiry. Mail received
  during a gap can be missed when the baseline is rebuilt; check your inbox.
- If the watcher cannot reach the mailbox, it says so. A missing or rejected
  Gmail sign-in (Google ends Testing-mode sign-ins after seven days), or 4 failed
  checks in a row, sends one "not watching your inbox" alert per day to your
  delivery target. Gmail sign-in problems are retried every 5 minutes. With
  `delivery_target: none`, or if delivery also fails, only
  `inbox_sentinel_status` shows the problem.
- The gate defaults to **NOISE** when the model returns anything unparseable — an
  occasional missed alert beats a stream of false ones.

## Privacy and runtime disclosures

- Gmail calls go to `gmail.googleapis.com`; Hermes manages the Google OAuth grant
  and refresh via Google's declared endpoints. IMAP connects to your configured
  server over TLS using the password/app password supplied through Hermes's
  profile secret scope. Neither path reads a separate credential store.
- A long-running task begins on a session lifecycle event and polls until
  disabled or unloaded. IMAP socket operations have a 30-second timeout;
  synchronous operations within a worker thread may finish after cancellation.
- Message text is processed by your configured Hermes model provider. That may
  be a remote service and incur charges. There is no plugin telemetry.
- Alerts use a child process invoking `hermes send` with an argument list, not a
  shell. Alert text is passed as an argument, so it may be visible to local
  process inspection. The destination may store or sync summaries and drafts.
- Cursor, deduplication, failure counters, draft counters and sender feedback
  live in Hermes's profile-scoped plugin state. Sender feedback itself contains
  email addresses and optional user notes.
- There is no automatic email sending, archival or deletion. Suggestions require
  human review. Read-only application behaviour is not a substitute for a
  provider-issued read-only IMAP credential where one is available.

## Development and verification

See [TESTING.md](TESTING.md) for reproducible no-account tests and their limits.
See [SECURITY.md](SECURITY.md) for boundaries, limits and release checks.
Requires Hermes v0.23.0 or later (`requires_hermes: ">=0.23.0"`). That is the
only tested release; the plugin-owned model slots need a recent host API.
Mobile push requires the separate configured push integration.

## License

MIT
