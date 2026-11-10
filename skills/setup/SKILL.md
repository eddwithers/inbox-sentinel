---
name: setup
description: "Inbox Sentinel Gmail/IMAP setup with masked secrets."
---

# Inbox Sentinel setup

Goal: configure Gmail or IMAP alerts without asking for secrets in chat.
Use the host's masked settings UI whenever it exists.

## 1) Pick the path

- Use the profile where the user installed Inbox Sentinel. Grants are profile-scoped.
- A grant in another Hermes profile or another application does **not** count here.
- Run `hermes auth status inbox-sentinel:gmail` for the selected profile to check its grant.
- If you are setting up Gmail from scratch, follow `GMAIL-SETUP.md` end to end.
- If the account supports IMAP username/password or app-password login over TLS, you can use the IMAP path instead.

## 2) Enter secrets in the host UI, not chat

- Use the host's masked settings form whenever it exists.
- Gmail: enter the Google Cloud OAuth client ID and secret from your own **Desktop app** client.
- IMAP: enter host, username, and password/app password only for providers that allow password login over TLS. STARTTLS-only and remote plaintext setups are unsupported.
- If the host UI does not expose masked secret fields, stop and use the environment's normal secure config path. Do not ask the user to paste secrets into chat.
- Do not copy browser profiles or use browser automation hacks.

## 3) Gmail browser auth

- Run `hermes auth add inbox-sentinel:gmail` on the Hermes host for the profile you actually want to use.
- The callback listener runs there; the browser can be elsewhere if its callback port is tunnelled.
- On a local desktop, complete the printed Google consent flow normally.
- On a remote host, wait for the callback port printed by the command; forward that port from the browser's machine to the Hermes host before opening the URL.
- Do not assume a phone-only SSH session supplies that tunnel.
- IMAP skips this OAuth step entirely.

## 4) Before Google consent: explain the warning

Google may show "Google hasn't verified this app" or a Testing-mode warning for a user-owned Google OAuth client that has not completed verification.
Explain this before sign-in, not after it surprises the user.

Tell the user to check the selected account, app/developer identity and requested permissions.
Inbox Sentinel's Gmail path should request read-only mail access only: `gmail.readonly`.
A narrow `gmail_query` is a plugin filter, not a restriction on the OAuth grant's mailbox-wide read permission.

Never click through consent or bypass a warning for the user.
If identity or permissions do not match, stop and investigate.
If the expected personal/test client is unverified, the user must make the informed decision to proceed.
Workspace policy or test-user rules may block access; do not work around them.

## 5) Finish setup

- Set `importance_profile` in plain language.
- Keep `provider` as `gmail` or `imap` as appropriate.
- Use `delivery_target: push` only when the mobile-push integration is installed and configured for the Hermes app beta in this same profile, and the profile uses `plugins.isolation: in_process` (push cannot load in the plugin host); otherwise use another configured target.
- After updating the plugin, restart the gateway so old in-process hooks are dropped.
- Keep the watcher setting `enabled` false while configuring.
- When ready, set it true and start a session or send a turn; installation alone does not start polling.
- Check `inbox_sentinel_status` for connection errors.
- `inbox_sentinel_test` only samples classification/drafting; it does not test mail connectivity or send a notification.
- Verify those with controlled demo mail.
- First poll establishes a baseline, not a backlog alert.
- Keep critical-mail notifications on until the complete chain is tested.
- Explain that the default classification cap is 100 attempts/day, with pending mail deferred at the cap. Failed model calls count too; review normal mail while paused. Draft attempts default to 15/day.
- Sender feedback needs an exact email address or explicit `@domain.test`, not a name/substring. A matching From header is a preference, never authentication.
- Live `session` delivery is refused: email must stay outside active agent context.
- Optional: pin a small, fast model for the importance gate in the auxiliary slot `inbox_sentinel_gate` (and `inbox_sentinel_draft` for drafts). Unpinned, both use the main model.
- Tell the user about the "not watching your inbox" alert: sent at most once a day when Gmail sign-in is missing or expired, or after 4 failed checks in a row. In Google Testing mode the sign-in ends after seven days; then run `hermes auth add inbox-sentinel:gmail` again.
- Explain that configured cloud models receive message text. Alerts may also be stored or synced by the configured delivery service.

## Guardrails

- Never print secrets.
- Never promise phone-only OAuth sign-in for Gmail.
- Never promise instant delivery; Gmail polls history every 15 seconds by default.
- Never promise Graph-only or IMAP-only support.
- Never say an existing grant in some other profile covers the current one.
