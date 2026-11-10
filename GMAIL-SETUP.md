# Inbox Sentinel Gmail OAuth setup

Use this path for the Gmail backend. Install the plugin in the profile you intend
to use first. If you use a named profile, select the same profile in the GUI and
add `-p YOUR_PROFILE` immediately after `hermes` in every command below; omit it
for the default profile. A connection in another profile or another application
does not grant this plugin access.

## 0) Know what is and is not shared

- A Gmail grant is profile-scoped. A working grant in another Hermes profile does **not** count here.
- The plugin only asks for `gmail.readonly`.
- This setup is for read-only history polling, not sending, archiving, deleting, Calendar, or Drive.
- Do not put secrets in chat, command-line arguments, or shell history.

## 1) Create or choose the Google Cloud project

1. Open [Google Cloud projects](https://console.cloud.google.com/projectselector2/home/dashboard)
   and create a dedicated project for Inbox Sentinel, or select an existing
   project you control. Check that it remains selected for the following steps.
2. Open the [Gmail API page](https://console.cloud.google.com/apis/library/gmail.googleapis.com)
   and choose **Enable**.
3. Open [Google Auth platform](https://console.cloud.google.com/auth/overview):
   use **Branding**, **Audience** and **Data Access** to configure consent.

### OAuth consent screen

Fill in the consent screen details Google asks for:

- App name
- User support email
- Developer contact email
- User type: **Internal** only if every user is inside your Google Workspace org; otherwise **External**
- Test users: add the exact Google accounts that are allowed to authorize while the app is in testing
- Scopes: add only the minimum scope Inbox Sentinel needs, which is `gmail.readonly`

Google limits an external app in **Testing** to its listed test users and expires
its authorisations and refresh tokens after seven days. `gmail.readonly` is a
[restricted scope](https://developers.google.com/workspace/gmail/api/auth/scopes);
the exception for basic identity-only scopes does not apply. For broader external
use without the test-user restriction and unverified-app warnings, follow Google's
verification and publishing requirements. Do not assume verification is automatic.

### Desktop OAuth client

Open [Google Auth platform → Clients](https://console.cloud.google.com/auth/clients),
choose **Create client**, and select **Desktop app**. Name it and create it;
Google displays its client ID and client secret. Keep these private. If you
choose to download the JSON credentials, store the file privately and don't
share or commit it.

Copy the secret with its copy icon when Google first shows it. Later, the client
page shows only a short masked preview (for example `GOCSPX-****abcd`). That
preview is not the secret: a real one is 35 characters. If you no longer have
it, open the client, choose **Add secret**, and copy the new one.

That is the correct client type for this loopback-based desktop flow. Do **not** create a Web application client for this setup.

## 2) Configure the plugin secrets on the host

Use the host's masked settings UI where it exists.

For Inbox Sentinel, the manifest exposes these secret fields:

- `client_id` → `INBOX_SENTINEL_CLIENT_ID`
- `client_secret` → `INBOX_SENTINEL_CLIENT_SECRET`

Paste the Google Cloud Desktop app client ID and client secret into those masked fields in the host UI. Do not pass them on the command line, in a one-line shell export, or in chat.

If the host does not expose a masked settings form, run `hermes config env-path`
on the host to find the selected profile's secrets file (add `-p YOUR_PROFILE`
for a named profile). Open that file in a local text editor, add these two lines
with your own values, then save and close it:

```text
INBOX_SENTINEL_CLIENT_ID=your-client-id
INBOX_SENTINEL_CLIENT_SECRET=your-client-secret
```

Replace the placeholders privately in the editor, not in a shell command or chat.
The file contains other credentials: don't share it, commit it, or print its
contents. Restrict access to your operating-system user. For a remote machine,
edit the profile's file on that machine, not on your laptop.

## 3) Start the Gmail sign-in on the Hermes host

Run the plugin OAuth flow on the machine that owns the Hermes profile:

```bash
hermes auth add inbox-sentinel:gmail --no-browser --timeout 600
```

This prints the sign-in link instead of opening a browser and allows up to ten
minutes for setup. For a named profile, use
`hermes -p YOUR_PROFILE auth add inbox-sentinel:gmail --no-browser --timeout 600`.
Run this in your own terminal, not inside an agent chat or scheduled job.

Hermes will print an authorize URL and a `Waiting for callback on http://127.0.0.1:<port>/callback` line.

### If Hermes and the browser are on the same machine

Open the printed URL in that machine's browser and complete the consent screen normally.

### If Hermes is on a remote host

You need a loopback tunnel from your laptop to the remote host before you open the consent URL. Keep the tunnel open until the login completes.

Single SSH hop:

```bash
ssh -N -L <port>:127.0.0.1:<port> user@remote-host
```

Through a jump box:

```bash
ssh -N -L <port>:127.0.0.1:<port> -J jump-user@jump-host user@final-host
```

Use the exact port Hermes printed on the `Waiting for callback on ...` line; replace
both instances of `<port>` and the SSH account and host placeholders. Start the
tunnel in a **second terminal on the same computer as the browser**, while the
first terminal keeps the auth command running on the host. Once the tunnel is up,
open the printed Google URL in that computer's browser. When sign-in completes,
stop the tunnel with Ctrl+C. If the auth command times out, start it again and
use the newly printed port; a phone SSH session alone may not provide this tunnel.

Hermes's own remote-host guide uses the same loopback pattern: the auth server redirects to `http://127.0.0.1:<port>/callback`, and the tunnel forwards that request back to the remote listener.

## 4) What the Google warning means

If the project is still unverified or in testing, Google may show a warning such as "Google hasn't verified this app".

That warning is about Google's verification state for the OAuth client, not a statement that Inbox Sentinel is malicious. For a first-time setup, check all of the following before continuing:

- the Google account you are signing in with is the one you intended
- the app name and support email on the consent screen match your project
- the requested scope is only `gmail.readonly`
- the account is listed as a test user if the app is still in Testing

If the account is not a test user and the project is in Testing, stop and fix the project settings instead of clicking through.

## 5) Verify the grant

After consent completes, verify the grant on the same Hermes profile:

```bash
hermes auth status inbox-sentinel:gmail
```

You want to see `logged in` for this profile. For a named profile, run
`hermes -p YOUR_PROFILE auth status inbox-sentinel:gmail`. This checks the saved
grant, not whether a live Gmail poll or push delivery has succeeded.

## 6) Turn the watcher on

1. Keep `provider: gmail`.
2. Keep `enabled: false` while you finish setup.
3. Set `delivery_target` to a real configured `hermes send` target.
4. If you want `delivery_target: push`, make sure the Hermes mobile push integration is installed and configured first.
5. Set `enabled: true`.
6. Start a Hermes session or send a new turn; installing the plugin alone does not start polling.

Useful checks:

- `inbox_sentinel_status` shows watcher state, last poll and the last error; use
  `hermes auth status inbox-sentinel:gmail` separately to check the saved grant.
- `inbox_sentinel_test` checks classification and drafting only; it does **not** prove Gmail connectivity or notification delivery.

The first poll only establishes a baseline. It does not alert on mail that was already in the inbox before the watcher started.

## 7) Troubleshooting

### Consent flow opens but callback never arrives

- The remote tunnel is missing or pointing at the wrong port.
- The tunnel was closed before the callback returned.
- The browser is hitting the wrong machine's `127.0.0.1`.

### Google says the app is unverified or in testing

- Add your account to the test-user list if the app is in Testing.
- Expect the 7-day refresh-token expiry while it stays in Testing.
- If you need broader use, complete Google's verification flow for the OAuth client.

### You got a "not watching your inbox" alert

- The Gmail sign-in is missing, expired or revoked. In Testing mode Google ends it
  after seven days. Run step 3 again for the same profile.
- The watcher retries every 5 minutes and resumes by itself after sign-in.

### Sign-in fails with `invalid_client` (HTTP 401)

Google accepted the consent but refused the client secret. The saved secret is
wrong or incomplete; a common cause is copying the short masked preview. Add a
new secret to the same client, save it in the profile's secrets file and run
step 3 again.

### `hermes auth status` shows no Gmail grant

- Re-run `hermes auth add inbox-sentinel:gmail` on the correct Hermes profile.
- Confirm the Desktop app client ID and secret were entered in the plugin's masked secret fields.
- Confirm the project uses `gmail.readonly` and Gmail API is enabled.

### Push delivery does not arrive on the phone

- `delivery_target: push` only works when the Hermes mobile push integration is installed and configured.
- The watcher may be on but delivery may still be pointed at another configured `hermes send` target.
- A working Gmail grant does not prove push is configured.

### The app is authorized, but mail still looks quiet

- The first poll is baseline-only.
- The message may have been filtered locally by `quiet_labels` or sender rules.
- `inbox_sentinel_test` is only a sample classifier; it does not read live mail.

## 8) Short version

1. Create a Google Cloud project.
2. Enable Gmail API.
3. Configure the OAuth consent screen.
4. Add test users if the app is still in Testing.
5. Create a **Desktop app** OAuth client.
6. Paste the client ID and secret into the host's masked Inbox Sentinel settings.
7. Run `hermes auth add inbox-sentinel:gmail` on the correct Hermes profile.
8. Use SSH local forwarding if Hermes is remote.
9. Verify with `hermes auth status inbox-sentinel:gmail`.
10. Enable the watcher, start a session and check `inbox_sentinel_status`.
