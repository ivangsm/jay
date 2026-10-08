---
title: Web console
description: A browser UI on the admin port for accounts, tokens, buckets, policies, quarantine and objects. Off by default.
---

Jay ships a web console: a single-page UI, embedded in the binary, served by the
admin listener under `/console/`. It covers what you would otherwise do with
`jay-admin` and `curl`: accounts, tokens, buckets, bucket policy and visibility,
quarantine, and browsing, uploading and downloading objects.

It is a thin layer. It adds no storage, no database and no secret of its own,
and it has no authorization rules for your data: every action is either an
[admin API](/jay/reference/admin-api/) call or an ordinary S3 request that the
S3 handler decides on.

## Turning it on

The console is **off by default**. An upgrade does not open a new login page on
your admin port unless you ask for it.

```bash
JAY_CONSOLE_ENABLED=true ./jay
```

or, in the [YAML file](/jay/reference/configuration/#yaml-file):

```yaml
console:
  enabled: true
```

Then open `http://localhost:9001/console/` (`/` on the admin port redirects
there). While the console is off, `/console/` answers `404` with the variable to
set — a plain-text hint for API clients, a short page for browsers. Nothing else
under `/console/` is reachable, and `/` stays a `404`.

## Signing in

The console has one credential: `JAY_ADMIN_TOKEN`. There are no users, roles or
SSO.

Signing in exchanges the admin token for a **server-side session**. The browser
holds only an opaque cookie (`HttpOnly`, `SameSite=Strict`; `Secure` and the
`__Host-` prefix when the admin port serves TLS) and never sees the admin token
again. Sessions live in memory:

- they end after 30 minutes without use, or 8 hours in all;
- at most 32 are open at once — a new sign-in evicts the least recently used;
- signing out revokes the session for real, and **restarting jay ends every
  session**, which is also how a rotated `JAY_ADMIN_TOKEN` takes effect.

Wrong tokens count against the same per-address backoff as the admin API: after
five failures an address is refused for 15 minutes, right token included.

## Browsing as a token

The console can list and read every bucket's metadata, but it never reads or
writes object bytes with the admin token. Objects are reached by choosing a
token to **browse as**. Each request is then signed as that token (a presigned
request that lives 60 seconds) and sent to the same S3 handler any client uses.

So what you can see and do in the object browser is exactly what that token
could do over S3: its account, its allowed actions, its bucket and prefix scope,
the bucket policy, and cross-account rules all apply. A `403` from the S3 handler
is shown as a `403`. A revoked or expired token, or one whose account is not
active, is explained before the request is made.

Create a narrow token (see [Authentication](/jay/reference/authentication/)) if
you want to see a bucket the way a given client sees it.

## Limits

- **Uploads** up to 64 MiB are one request; larger files go as a multipart upload
  in parts of at least 16 MiB, three at a time, with one retry per part.
  Anything above `JAY_MAX_OBJECT_SIZE` is refused by jay, as it is for any client.
- **Downloads** go through the admin listener, which gives a response five
  minutes to finish. For objects over 1 GiB the console warns you and offers a
  share link that points at the S3 port directly.
- **Previews** are images up to 10 MiB and the first 64 KiB of text. Nothing else
  is rendered.
- **Request bodies** to the admin API through the console are capped at 1 MiB
  (a bucket policy is limited to 64 KiB anyway).
- **Rate limits** are the S3 handler's: the console is one more client, and a
  `429` is shown with its `Retry-After`.
- Not offered, because jay does not have them: versioning, lifecycle, tagging,
  ACLs, CORS, rename or move, recursive bucket delete, and account or token
  rotation. Graphs belong to Prometheus: see [Observability](/jay/reference/observability/).

## Security

The page is built so that a stored XSS cannot become admin access.

- **No inline script or style.** The page's CSP allows scripts and styles only
  from the console's own origin (`script-src 'self'; style-src 'self'`, no
  `unsafe-inline`), and `frame-ancestors 'none'`.
- **Object bytes are never rendered by the console's origin.** Every object
  response is `Content-Disposition: attachment`, `nosniff`, and carries
  `Content-Security-Policy: sandbox; default-src 'none'`. Image previews go
  through a `blob:` URL; text previews are inserted as text, never as HTML.
- **CSRF.** Every `/console/api/` call is checked against the browser's
  `Sec-Fetch-Site` and `Origin` headers, and anything that changes state also
  needs the per-session CSRF token, sent in the `X-Jay-Console-CSRF` header.
- **Credentials do not travel.** The proxy forwards a short allow-list of
  headers; the cookie, the CSRF token and any `Authorization` the browser sent
  are dropped.
- **Every change leaves an audit line**, with the same `request_id`, `action` and
  `remote_ip` fields as the admin API: `console.login`, `console.logout`, and
  `console.s3` for each object write (bucket, key, the token browsed as). Admin
  changes made through the console are audited by the admin API itself.

**The console speaks plain HTTP unless you give the admin port TLS.** Signing in
sends the admin token over that connection. Keep `JAY_ADMIN_ADDR` on loopback and
reach it through an SSH tunnel, set `JAY_TLS_CERT` and `JAY_TLS_KEY`, or put a
TLS-terminating proxy in front. With the console enabled and an admin address
that is not loopback and no TLS, jay logs a `WARN` at startup saying so. Behind a
proxy that terminates TLS but talks HTTP to jay, the cookie is not marked
`Secure`: the proxy has to enforce HTTPS.

Anyone who gets a working session has admin power until it ends, so treat the
admin port as you already do: never on an untrusted network.

## Verifying the console

The repository carries a smoke test that starts two real jay instances, one with
the console off and one with it on, and drives the second with `curl`:

```bash
make console-smoke
```

Each step does something through `/console/` and then confirms the effect by
another road — the native client (`jay ls`, `jay cp`) or the admin API with the
bearer token — rather than trusting the console's own answer. It prints `PASS` or
`FAIL` for each check and exits non-zero at the first failure.
