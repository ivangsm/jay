---
title: Quickstart
description: Run Jay, create a token and store your first object in about a minute.
---

This gets you from nothing to a stored object. It assumes Docker; see
[Install](/jay/install/) for the other options.

## 1. Start the server

Both secrets are required and must be at least 32 characters. Jay refuses to
start without them — there is no default and no development fallback.

```bash
export JAY_ADMIN_TOKEN=$(openssl rand -base64 32)
export JAY_SIGNING_SECRET=$(openssl rand -base64 32)

docker run -d --name jay \
  -p 9000:9000 -p 127.0.0.1:9001:9001 \
  -v jay_data:/data \
  -e JAY_ADMIN_TOKEN -e JAY_SIGNING_SECRET \
  ghcr.io/ivangsm/jay:latest
```

Port `9000` is the S3 API and the only one meant to face an untrusted network.
Port `9001` is the admin API and the health probes, bound to loopback here on
purpose.

Check that it came up:

```bash
curl -fsS http://localhost:9001/health/ready && echo ready
```

## 2. Create an account and a token

The admin API mints credentials. Nothing else can.

```bash
ACCOUNT=$(curl -fsS -X POST http://localhost:9001/_jay/accounts \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"myapp"}' | jq -r .account_id)

curl -fsS -X POST http://localhost:9001/_jay/tokens \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"account_id\":\"$ACCOUNT\",\"name\":\"deploy\",
       \"allowed_actions\":[\"bucket:write-meta\",\"object:put\",\"object:get\",\"object:list\"]}"
```

`allowed_actions` is **required** — Jay will not mint a token that does not say
what it may do. The four above are what the rest of this page needs. The full
list is in [Authentication](/jay/reference/authentication/), and `["*"]` grants
all of them.

The response carries `token_id` and `secret`. **The secret is shown once** — it
is bcrypt-hashed before storage and cannot be read back.

```bash
export TOKEN_ID=...      # from the response
export TOKEN_SECRET=...  # from the response
```

If you would rather not make this call on every fresh deployment, Jay can create
an account and token at startup from environment variables. See
[Seed token](/jay/reference/seed-token/).

## 3. Store something

With `curl`, using the bearer form:

```bash
AUTH="Authorization: Bearer $TOKEN_ID:$TOKEN_SECRET"

curl -fsS -X PUT -H "$AUTH" http://localhost:9000/media
curl -fsS -X PUT -H "$AUTH" --data-binary @photo.jpg \
  http://localhost:9000/media/photo.jpg
curl -fsS -H "$AUTH" http://localhost:9000/media/photo.jpg -o roundtrip.jpg

cmp photo.jpg roundtrip.jpg && echo "identical"
```

Or with the AWS CLI, which needs no special configuration beyond the endpoint:

```bash
aws configure set aws_access_key_id "$TOKEN_ID"
aws configure set aws_secret_access_key "$TOKEN_SECRET"
aws configure set default.region us-east-1

aws --endpoint-url http://localhost:9000 s3 cp photo.jpg s3://media/
aws --endpoint-url http://localhost:9000 s3 ls s3://media/
```

## Where to go next

- [The S3 API](/jay/guides/s3-api/) — what works with which client.
- [The native protocol](/jay/guides/native-protocol/) — if your caller is Go.
- [Configuration](/jay/reference/configuration/) — every variable Jay reads.
- [Deploying Jay](/jay/guides/deployment/) — TLS, proxies and backups.
