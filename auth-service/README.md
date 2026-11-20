# auth-service

User accounts and authentication for the YIEMN platform: signup, login, rotating refresh tokens, logout, and profile (including an icon: preset or photo). Rust (axum + tokio), DynamoDB, Docker, Kubernetes.

Built to scale horizontally to millions of users: the service is stateless, every database access is a single-key lookup, and other services verify access tokens locally without calling this one.

## Quick start

```bash
# Zero dependencies (in-memory store):
make run-memory
# Full stack with DynamoDB Local:
make up
# Tests (no AWS needed):
make test
```

The Docker image builds from the code in the GitHub repo (`ggamble22/YIEMN_server`), not your local files. It uses `main` by default. To build another branch, tag or commit, set `GIT_REF`:

```bash
GIT_REF=my-branch docker compose up --build                       # bash
$env:GIT_REF="my-branch"; docker compose up --build              # PowerShell
docker build -t auth-service --build-arg GIT_REF=my-branch .      # image only
```

Local changes must be pushed to GitHub before a Docker build sees them. For a quick local loop, use `cargo run` / `cargo test` instead.

```bash
curl -s localhost:8080/v1/auth/signup -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery","display_name":"Ada","role":"student"}'
```

## API

All errors share one shape: `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Auth | Body | Success |
|---|---|---|---|---|
| POST | `/v1/auth/signup` | – | `email, password, display_name, role?, icon?` | 201 user + tokens |
| POST | `/v1/auth/login` | – | `email, password` | 200 user + tokens |
| POST | `/v1/auth/refresh` | – | `refresh_token` | 200 new token pair |
| POST | `/v1/auth/logout` | – | `refresh_token` | 204 |
| POST | `/v1/auth/logout-all` | Bearer | – | 204 |
| GET | `/v1/users/me` | Bearer | – | 200 user |
| PATCH | `/v1/users/me` | Bearer | `display_name?`, `icon?` | 200 user |
| PUT | `/v1/users/me/photo` | Bearer | raw image bytes (JPEG/PNG/WebP, ≤ 5 MiB) | 200 user |
| GET | `/v1/users/icons` | – | – | 200 `{"icons": [...], "photo_upload_enabled": true}` |
| GET | `/v1/photos/{key}` | – | – | 200 `image/jpeg` (the URL in a user's `icon`) |
| GET | `/healthz` | – | – | liveness |
| GET | `/readyz` | – | – | readiness (checks DynamoDB) |
| GET | `:9090/metrics` | – | – | Prometheus (separate port, never public) |

Roles: `student` (default), `parent`, `educator`. `admin` cannot be self-assigned.

**Icons.** A user's icon is optional and is either a preset or a photo:

```json
"icon": null
"icon": { "type": "preset", "id": "owl" }
"icon": { "type": "photo",  "url": "https://cdn.example.com/v1/photos/avatars/<user>/<random>.jpg" }
```

- **Preset:** pick from `GET /v1/users/icons` (`fox`, `owl`, `rocket`, …); the frontend maps each id to artwork. Set at signup (`"icon": "owl"`) or with `PATCH /v1/users/me`. Change the set with `USER_ICONS`.
- **Photo:** `PUT /v1/users/me/photo` with the image file as the body:
  ```bash
  curl -X PUT localhost:8080/v1/users/me/photo -H "authorization: Bearer $TOKEN" \
    -H 'content-type: image/jpeg' --data-binary @me.jpg
  ```
  Uploading again replaces the photo.
- **Remove / switch:** `PATCH /v1/users/me` with `"icon": null` or `"icon": "fox"`. Leaving `icon` out keeps it. The old photo is deleted from storage whenever it is replaced or removed.

What happens to an uploaded photo:
1. **Re-encoded from raw pixels.** This strips all metadata, including **EXIF GPS location**, which matters when a child takes a selfie at home. It also means we only ever store and serve a plain JPEG, never the uploaded bytes.
2. **Auto-rotated, centre-cropped and resized** to 256×256 (~10–30 KB).
3. **Screened** with AWS Rekognition content moderation (nudity, violence, drugs, hate symbols…). A flagged photo returns `422 photo_rejected` and is never stored. The reason is deliberately not shown, so the filter can't be probed.
4. **Stored** in a private S3 bucket under a fresh random key. Keys can't be guessed or enumerated, and objects are immutable, so they're cached forever.

Errors: `400` for unreadable or unsupported images, or images smaller than 64×64 or larger than 6000×6000; `413` if over `PHOTO_MAX_BYTES`; `403` if the user's role isn't in `PHOTO_ICON_ROLES`. Decoding runs on the blocking pool behind a per-pod limit (`MAX_CONCURRENT_PHOTO_JOBS`), with decoder memory caps against decompression bombs.

Token response:

```json
{ "access_token": "eyJ…", "refresh_token": "<user>.<session>.<secret>", "token_type": "Bearer", "expires_in": 900 }
```

## How it works

**Access tokens** are HS256 JWTs (15 min) with `sub` (user id), `role`, `iss`, `exp`, `jti`. Any service in the ecosystem validates them with the shared secret, so auth never becomes a per-request bottleneck.

**Refresh tokens** are opaque, 256-bit random, and rotate on every use. Only a SHA-256 of the secret is stored. Replaying an already-used token is treated as theft and revokes that session for everyone holding it. Rotation is a conditional write, so two concurrent refreshes can't both win.

**Passwords** use Argon2id. Hashing runs on the blocking thread pool behind a semaphore so login spikes can't stall the async runtime or blow up pod memory. Login always runs a hash, even for unknown emails, and returns the same 401 for every failure, so attackers can't tell which emails exist.

### DynamoDB layout (single table)

| Item | `pk` | `sk` |
|---|---|---|
| User profile (incl. `icon` preset id **or** `icon_photo_key`) | `USER#<id>` | `PROFILE` |
| Email reservation | `EMAIL#<email>` | `EMAIL` |
| Session | `USER#<id>` | `SESSION#<session_id>` |

Photos themselves live in S3, not DynamoDB. Signup writes the profile and email reservation in one transaction, which is how email uniqueness is guaranteed. Expired sessions are removed by DynamoDB TTL at no cost. There are no scans or GSIs; all reads are point lookups or a query within one user's partition.

### Code map

```
src/
  main.rs            startup, metrics server, graceful shutdown
  lib.rs             router + middleware stack
  config.rs          env-var config
  routes/            HTTP handlers (auth, users, health)
  auth/              passwords, JWTs, refresh tokens, AuthUser extractor
  repo/              Repo trait + DynamoDB and in-memory implementations
  media/             photo processing, storage (S3 / memory), moderation (Rekognition / off)
  aws.rs             shared AWS SDK config
  middleware/        rate limiting, Prometheus metrics
tests/api.rs         end-to-end API tests
```

Handlers only see the `Repo`, `PhotoStore` and `Moderator` traits, so the storage engine can change without touching business logic, and tests run in milliseconds against the in-memory store.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `JWT_SECRET` | **required** | ≥ 32 bytes. `openssl rand -base64 48` |
| `STORAGE_BACKEND` | `dynamodb` | `memory` for local hacking only |
| `DYNAMODB_TABLE` | `auth` | |
| `DYNAMODB_ENDPOINT` | – | e.g. `http://localhost:8000` for DynamoDB Local |
| `AWS_REGION` | – | Credentials come from the standard AWS chain (IRSA in EKS) |
| `JWT_ISSUER` | `auth-service` | Validated on every token |
| `ACCESS_TOKEN_TTL_SECS` | `900` | |
| `REFRESH_TOKEN_TTL_SECS` | `2592000` | 30 days, sliding |
| `RATE_LIMIT_PER_MINUTE` | `30` | Per IP on signup/login/refresh, per pod. `0` disables |
| `TRUST_FORWARDED_FOR` | `false` | Use right-most `X-Forwarded-For` hop. Enable only behind one trusted proxy |
| `CORS_ALLOWED_ORIGINS` | – | Comma-separated |
| `MAX_CONCURRENT_HASHES` | CPUs × 2 | Argon2 concurrency cap per pod |
| `USER_ICONS` | 16 built-in ids | Comma-separated icon ids (a-z, 0-9, `-`). Removing one is safe: clients fall back to a default |
| `PHOTO_STORAGE` | `s3` | `memory` for local runs only |
| `PHOTO_BUCKET` | – | Required when `PHOTO_STORAGE=s3` |
| `S3_ENDPOINT` | – | For S3-compatible stores (MinIO, LocalStack) |
| `PHOTO_PUBLIC_BASE_URL` | `/v1/photos` | Prefix of photo URLs given to clients. In production, a CDN in front of `/v1/photos` |
| `PHOTO_MAX_BYTES` | `5242880` | Upload limit (5 MiB). Keep the ingress body size above this |
| `PHOTO_MODERATION` | `rekognition` | `off` for local runs only — never in production |
| `PHOTO_MODERATION_MIN_CONFIDENCE` | `60` | Rekognition label confidence (0–100) that rejects a photo. Lower = stricter |
| `PHOTO_ICON_ROLES` | all roles | Who may upload photos, e.g. `parent,educator`. Everyone can still use presets |
| `MAX_CONCURRENT_PHOTO_JOBS` | `2` | Image decodes per pod (each up to ~100 MiB) |
| `BIND_ADDR` / `METRICS_ADDR` | `0.0.0.0:8080` / `:9090` | |
| `LOG_FORMAT` | `json` | `pretty` for local |

## Deploying

1. `infra/terraform`: creates the table (on-demand, TTL, point-in-time recovery, encryption, deletion protection), a private encrypted S3 bucket for photos, and a least-privilege IAM role for IRSA (DynamoDB, the bucket's `avatars/` prefix, and Rekognition moderation).
2. Put the role ARN in `k8s/serviceaccount.yaml`, your image in `k8s/kustomization.yaml`, your domain in `k8s/ingress.yaml`, and the bucket name and photo URL base in `k8s/configmap.yaml`.
3. Put a CDN (e.g. CloudFront) in front of `https://<your-domain>/v1/photos/*` with your ingress as the origin, and set `PHOTO_PUBLIC_BASE_URL` to the CDN URL. Photos are immutable and sent with `Cache-Control: immutable`, so the CDN serves almost all photo traffic.
4. Create the secret: `kubectl -n auth create secret generic auth-service --from-literal=JWT_SECRET="$(openssl rand -base64 48)"`.
5. `kubectl apply -k k8s/`.

The deployment runs ≥ 3 replicas spread across zones, autoscales on CPU (3–60 pods), uses a PodDisruptionBudget, zero-downtime rolling updates, drains connections on SIGTERM, and runs as non-root with a read-only filesystem in a distroless image.

## Scaling to 1M+ users

- **Storage**: 1M users ≈ 1M profile + 1M email items, a few hundred MB. DynamoDB on-demand handles this with single-digit-ms latency and no tuning; it scales far beyond 1M.
- **Traffic**: with 15-min access tokens, 100k concurrently active users generate roughly 110 refreshes/s. Each refresh is 3 small DynamoDB operations. API requests elsewhere in the platform never touch this service.
- **The real cost is Argon2**: roughly 20–50 logins/s per CPU core. The HPA adds pods when CPU passes 65%, and the semaphore keeps each pod's memory flat during spikes.
- **Photos**: 1M users with photos ≈ 1M × ~25 KB ≈ 25 GB in S3 (well under $1/month). Uploads are rare and cost one decode (~50–200 ms CPU) plus one Rekognition call (~$1 per 1,000 images). Reads go through the CDN. Ask clients to downscale to ~1024 px before upload, which makes uploads faster and cheaper.
- **Rate limiting** is per pod. The ingress limit gives a global ceiling; for strict global limits, move the counter to Redis/ElastiCache or use AWS WAF rate rules.

## Before production

- **Children's data.** The platform serves kids. In the US, collecting personal data from under-13s requires verifiable parental consent (COPPA); the EU/UK have similar rules. This service does not yet collect birthdates or model parent–child links. Decide the policy (e.g. age gate at signup, parent-managed child accounts) before launch.
- **Photos of children are personal data.** Under COPPA, a photo of a child under 13 counts as personal information, so it needs verifiable parental consent before collection. Until parental consent exists, consider `PHOTO_ICON_ROLES=parent,educator`. Students still get preset icons, which the frontend can offer as the default.
- **Photo visibility.** Photo URLs are public-but-unguessable: anyone who is given a URL can view it. That's standard for avatars, but if child photos should only be visible to signed-in users or classmates, switch to short-lived signed URLs.
- **Reporting and takedown.** Automated moderation misses things. Add a "report this photo" flow and an admin action that clears a user's icon (clearing already deletes the stored object).
- **Email verification and password reset** are not implemented. Both need an email provider (e.g. SES) and short-lived single-use tokens stored like sessions.
- **Key rotation / asymmetric signing.** If third parties will verify tokens, switch to EdDSA/RS256 and publish a JWKS endpoint so services never hold a signing secret.
- **Account deletion** (`DELETE /v1/users/me`) for data-protection requests.
