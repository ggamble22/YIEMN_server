# auth-service

User accounts and authentication for the YIEMN platform: signup, login, rotating refresh tokens, logout, and profile. Rust (axum + tokio), DynamoDB, Docker, Kubernetes.

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

```bash
curl -s localhost:8080/v1/auth/signup -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery","display_name":"Ada","role":"student"}'
```

## API

All errors share one shape: `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Auth | Body | Success |
|---|---|---|---|---|
| POST | `/v1/auth/signup` | – | `email, password, display_name, role?` | 201 user + tokens |
| POST | `/v1/auth/login` | – | `email, password` | 200 user + tokens |
| POST | `/v1/auth/refresh` | – | `refresh_token` | 200 new token pair |
| POST | `/v1/auth/logout` | – | `refresh_token` | 204 |
| POST | `/v1/auth/logout-all` | Bearer | – | 204 |
| GET | `/v1/users/me` | Bearer | – | 200 user |
| PATCH | `/v1/users/me` | Bearer | `display_name` | 200 user |
| GET | `/healthz` | – | – | liveness |
| GET | `/readyz` | – | – | readiness (checks DynamoDB) |
| GET | `:9090/metrics` | – | – | Prometheus (separate port, never public) |

Roles: `student` (default), `parent`, `educator`. `admin` cannot be self-assigned.

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
| User profile | `USER#<id>` | `PROFILE` |
| Email reservation | `EMAIL#<email>` | `EMAIL` |
| Session | `USER#<id>` | `SESSION#<session_id>` |

Signup writes the profile and email reservation in one transaction, which is how email uniqueness is guaranteed. Expired sessions are removed by DynamoDB TTL at no cost. There are no scans or GSIs; all reads are point lookups or a query within one user's partition.

### Code map

```
src/
  main.rs            startup, metrics server, graceful shutdown
  lib.rs             router + middleware stack
  config.rs          env-var config
  routes/            HTTP handlers (auth, users, health)
  auth/              passwords, JWTs, refresh tokens, AuthUser extractor
  repo/              Repo trait + DynamoDB and in-memory implementations
  middleware/        rate limiting, Prometheus metrics
tests/api.rs         end-to-end API tests
```

Handlers only see the `Repo` trait, so the storage engine can change without touching business logic, and tests run in milliseconds against the in-memory store.

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
| `BIND_ADDR` / `METRICS_ADDR` | `0.0.0.0:8080` / `:9090` | |
| `LOG_FORMAT` | `json` | `pretty` for local |

## Deploying

1. `infra/terraform`: creates the table (on-demand, TTL, point-in-time recovery, encryption, deletion protection) and a least-privilege IAM role for IRSA.
2. Put the role ARN in `k8s/serviceaccount.yaml`, your image in `k8s/kustomization.yaml`, your domain in `k8s/ingress.yaml`.
3. Create the secret: `kubectl -n auth create secret generic auth-service --from-literal=JWT_SECRET="$(openssl rand -base64 48)"`.
4. `kubectl apply -k k8s/`.

The deployment runs ≥ 3 replicas spread across zones, autoscales on CPU (3–60 pods), uses a PodDisruptionBudget, zero-downtime rolling updates, drains connections on SIGTERM, and runs as non-root with a read-only filesystem in a distroless image.

## Scaling to 1M+ users

- **Storage**: 1M users ≈ 1M profile + 1M email items, a few hundred MB. DynamoDB on-demand handles this with single-digit-ms latency and no tuning; it scales far beyond 1M.
- **Traffic**: with 15-min access tokens, 100k concurrently active users generate roughly 110 refreshes/s. Each refresh is 3 small DynamoDB operations. API requests elsewhere in the platform never touch this service.
- **The real cost is Argon2**: roughly 20–50 logins/s per CPU core. The HPA adds pods when CPU passes 65%, and the semaphore keeps each pod's memory flat during spikes.
- **Rate limiting** is per pod. The ingress limit gives a global ceiling; for strict global limits, move the counter to Redis/ElastiCache or use AWS WAF rate rules.

## Before production

- **Children's data.** The platform serves kids. In the US, collecting personal data from under-13s requires verifiable parental consent (COPPA); the EU/UK have similar rules. This service does not yet collect birthdates or model parent–child links. Decide the policy (e.g. age gate at signup, parent-managed child accounts) before launch.
- **Email verification and password reset** are not implemented. Both need an email provider (e.g. SES) and short-lived single-use tokens stored like sessions.
- **Key rotation / asymmetric signing.** If third parties will verify tokens, switch to EdDSA/RS256 and publish a JWKS endpoint so services never hold a signing secret.
- **Account deletion** (`DELETE /v1/users/me`) for data-protection requests.
