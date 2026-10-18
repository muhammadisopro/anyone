# Anyone backend — integration in progress

This backend has no Telegram API, account, phone-number or MTProto dependency. It uses native Cloudflare Worker APIs, Turso's HTTP API, private R2 storage and SQLite Durable Objects. No new application dependency is added.

**The inherited Web A frontend is not connected to this backend yet. Do not publish that frontend as an independent messenger.** This branch is the backend foundation, not a completed migration. Legacy login, icons, internal title updates, localization, API adapter, cache isolation and Telegram links still need replacement. Premium checkout is not implemented.

## Services and secrets

1. Create a Turso database named `anyone`. Obtain its database URL and database auth token (not a platform/account token).
2. Apply `server/migrations/001_initial.sql` to that database, for example through the Turso CLI: `turso db shell anyone < server/migrations/001_initial.sql`. Apply once to a fresh database.
3. Enable Cloudflare R2 and create a **private** bucket named `anyone-media`. Do not enable public access. R2 requires billing setup even when using the free allowance.
4. Deploy the Worker using the Cloudflare Wrangler CLI and `server/wrangler.jsonc`. The configured `MEDIA` binding accesses R2 without S3 credentials; `EVENTS` creates the SQLite Durable Object namespace.
5. Set `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` as Worker secrets. Never use frontend environment variables for these values. Set `APP_ORIGIN` to the exact frontend origin with no trailing slash.
6. Host frontend and API under the same site (for example `anyone.example` and `api.anyone.example`). Session cookies use `HttpOnly`, `Secure` and `SameSite=Strict`; unrelated `pages.dev` and `workers.dev` hostnames are not a supported production cookie deployment.

CLI commands (Wrangler is deployment tooling, not an app dependency):

```sh
wrangler login
wrangler secret put TURSO_DATABASE_URL --config server/wrangler.jsonc
wrangler secret put TURSO_AUTH_TOKEN --config server/wrangler.jsonc
wrangler deploy --config server/wrangler.jsonc
```

For local development copy `server/.dev.vars.example` to `server/.dev.vars`. This file is gitignored. Use Wrangler's local R2 simulation rather than production media.

## API

All authenticated requests use the session cookie (`credentials: 'include'` in the browser). JSON payloads are limited to 16 KB. Usernames are 4–32 ASCII letters/numbers/underscores starting with a letter; passwords are 12–128 characters.

| Method | Route | Body / result |
|---|---|---|
| GET | `/health` | Anyone service identity |
| POST | `/auth/register` | `{username, password, displayName}`; creates account and session |
| POST | `/auth/login` | `{username, password}`; creates session |
| POST | `/auth/logout` | Revokes session and closes user event sockets |
| GET | `/me` | User identity and server-calculated video limit |
| GET | `/chats` | Current user's first 100 chat memberships |
| POST | `/chats` | `{kind: 'direct' or 'group', usernames: [...], title?}` |
| GET | `/chats/:id/messages?before=cursor` | Latest 50 messages; use oldest `cursor` for the next page |
| POST | `/chats/:id/messages` | `{text?, attachmentId?}` |
| POST | `/chats/:id/videos` | Raw video body with Content-Type and Content-Length |
| GET | `/media/:id` | Private video playback, including byte ranges |
| GET | `/events` | Authenticated, receive-only WebSocket events |

Video limits are decimal MB: **50,000,000 bytes** for standard and **100,000,000 bytes** while `users.premium_until` is in the future (Unix milliseconds). The client cannot grant itself Premium. Supported declared types are MP4, WebM and MOV. Streaming enforces actual byte length as well as the declared length. File content inspection/transcoding is not implemented. Do not send multipart/form-data to the video route.

Chat history is the source of truth. WebSocket notifications are best effort; reconnecting clients must refetch history. No external chat discovery, channel import or Telegram authentication exists in this backend.

## Before public release

Complete the original UI adapter and independent auth screens; replace the legacy bootstrap and caches so they cannot initiate Telegram connections. Add account recovery, membership management, abuse controls, per-account storage quotas, orphan-upload cleanup, billing entitlements and monitoring. Load-test against the actual target concurrency and media traffic. No 1,000-user capacity claim is verified yet.

Verification performed: Node syntax validation; initial migration applied to in-memory SQLite; HTTP smoke checks for health, unauthenticated access and CORS. Real Turso/R2/Durable Objects integration and full browser flows require provisioned services and remain unverified.

The inherited project's GPL license and copyright notices remain in place.
