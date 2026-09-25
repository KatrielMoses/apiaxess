# Reference target — ground-truth request manifest

Every HTTP request `pro.mailaccess.reference` (v1.0.0) can make. This table is the source of truth
that fidelity tests score APIaxess's recovered surface against. The machine-readable copy is
[`ground-truth.json`](ground-truth.json); keep the two in sync with the source.

- **First-party host:** `mailaccess.pro` (HTTPS). **Third-party host:** `jsonplaceholder.typicode.com`.
- **Common header:** every first-party request made through the shared OkHttp client (all Retrofit and
  raw-OkHttp calls) carries `X-App-Platform: android`, added by an interceptor in `Network.kt`.
- **IDs** match the `E##` tags the app writes to logcat (`adb logcat -s MailAccessRef`) as each call
  completes, e.g. `E04 -> 404`. That confirms a call fired without instrumenting the network.

| ID | Method | Host | Templated path | Query | Body (JSON) | Extra headers | Construction style | Trigger |
|----|--------|------|----------------|-------|-------------|---------------|--------------------|---------|
| E01 | GET | mailaccess.pro | `/api/v1/status` | — | — | — | Retrofit `suspend` | launch |
| E02 | GET | mailaccess.pro | `/api/v1/users/{id}` | — | — | — | Retrofit `suspend`, `@Path` | launch |
| E03 | GET | mailaccess.pro | `/api/v1/users` | `page`, `sort` | — | — | Retrofit `suspend`, `@Query` | launch |
| E04 | POST | mailaccess.pro | `/api/v1/users` | — | `{name, email}` | — | Retrofit `suspend`, `@Body` data class | tap **Create user** |
| E05 | PUT | mailaccess.pro | `/api/v1/users/{id}` | — | `{name, email}` | — | Retrofit `suspend`, `@Path` + `@Body` | tap **Update user** |
| E06 | DELETE | mailaccess.pro | `/api/v1/users/{id}` | — | — | — | Retrofit `suspend`, `@Path` | tap **Delete user** |
| E07 | GET | mailaccess.pro | `/api/v1/search` | `q` | — | — | Retrofit `suspend`, `@Query` | tap **Search** |
| E08 | GET | mailaccess.pro | `/api/v1/mailboxes/{mailboxId}/messages` | `limit`, `before` | — | `X-Client-Version` | Retrofit `suspend`, `@Path` + `@Query` + `@Header` | opening **Settings** (tap **Open settings**) |
| E09 | GET | mailaccess.pro | `/api/v1/config` | — | — | — | OkHttp, `BASE_URL + CONFIG_PATH` (both `const`) | launch |
| E10 | POST | mailaccess.pro | `/api/v1/events` | — | `{event, screen, ts}` | `X-Request-Id` | OkHttp, `BASE_URL + "/api/v1/events"`, `JSONObject` body | launch |
| E11 | GET | mailaccess.pro | `/api/v1/orders/{orderId}/items` | — | — | — | OkHttp, string template `"$BASE_URL/…/$orderId/items"` | tap **Load order** |
| E12 | GET | mailaccess.pro | `/api/v2/reports` | `from`, `to` | — | — | OkHttp `HttpUrl.Builder` (scheme/host/`addPathSegments`/`addQueryParameter`) | tap **Reports** |
| E13 | DELETE | mailaccess.pro | `/api/v1/sessions/{sessionId}` | — | — | — | OkHttp, `BASE_URL + "/api/v1/sessions/" + sessionId` | Settings → tap **Clear session** |
| E14 | POST | mailaccess.pro | `/graphql` | — | `{operationName, query, variables{id}}` — `query GetProfile` | — | OkHttp, hand-written GraphQL (no Apollo) | tap **Load profile** |
| E15 | GET | mailaccess.pro | `/api/v1/health` | — | — | — | `HttpURLConnection`, full URL literal | launch |
| E16 | PUT | mailaccess.pro | `/api/v1/settings/notifications` | — | `{email, push}` | `X-App-Platform` (set explicitly) | `HttpURLConnection`, `BASE_URL + path`, `setRequestMethod("PUT")` | Settings → tap **Save settings** |
| E17 | GET | jsonplaceholder.typicode.com | `/todos/{id}` | — | — | — | Retrofit blocking `Call<T>`, second Retrofit instance | launch |

**Concrete values on the wire** (what a dynamic capture sees): `{id}` = `42` (E02/E05/E06) and `1` (E17),
`{mailboxId}` = `inbox`, `{orderId}` = `ord_9f2c`, `{sessionId}` = `sess_7d1e`; E03 `?page=1&sort=name`,
E07 `?q=invoice`, E08 `?limit=20&before=2026-09-25T00:00:00Z`, E12 `?from=2026-09-01&to=2026-09-30`.
The non-numeric path parameters (`inbox`, `ord_9f2c`, `sess_7d1e`) are deliberate. From one dynamic
observation they can't be distinguished from literal segments, so templating them relies on static
evidence or on repeated observations.

**Totals:** 17 requests. 16 first-party, 1 third-party. By style: Retrofit 9, OkHttp 6 (including GraphQL),
HttpURLConnection 2. By trigger: launch 7, one tap on the home screen 6, Settings screen 4 (opening it fires
E08; E13/E16 need a second tap).

**Negative space (precision).** The app makes no other requests. Any other `mailaccess.pro` or
`jsonplaceholder.typicode.com` endpoint in a recovered surface is a phantom. Android system or
emulator background traffic (connectivity checks and similar) doesn't come from this app and is
outside the manifest.
