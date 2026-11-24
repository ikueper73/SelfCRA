# CRA Self Assessment Helper – risk assessment and technical documentation

A web application for the product-level obligations of **Regulation (EU) 2024/2847 (Cyber Resilience Act)**. It covers **consumer** and **commercial/industrial** products with one data model:

- the **cybersecurity risk assessment** (Art. 13(2)–(4)), guided step by step, with a STRIDE threat model;
- the **technical documentation** per **Art. 31 and Annex VII**, per product;
- **components and SBOMs** (firmware, backend, frontend, mobile app …), with **vulnerability lookup** in public databases and VEX-based triage;
- **roles and access control** per product, with in-app accounts or single sign-on (e.g. Microsoft Entra ID).

> Requirement texts are paraphrased (Annex I is also shown in the official German wording). The Official Journal text prevails. The tool supports, but does not replace, legal review of classification and conformity route.

## Structure

```
Product ─┬─ Risk assessment (one per product, Art. 13)
         ├─ Components (firmware, backend, frontend, mobile, desktop, library, hardware)
         │     └─ SBOMs (CycloneDX / SPDX JSON, history kept) ─ vulnerability findings with triage (VEX)
         ├─ Technical documentation (Annex VII items 1–8, text + evidence files)
         ├─ Releases (frozen ZIP packages with SHA-256 manifest)
         └─ Members (owner / approver / editor / viewer)
```

### Annex VII coverage

| Annex VII | Where the content comes from | Checks |
|---|---|---|
| 1 General description | Risk assessment (purpose, use, environment), components & versions, hardware photos, Annex II user information | purpose, versions, photos if hardware, Annex II implemented |
| 2 Design, development, production, vulnerability handling | Architecture & threat-model diagram, design documents, **SBOMs**, CVD policy, contact address with evidence, update distribution, production processes, **vulnerability status** | SBOM per software component and its quality, no open *exploitable* vulnerabilities, all findings triaged, actively exploited CVEs flagged (Art. 14) |
| 3 Risk assessment | Risk assessment (all steps) | no blocking findings, method and latest revision approved, version frozen |
| 4 Support period | Risk assessment → support period | period, rationale, end date |
| 5 Standards | Risk assessment → standards; description of solutions where no standard is applied | applied parts named |
| 6 Test reports | Uploaded reports with type, date, result and the **Annex I requirements they verify** | every applicable Annex I requirement covered, Part II verified, no failed reports |
| 7 EU declaration of conformity | Signed copy, date/version, internet address (Annex II(6)) | |
| 8 SBOM on request | SBOMs in every release; hand-over procedure | |

The overview page shows each item as *complete / partial / missing*, with links to where the gap is fixed. The retention date is computed from the placing-on-market date and the support period (Art. 13(13)).

### Risk assessment

| CRA requirement | Step |
|---|---|
| Art. 13(3) intended purpose, foreseeable use, operating environment, assets, expected lifetime | *Product description*, *Assets* |
| Art. 13(3)–(4) applicability of Annex I, implementation, justification of non-applicable requirements | *Annex I applicability* |
| Art. 13(2)–(3) systematic threat identification | *Threat identification (STRIDE)* with data-flow diagram (drag to arrange) and worked example |
| Art. 13(2) risk analysis incl. health and safety | *Risk method*, *Risk register* |
| Art. 13(5), (8), (19); Art. 7, 8, 32; Annex II–IV, VII(4)–(5) | due diligence, support period, user information, classification, standards |
| Art. 13(3), Art. 31(2) kept up to date | *Review & approval* (review log, approvals, audit trail), frozen versions |

Consumer vs. commercial is a profile setting. It switches impact scales, threat library, mapping columns (EN 18031; ETSI EN 303 645; IEC 62443), the EN 303 645 checklist and zone/SL-T fields.

## SBOMs and vulnerabilities

- **Import:** CycloneDX JSON 1.2–1.6 and SPDX 2.x JSON (XML and SPDX 3 must be converted first). Each import is kept with its SHA-256; the newest is current.
- **SBOM quality check** (NTIA minimum elements / BSI TR-03183-2): author/tool, timestamp, primary component, dependency relationships (*top-level dependencies*, Annex I Part II(1)), name and version, unique identifier (package URL / CPE / hash), supplier, licence.
- **Online lookup** (background job, results kept per component):

  | Source | Matching | Notes |
  |---|---|---|
  | [OSV.dev](https://osv.dev) | package URL (npm, PyPI, Maven, Go, NuGet, Debian, Alpine, …) | batch, free, details cached 24 h |
  | [NVD](https://nvd.nist.gov) | CPE 2.3 (typical for C libraries / OS components in firmware) | 5 requests / 30 s without key; set `NVD_API_KEY` for 50. CPE matching can over-report – triage decides |
  | [ENISA EUVD](https://euvd.enisa.europa.eu) | per CVE found | EUVD ID and EPSS; exploited list merged into the KEV flag |
  | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | per CVE | *actively exploited* flag |

  OSV and NVD hits for the same package are merged under the CVE ID.
- **Offline / restricted networks:** set `VULN_LOOKUP=off` and import results produced elsewhere: **CycloneDX with `vulnerabilities` (VEX)**, **OSV-Scanner JSON**, **Grype JSON**, **Trivy JSON**. Outbound calls can go through a proxy (`HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1`).
- **Triage** uses the CycloneDX VEX states: *in triage, exploitable, not affected* (with justification), *false positive, resolved*, plus response and analysis. Decisions survive rescans and new SBOM versions. **VEX export** per component or product (CycloneDX 1.5).
- Findings flagged as actively exploited show an **Art. 14** notice (24 h early warning, 72 h notification, final report).

## Roles and access

| Global role | Rights |
|---|---|
| Administrator | manages users; full access to all products |
| Auditor | read-only access to all products |
| Product creator | may create products (and becomes owner) |
| User | only products they are a member of |

| Product role | Read & export | Edit content | Approve, freeze releases | Members, delete |
|---|---|---|---|---|
| Owner | ✓ | ✓ | ✓ | ✓ |
| Approver | ✓ | – | ✓ | – |
| Editor | ✓ | ✓ | – | – |
| Viewer | ✓ | – | – | – |

Enforced on the server. Approvals (risk method, review-log revisions, assessment status) are recorded with the approver's sign-in identity. Editors cannot grant approvals but withdraw them by changing the approved content (four-eyes principle). Non-members get 404 for a product. Products with releases can only be deleted by administrators (retention).

### Sign-in

| `AUTH_MODE` | Use |
|---|---|
| `local` (default) | In-app accounts (e-mail + password, scrypt). Administrators create users with a temporary password that must be changed. Sessions: HttpOnly, SameSite=Strict cookie, 2 h idle / 12 h absolute. Brute-force throttling. |
| `header` | Single sign-on behind an authenticating proxy (Azure Easy Auth, oauth2-proxy, AWS ALB …) that sets the user's e-mail in `AUTH_HEADER`. **Existing local users are matched by e-mail and become SSO-managed** at their first SSO sign-in (password removed). Unknown users are provisioned without rights (`SSO_AUTO_PROVISION`). |
| `none` | Development only – everybody is administrator. |

First administrator: `INITIAL_ADMIN_EMAIL` (+ `INITIAL_ADMIN_PASSWORD` in local mode). Without these, local mode prints a **one-time setup token** to the log. Global roles can come from the identity provider: `ROLE_SOURCE=entra` reads Entra **app roles** from `X-MS-CLIENT-PRINCIPAL` (Azure Container Apps / App Service), `ROLE_SOURCE=header` reads a comma-separated header (e.g. oauth2-proxy groups). `ROLE_MAP` maps values to roles (default `CRA.Admin=admin,CRA.Auditor=auditor,CRA.Creator=creator`). Product memberships are always managed in the app.

State-changing API calls require `X-Requested-With: XMLHttpRequest` (CSRF protection). Uploaded files are always served as downloads, never rendered inline.

## Exports and releases

- **Risk assessment:** PDF, XLSX (template layout), JSON; frozen versions with SHA-256.
- **Release of the technical documentation** (approver/owner): ZIP with `00_index_annex-VII.pdf` (Annex VII structure, completeness, references), risk assessment (PDF/XLSX/JSON), threat-model diagram (SVG), original SBOMs, VEX per component, `vulnerabilities.csv`, all evidence files sorted by Annex VII item, and `manifest.json` with the SHA-256 of every file. The ZIP is stored immutably; its SHA-256 is shown and sent as `X-Content-SHA256`. A draft package can be downloaded at any time.

## Run

Requires Node.js ≥ 22.13 (built-in `node:sqlite`; Node 24 for `NODE_USE_ENV_PROXY`).

```bash
npm ci
INITIAL_ADMIN_EMAIL=you@example.com INITIAL_ADMIN_PASSWORD='choose-a-long-one' npm start   # http://localhost:8080
npm test
```

Container (Docker or Podman – with Podman build with `--format docker` so the HEALTHCHECK is kept):

```bash
podman build --format docker -t cra-risk-assessment .
podman run -d -p 8080:8080 -v cra-data:/data --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e INITIAL_ADMIN_EMAIL=you@example.com -e INITIAL_ADMIN_PASSWORD='choose-a-long-one' cra-risk-assessment
# or: docker compose up -d   /   DATABASE_URL=postgres://cra:cra@db:5432/cra docker compose --profile postgres up -d
```

The image runs as non-root, has no build step and works with a read-only root filesystem. Outbound HTTPS is only needed for the online vulnerability lookup.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `DATABASE_URL` | `sqlite:/data/cra.db` (image) | `sqlite:<path>` or `postgres://user:pass@host:5432/db` |
| `PGSSLMODE` | – | `disable`, `require` or `verify-full` |
| `AUTH_MODE` | `local` | `local`, `header` or `none` |
| `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` | – | first administrator (password only for `local`) |
| `AUTH_HEADER` | `x-forwarded-user` | identity (e-mail) header in `header` mode, e.g. `x-ms-client-principal-name` |
| `AUTH_NAME_HEADER` | – | optional display-name header |
| `SSO_AUTO_PROVISION` | `true` | create unknown SSO users (without rights) |
| `ROLE_SOURCE` / `ROLE_MAP` / `AUTH_ROLES_HEADER` | `app` / see above / `x-forwarded-groups` | global roles from the identity provider |
| `SESSION_IDLE_MINUTES` / `SESSION_MAX_HOURS` | `120` / `12` | local sessions |
| `COOKIE_SECURE` | `auto` | `auto` (secure when the request is HTTPS), `true`, `false` |
| `VULN_LOOKUP` | `on` | `off` disables online lookups (import still works) |
| `VULN_SOURCES` | `osv,nvd,euvd,kev` | enabled sources |
| `NVD_API_KEY` | – | NVD API key (higher rate limit) |
| `NVD_MAX_LOOKUPS` / `EUVD_MAX_LOOKUPS` | `200` / `300` | per scan |
| `HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1` | – | outbound proxy for lookups |
| `FILE_MAX_MB` | `25` | maximum evidence file size |
| `TRUST_PROXY` | `loopback, linklocal, uniquelocal` | Express trust-proxy setting |

## Hosting

| Situation | Suggested setup |
|---|---|
| **On-prem / single VM** | `docker compose` with SQLite on a local volume behind a TLS reverse proxy; `AUTH_MODE=local`, or oauth2-proxy with `AUTH_MODE=header`, `AUTH_HEADER=x-forwarded-email`. |
| **Azure** | Container Apps + Entra ID (Easy Auth) + PostgreSQL Flexible Server + Key Vault – see [azure-hosting.md](azure-hosting.md). |
| **AWS** | ECS Fargate / App Runner behind an ALB with OIDC, or oauth2-proxy; RDS for PostgreSQL. |
| **Kubernetes** | Deployment + Ingress with oauth2-proxy; PostgreSQL. |

- **SQLite = one replica on a local disk** (not on SMB/NFS). Use PostgreSQL for cloud hosting or several replicas. Scans run in the replica that started them; a restart marks them *interrupted*.
- **`AUTH_MODE=header` trusts the header** – the container must only be reachable through the proxy.
- `/healthz` is unauthenticated (database check).
- **Retention:** keep the documentation 10 years after placing on the market or for the support period, whichever is longer (Art. 13(13)). Back up the database (it contains the releases and evidence files) and archive release ZIPs in your document management system.

### Upgrading from 0.3

The database is migrated automatically. Every existing assessment becomes a product (visible to administrators; add members afterwards). `AUTH_MODE=basic` was replaced by `AUTH_MODE=local`; the default changed from `none` to `local`, so set `INITIAL_ADMIN_EMAIL`/`INITIAL_ADMIN_PASSWORD` (or use the setup token from the log) on first start. With `AUTH_MODE=header`, users are created at first sign-in; set `INITIAL_ADMIN_EMAIL` to make yourself administrator.

## Project layout

```
src/server.js           HTTP API with RBAC checks, uploads, exports
src/auth.js             local accounts, sessions, SSO header mode, IdP roles
src/store.js            SQLite / PostgreSQL persistence with schema migrations
src/sbom.js             CycloneDX / SPDX parser and SBOM quality check
src/vuln.js             OSV / NVD / EUVD / KEV lookup, scanner-report import, VEX export, CVSS 3.x
src/export/             risk-assessment PDF/XLSX, technical-documentation package (ZIP + index PDF)
src/shared/             pure modules used by browser and server: catalog, model, roles, techdoc, diagram, tutorial
public/                 browser UI (plain ES modules, no build step); styles follow Fluent 2 (tokens in public/css/app.css)
test/                   node:test suite (API incl. RBAC, SSO, scans against a mocked vulnerability service)
```

## Design

The UI follows Microsoft's [Fluent 2](https://fluent2.microsoft.design) design system: colour, type, radius, elevation and motion tokens of the web light theme are defined as CSS variables in `public/css/app.css`, and controls follow the Fluent specifications (buttons, inputs, badges, message bars, data grid, nav pane, dialog, toast). Icons are [Fluent System Icons](https://github.com/microsoft/fluentui-system-icons) (© Microsoft, MIT License), embedded as path data in `public/js/icons.js`. Segoe UI is used where installed (Windows); other systems fall back to their system font.

## Known limitations

- Simultaneous editing of the same assessment is detected (optimistic locking), not merged.
- UI and exports are in English (Annex I also in official German).
- SBOM import is JSON only (CycloneDX XML, SPDX tag-value and SPDX 3 need conversion).
- NVD CPE matching relies on correct CPEs in the SBOM; packages without package URL or CPE cannot be looked up (shown as *unidentified*).
- Art. 14 reporting itself happens on the ENISA single reporting platform; the tool only flags candidates.
- When harmonised standards for CRA (prEN 40000 series) are cited in the OJ, update `src/shared/catalog.js`.
