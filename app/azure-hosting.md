# Hosting the CRA Self Assessment Helper on Azure with Entra ID sign-in

This guide deploys the application on **Azure Container Apps**. Users sign in through **Microsoft Entra ID**, using the platform's built-in authentication ("Easy Auth"). Data is stored in **Azure Database for PostgreSQL – Flexible Server**, reachable only inside a virtual network. Secrets live in **Azure Key Vault** and the image is pulled from **Azure Container Registry**. No passwords or keys are stored in the app configuration.

It is written for the engineer doing the deployment, who should know the Azure portal and the Azure CLI. Expect about 1–2 hours for a first deployment.

> Commands use Bash and Azure CLI ≥ 2.60 with the `containerapp` extension (`az extension add -n containerapp --upgrade`). They were checked against the Microsoft Learn CLI reference (November 2026). CLI flags change between versions, so check them with `-h` if a command is rejected. Each step can also be done in the portal.

---

## 1. Target architecture

```
                        Internet (HTTPS only)
                                │
                ┌───────────────▼────────────────────────────────┐
                │ Azure Container Apps environment (VNet-integrated)│
                │  ┌──────────────────────────────────────────┐  │
 Entra ID ◄─────┼──┤ Easy Auth sidecar (sign-in, session,      │  │
 (OIDC)         │  │ sets X-MS-CLIENT-PRINCIPAL-NAME)          │  │
                │  │            │                              │  │
                │  │ cra-risk-assessment container :8080       │  │
                │  │ (AUTH_MODE=header)                        │  │
                │  └────────────┬─────────────────────────────┘  │
                └───────────────┼────────────────────────────────┘
       user-assigned            │ TLS 5432, private IP only
       managed identity         ▼
     ┌─────────┴───────┐   ┌──────────────────────────────┐
     │ Key Vault        │   │ PostgreSQL Flexible Server    │
     │ (DB URL, auth    │   │ private access (delegated     │
     │  client secret)  │   │ subnet + private DNS zone)    │
     └─────────────────┘   └──────────────────────────────┘
     ┌─────────────────┐   ┌──────────────────────────────┐
     │ Container Registry│  │ Log Analytics workspace       │
     │ (AcrPull via MI) │   │ (app + platform logs)         │
     └─────────────────┘   └──────────────────────────────┘
```

### Security design decisions

| Concern | Decision | Why |
|---|---|---|
| User authentication | Container Apps built-in auth with Entra ID, *Require authentication* | No auth code in the app. Supports MFA and Conditional Access from Entra. |
| Who may use the app | Enterprise application with **Assignment required = Yes**, access granted to a security group | Without it, *every* user in the tenant can sign in. |
| Identity passed to the app | App runs with `AUTH_MODE=header`, `AUTH_HEADER=x-ms-client-principal-name` | Microsoft documents that external requests can't set these headers; only the platform sets them. The user name appears in the audit trail and on frozen versions. |
| Database | PostgreSQL Flexible Server, **private access only**, TLS with certificate verification, dedicated least-privilege login | No public endpoint. The app login can't administer the server. |
| Not SQLite | SQLite is **not** used on Azure | Container storage is ephemeral, and SQLite on Azure Files (SMB) has unreliable locking. |
| Secrets | Key Vault + Key Vault references in Container Apps, read by a user-assigned managed identity | No secret values in templates, pipelines or the portal configuration. |
| Image pull | ACR with admin user disabled; pull via managed identity (`AcrPull`) | No registry passwords. |
| Transport | HTTPS only (`allowInsecure: false`), TLS ≥ 1.2 at ingress | Required for Easy Auth cookies. |
| Isolation | Dedicated Container Apps environment for this app | Other apps in the same environment share the network boundary. |
| Operator access | Narrow Azure RBAC; avoid granting *Container Apps Contributor/Operator* broadly | These roles can read app secrets in plain text (`listSecrets`). |

---

## 2. Prerequisites

- Azure subscription. Your account needs **Owner**, or **Contributor + User Access Administrator**, on the target resource group (the steps create role assignments).
- Entra ID role that can create app registrations and configure enterprise applications, e.g. **Application Administrator** (or *Application Developer* plus help from an admin for step 11).
- A security group with the people who should use the app, e.g. `sg-cra-assessors`. Assigning *groups* to an enterprise application needs **Entra ID P1** or higher; without it, assign individual users.
- Local tools: Azure CLI, `openssl`, `envsubst` (package `gettext`). The image is built in Azure with `az acr build`, so no local Docker/Podman is needed.

---

## 3. Variables

Set these once in your shell. All later commands use them.

```bash
# --- adjust ---
export LOCATION="westeurope"                 # region inside the EU for EU data residency
export RG="rg-cra-prod"
export PREFIX="cracomp"                      # short, lowercase, unique within your org
export APP_VERSION="0.4.0"                   # matches app/package.json
export ENTRA_GROUP_NAME="sg-cra-assessors"
export ADMIN_EMAIL="you@example.com"         # your Entra UPN – becomes the first administrator of the app

# --- derived names ---
export VNET="vnet-$PREFIX"
export LAW="log-$PREFIX"
export ACR="acr${PREFIX}$RANDOM"             # must be globally unique, alphanumeric
export KV="kv-$PREFIX-$RANDOM"               # must be globally unique, 3–24 chars
export ID_NAME="id-$PREFIX-app"
export PG="psql-$PREFIX-$RANDOM"             # globally unique
export PG_DNS_ZONE="$PREFIX.private.postgres.database.azure.com"
export ENV_NAME="cae-$PREFIX"
export APP="ca-$PREFIX"
export TENANT_ID="$(az account show --query tenantId -o tsv)"
export SUB_ID="$(az account show --query id -o tsv)"
echo "ACR=$ACR KV=$KV PG=$PG"                # write these down
```

---

## 4. Resource group, network and logging

```bash
az group create -n "$RG" -l "$LOCATION"

az network vnet create -g "$RG" -n "$VNET" -l "$LOCATION" --address-prefixes 10.42.0.0/16

# Container Apps (workload profiles environment): min /27, delegated to Microsoft.App/environments
az network vnet subnet create -g "$RG" --vnet-name "$VNET" -n snet-aca \
  --address-prefixes 10.42.0.0/24 --delegations Microsoft.App/environments

# PostgreSQL Flexible Server private access: min /28, delegated to Microsoft.DBforPostgreSQL/flexibleServers
az network vnet subnet create -g "$RG" --vnet-name "$VNET" -n snet-pg \
  --address-prefixes 10.42.1.0/28 --delegations Microsoft.DBforPostgreSQL/flexibleServers

az monitor log-analytics workspace create -g "$RG" -n "$LAW" -l "$LOCATION" --retention-time 90
```

> Don't use address ranges that overlap the ranges Azure Container Apps reserves (169.254.0.0/16, 172.30.0.0/16, 172.31.0.0/16, 192.0.2.0/24, 100.100.0.0/17 and related). Don't overlap your on-premises ranges either if the VNet will be peered or connected by VPN later.

---

## 5. Managed identity

One user-assigned identity is used to pull the image and to read Key Vault secrets.

```bash
az identity create -g "$RG" -n "$ID_NAME" -l "$LOCATION"
export ID_RES_ID="$(az identity show -g "$RG" -n "$ID_NAME" --query id -o tsv)"
export ID_PRINCIPAL="$(az identity show -g "$RG" -n "$ID_NAME" --query principalId -o tsv)"
```

---

## 6. Container registry and image

```bash
az acr create -g "$RG" -n "$ACR" -l "$LOCATION" --sku Standard --admin-enabled false
export ACR_ID="$(az acr show -n "$ACR" --query id -o tsv)"

az role assignment create --assignee-object-id "$ID_PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role AcrPull --scope "$ACR_ID"

# Build the image inside Azure from the app folder (contains the Dockerfile)
cd app
az acr build -r "$ACR" -t "cra-risk-assessment:$APP_VERSION" .
cd ..
```

Always deploy an **explicit version tag** (never `latest`). That way you know exactly which code produced a frozen assessment, and you can roll back.

*Hardening option:* ACR **Premium** supports private endpoints and disabling public network access. If you use it, builds must run from inside the network (ACR tasks with agent pools, or a self-hosted build agent).

---

## 7. Key Vault

```bash
az keyvault create -g "$RG" -n "$KV" -l "$LOCATION" \
  --enable-rbac-authorization true --enable-purge-protection true --retention-days 90
export KV_ID="$(az keyvault show -n "$KV" --query id -o tsv)"

# the app identity may read secrets
az role assignment create --assignee-object-id "$ID_PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" --scope "$KV_ID"

# you (the deploying user) may write secrets
az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" \
  --role "Key Vault Secrets Officer" --scope "$KV_ID"
```

Role assignments can take a few minutes to take effect. If the next `az keyvault secret set` fails with *Forbidden*, wait and retry.

*Hardening option:* disable public network access on the vault and add a private endpoint in the VNet (private DNS zone `privatelink.vaultcore.azure.net`). Container Apps then resolves the vault privately.

---

## 8. PostgreSQL Flexible Server (private access)

### 8.1 Create the server

```bash
# admin password: only URL-safe characters, so it can be used in connection strings without escaping
export PG_ADMIN_PW="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32)"

az postgres flexible-server create -g "$RG" -n "$PG" -l "$LOCATION" \
  --version 16 --tier Burstable --sku-name Standard_B1ms --storage-size 32 \
  --admin-user craadmin --admin-password "$PG_ADMIN_PW" \
  --vnet "$VNET" --subnet snet-pg --private-dns-zone "$PG_DNS_ZONE" \
  --backup-retention 35 --geo-redundant-backup Disabled \
  --high-availability Disabled --yes

az postgres flexible-server db create -g "$RG" -s "$PG" -d cra

# keep the admin password in Key Vault, not in your shell history
az keyvault secret set --vault-name "$KV" -n pg-admin-url \
  --value "postgres://craadmin:${PG_ADMIN_PW}@${PG}.postgres.database.azure.com:5432/cra" >/dev/null
```

Notes:
- **Sizing:** Burstable B1ms is enough for a handful of concurrent users. Choose General Purpose if many teams use it at once.
- **High availability / geo-redundant backup:** enable for production if a regional outage must not stop work. Geo-redundant backup can only be chosen at creation time.
- The private DNS zone must end in `.postgres.database.azure.com` and must not equal the server name. The CLI creates it and links it to the VNet.
- **Optional hardening:** in *Server parameters* set `require_secure_transport = ON` (the default) and `ssl_min_protocol_version = TLSv1.2` or higher.

### 8.2 Create a least-privilege login for the app

The app creates its own tables on first start. It needs to connect to database `cra` and create objects in schema `public`, nothing more. The server is only reachable from inside the VNet, so the SQL runs as a one-off **Container Apps job** in the environment created in step 9. **Do step 9.1 first, then come back here.**

```bash
export APP_DB_PW="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32)"
az keyvault secret set --vault-name "$KV" -n database-url \
  --value "postgres://cra_app:${APP_DB_PW}@${PG}.postgres.database.azure.com:5432/cra" >/dev/null
az keyvault secret set --vault-name "$KV" -n app-db-password --value "$APP_DB_PW" >/dev/null
unset APP_DB_PW PG_ADMIN_PW

export KV_URI="https://${KV}.vault.azure.net"

# The script runs inside the job container. Variables are expanded there, not in your shell (quoted heredoc).
read -r -d '' DBINIT_SCRIPT <<'SCRIPT'
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -v pw="$APP_PW" <<'SQL'
CREATE ROLE cra_app LOGIN PASSWORD :'pw';
REVOKE CONNECT ON DATABASE cra FROM PUBLIC;
GRANT CONNECT ON DATABASE cra TO cra_app;
GRANT USAGE, CREATE ON SCHEMA public TO cra_app;
SQL
SCRIPT

az containerapp job create -g "$RG" -n job-cra-dbinit --environment "$ENV_NAME" \
  --trigger-type Manual --replica-timeout 300 --replica-retry-limit 0 --parallelism 1 --replica-completion-count 1 \
  --image docker.io/library/postgres:17-alpine \
  --mi-user-assigned "$ID_RES_ID" \
  --secrets "admin-url=keyvaultref:${KV_URI}/secrets/pg-admin-url,identityref:${ID_RES_ID}" \
            "app-pw=keyvaultref:${KV_URI}/secrets/app-db-password,identityref:${ID_RES_ID}" \
  --env-vars "ADMIN_URL=secretref:admin-url" "APP_PW=secretref:app-pw" "PGSSLMODE=verify-full" "PGSSLROOTCERT=system" \
  --command "/bin/sh" --args "-c" "$DBINIT_SCRIPT"

az containerapp job start -g "$RG" -n job-cra-dbinit
# check the result (wait ~1 min)
az containerapp job execution list -g "$RG" -n job-cra-dbinit -o table
```

When the execution shows **Succeeded**, delete the job. It holds a reference to the admin secret. If it failed, look at the job's console logs in Log Analytics (`ContainerAppConsoleLogs_CL`). A `role "cra_app" already exists` error means an earlier run succeeded.

```bash
az containerapp job delete -g "$RG" -n job-cra-dbinit --yes
```

> `PGSSLROOTCERT=system` makes `psql` verify the server certificate against the operating-system trust store (libpq ≥ 16). If your organisation inspects TLS or uses its own CA, see *Troubleshooting*.

---

## 9. Container Apps environment and app

### 9.1 Environment

```bash
export SNET_ACA_ID="$(az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n snet-aca --query id -o tsv)"
export LAW_ID="$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query customerId -o tsv)"
export LAW_KEY="$(az monitor log-analytics workspace get-shared-keys -g "$RG" -n "$LAW" --query primarySharedKey -o tsv)"

az containerapp env create -g "$RG" -n "$ENV_NAME" -l "$LOCATION" \
  --infrastructure-subnet-resource-id "$SNET_ACA_ID" \
  --logs-destination log-analytics --logs-workspace-id "$LAW_ID" --logs-workspace-key "$LAW_KEY"
unset LAW_KEY
export ENV_ID="$(az containerapp env show -g "$RG" -n "$ENV_NAME" --query id -o tsv)"
```

This creates an **external** environment, reachable from the internet but protected by Entra sign-in. For access only from the corporate network, see section 13.

Now go back and run **8.2**.

### 9.2 Container app

Create `containerapp.yaml` from this template. `envsubst` fills in the variables.

```bash
cat > containerapp.tmpl.yaml <<'YAML'
location: ${LOCATION}
identity:
  type: UserAssigned
  userAssignedIdentities:
    ${ID_RES_ID}: {}
properties:
  managedEnvironmentId: ${ENV_ID}
  configuration:
    activeRevisionsMode: Single
    ingress:
      external: true
      targetPort: 8080
      transport: auto
      allowInsecure: false
      # Optional: allow only your corporate egress IPs (see section 13)
      # ipSecurityRestrictions:
      #   - name: corp-egress
      #     ipAddressRange: 203.0.113.0/24
      #     action: Allow
    registries:
      - server: ${ACR}.azurecr.io
        identity: ${ID_RES_ID}
    secrets:
      - name: database-url
        keyVaultUrl: https://${KV}.vault.azure.net/secrets/database-url
        identity: ${ID_RES_ID}
      - name: nvd-api-key
        keyVaultUrl: https://${KV}.vault.azure.net/secrets/nvd-api-key
        identity: ${ID_RES_ID}
  template:
    containers:
      - name: cra
        image: ${ACR}.azurecr.io/cra-risk-assessment:${APP_VERSION}
        resources:
          cpu: 1.0
          memory: 2Gi
        env:
          - name: DATABASE_URL
            secretRef: database-url
          - name: PGSSLMODE
            value: verify-full
          - name: AUTH_MODE
            value: header
          - name: AUTH_HEADER
            value: x-ms-client-principal-name
          - name: INITIAL_ADMIN_EMAIL
            value: ${ADMIN_EMAIL}
          - name: ROLE_SOURCE
            value: entra
          - name: VULN_LOOKUP
            value: "on"
          - name: NVD_API_KEY
            secretRef: nvd-api-key
          - name: NODE_ENV
            value: production
        probes:
          - type: Liveness
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 30
          - type: Readiness
            httpGet:
              path: /healthz
              port: 8080
            periodSeconds: 10
    scale:
      minReplicas: 1
      maxReplicas: 3
YAML

# NVD API key (free, https://nvd.nist.gov/developers/request-an-api-key) – raises the NVD rate limit from 5 to 50 requests / 30 s.
# Without a key, store a placeholder: the app then uses the public limit.
az keyvault secret set --vault-name "$KV" -n nvd-api-key --value "${NVD_API_KEY:-none}" >/dev/null

export ID_RES_ID ENV_ID ACR KV APP_VERSION LOCATION ADMIN_EMAIL
envsubst < containerapp.tmpl.yaml > containerapp.yaml
az containerapp create -g "$RG" -n "$APP" --yaml containerapp.yaml

export FQDN="$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv)"
echo "https://$FQDN"
```

What the settings do:
- **`AUTH_MODE=header`:** the app refuses every request without the identity header (HTTP 401). Even if authentication were accidentally switched off in the next step, the app would not open up. It would stop working instead.
- **`INITIAL_ADMIN_EMAIL`:** this Entra user becomes administrator of the app at first start. Everybody else who passes Entra sign-in is registered at their first sign-in **without** product access, until an administrator or product owner adds them (or an Entra app role grants a global role, section 11.1).
- **`ROLE_SOURCE=entra`:** global roles (administrator, auditor, product creator) come from Entra app roles in the sign-in token. Product memberships (owner / approver / editor / viewer) are always managed in the app.
- **`cpu: 1.0`, `memory: 2Gi`:** building a documentation release packs all evidence files into a ZIP in memory. Use more memory if products carry many large files.
- **`PGSSLMODE=verify-full`:** encrypted connection with certificate and host-name verification.
- **`minReplicas: 1`:** avoids cold starts. With PostgreSQL several replicas are safe; concurrent edits are detected with optimistic locking.
- **Secrets:** the app never sees Key Vault itself. Container Apps resolves the reference and passes the value as an environment variable. Without a pinned version, a new secret version is picked up automatically within ~30 minutes and the revision is restarted.

At this point the app answers with HTTP 401 ("Missing identity header"). That is expected until step 10 is done.

---

## 10. Entra ID sign-in (Easy Auth)

### 10.1 App registration

```bash
az ad app create --display-name "CRA Self Assessment Helper" --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "https://$FQDN/.auth/login/aad/callback" \
  --enable-id-token-issuance true
export APP_ID="$(az ad app list --display-name "CRA Self Assessment Helper" --query "[0].appId" -o tsv)"

az ad sp create --id "$APP_ID"
export SP_ID="$(az ad sp show --id "$APP_ID" --query id -o tsv)"
```

The app requests only sign-in (`openid`, `profile`, `email` via *User.Read*). No API permissions or admin consent beyond the default are needed.

### 10.2 Client secret into Key Vault

```bash
# 12 months; use what your organisation's policy allows and put the expiry date in your operations calendar
EASYAUTH_SECRET="$(az ad app credential reset --id "$APP_ID" --display-name "easyauth-$(date +%Y%m)" \
  --years 1 --append --query password -o tsv)"
az keyvault secret set --vault-name "$KV" -n easyauth-client-secret --value "$EASYAUTH_SECRET" \
  --expires "$(date -u -d '+11 months' +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
unset EASYAUTH_SECRET

az containerapp secret set -g "$RG" -n "$APP" \
  --secrets "microsoft-provider-authentication-secret=keyvaultref:https://${KV}.vault.azure.net/secrets/easyauth-client-secret,identityref:${ID_RES_ID}"
```

### 10.3 Enable authentication on the container app

```bash
az containerapp auth microsoft update -g "$RG" -n "$APP" \
  --client-id "$APP_ID" \
  --client-secret-name microsoft-provider-authentication-secret \
  --issuer "https://login.microsoftonline.com/$TENANT_ID/v2.0" \
  --yes

az containerapp auth update -g "$RG" -n "$APP" \
  --enabled true \
  --unauthenticated-client-action RedirectToLoginPage \
  --redirect-provider azureactivedirectory \
  --require-https true \
  --excluded-paths "/healthz"
```

- **`RedirectToLoginPage`:** browsers are sent to the Microsoft sign-in page. If the sign-in session expires while someone is working, the app's background save gets a login redirect (or a 401) instead of an answer. The app (≥ 0.3.1) detects both, keeps the unsaved changes in the browser, asks the user to sign in again in a new tab, and then saves.
- **`/healthz`** is excluded so platform probes and uptime monitors work. It only returns `{"ok":true}` after a database check and reveals no data.

**Portal equivalent:** *Container App → Security → Authentication → Add identity provider → Microsoft*. Use the existing app registration, client secret setting name `microsoft-provider-authentication-secret`, *Restrict access: Require authentication*, *Unauthenticated requests: HTTP 302 redirect*.

**Session lifetime (optional):** the platform's session cookie expires after 8 hours by default. To change it:

```bash
az containerapp auth update -g "$RG" -n "$APP" --set login.cookieExpiration.timeToExpiration=10:00:00
```

---

## 11. Restrict who can use the app

By default **any user in your tenant** can sign in. Limit it to the assessor group:

```bash
# 1. require assignment
az ad sp update --id "$SP_ID" --set appRoleAssignmentRequired=true

# 2. assign the group (default access role 00000000-0000-0000-0000-000000000000)
export GROUP_ID="$(az ad group show --group "$ENTRA_GROUP_NAME" --query id -o tsv)"
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" \
  --body "{\"principalId\":\"$GROUP_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}"
```

Portal: *Entra ID → Enterprise applications → CRA Self Assessment Helper → Properties → Assignment required = Yes*, then *Users and groups → Add user/group*.

Users outside the group get Entra error **AADSTS50105** and never reach the app.

Inside the app, access is controlled per product (owner, approver, editor, viewer). Assignment in Entra decides who can reach the app at all; product owners decide who sees which product.

### 11.1 Global roles from Entra app roles (optional)

With `ROLE_SOURCE=entra`, the app reads Entra **app roles** from the platform header `X-MS-CLIENT-PRINCIPAL` and maps them to global roles:

| App role value | Global role in the app |
|---|---|
| `CRA.Admin` | Administrator – manages users, sees all products |
| `CRA.Auditor` | Auditor – read-only access to all products |
| `CRA.Creator` | Product creator – may create products |
| *(none)* | User – sees only products they are a member of |

Create the roles on the app registration and assign groups:

```bash
cat > app-roles.json <<'JSON'
[
  {"allowedMemberTypes":["User"],"displayName":"CRA administrator","description":"Manages users; full access to all products","value":"CRA.Admin","id":"8f2c4c0e-6a3e-4d5e-9b1a-1c7f2a9e0a01","isEnabled":true},
  {"allowedMemberTypes":["User"],"displayName":"CRA auditor","description":"Read-only access to all products","value":"CRA.Auditor","id":"8f2c4c0e-6a3e-4d5e-9b1a-1c7f2a9e0a02","isEnabled":true},
  {"allowedMemberTypes":["User"],"displayName":"CRA product creator","description":"May create products","value":"CRA.Creator","id":"8f2c4c0e-6a3e-4d5e-9b1a-1c7f2a9e0a03","isEnabled":true}
]
JSON
az ad app update --id "$APP_ID" --app-roles @app-roles.json

# example: product managers may create products
export PM_GROUP_ID="$(az ad group show --group sg-cra-product-managers --query id -o tsv)"
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" \
  --body "{\"principalId\":\"$PM_GROUP_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"8f2c4c0e-6a3e-4d5e-9b1a-1c7f2a9e0a03\"}"
```

(Generate your own GUIDs with `uuidgen` if you prefer.) A user assigned to an app role is also "assigned" for the purpose of *Assignment required*. Role changes take effect at the user's next sign-in. With `ROLE_SOURCE=entra`, global roles of SSO users can no longer be changed in the app's user administration – they follow Entra. Keep at least one person with `CRA.Admin`.

If you prefer to manage everything in the app, leave out `ROLE_SOURCE` (default `app`): administrators then assign global roles under *Users*.

### 11.2 Conditional Access (recommended)

Create a Conditional Access policy (*Entra ID → Protection → Conditional Access*) targeting the *CRA Self Assessment Helper* enterprise application, for example:
- require **phishing-resistant MFA** or MFA,
- require a **compliant or hybrid-joined device**,
- optionally block sign-ins from outside approved countries / named locations.

Test it in *Report-only* mode first.

---

### 11.3 Outbound access for the vulnerability lookup

The online lookup calls these HTTPS endpoints from the container:

| Host | Purpose |
|---|---|
| `api.osv.dev` | OSV.dev vulnerability database (package URLs) |
| `services.nvd.nist.gov` | NVD CVE API (CPE matching) |
| `euvdservices.enisa.europa.eu` | ENISA EU Vulnerability Database (EUVD IDs, EPSS, exploited list) |
| `www.cisa.gov` | CISA Known Exploited Vulnerabilities feed |

Container Apps allows outbound internet access by default. If you route egress through Azure Firewall / a NAT appliance (UDR), allow these FQDNs. Where no outbound access is permitted, set `VULN_LOOKUP=off` and import scanner results (CycloneDX VEX, OSV-Scanner, Grype, Trivy JSON) produced in your build pipeline. With an explicit proxy, set `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`.

Lookups run as background jobs in the replica that started them. With `minReplicas: 1` and single-revision mode a deployment can interrupt a running scan; it is then shown as *interrupted* and can simply be started again.

---

## 12. Custom domain (optional)

```bash
export CUSTOM_HOST="cra.example.com"
# DNS: create CNAME cra.example.com -> $FQDN and TXT asuid.cra.example.com -> verification ID:
az containerapp show -g "$RG" -n "$APP" --query properties.customDomainVerificationId -o tsv

az containerapp hostname add  -g "$RG" -n "$APP" --hostname "$CUSTOM_HOST"
az containerapp hostname bind -g "$RG" -n "$APP" --hostname "$CUSTOM_HOST" \
  --environment "$ENV_NAME" --validation-method CNAME        # free managed certificate

# add the new redirect URI (keep the old one until users have switched)
az ad app update --id "$APP_ID" --web-redirect-uris \
  "https://$FQDN/.auth/login/aad/callback" "https://$CUSTOM_HOST/.auth/login/aad/callback"
```

---

## 13. Network exposure options

Pick one, depending on your policy:

| Option | How | Notes |
|---|---|---|
| **A. Internet + Entra ID** (this guide) | External environment, Easy Auth, Conditional Access | Simplest. Usable from anywhere, including home office without VPN. |
| **B. A + IP allow-list** | `ipSecurityRestrictions` in the YAML (or `az containerapp ingress access-restriction set -g "$RG" -n "$APP" --rule-name corp --ip-address 203.0.113.0/24 --action Allow`) | Only corporate egress IPs reach the sign-in redirect at all. |
| **C. Private only** | Create the environment with `--internal-only true`, add a private DNS zone for the environment's default domain, and reach it via VPN / ExpressRoute or an Application Gateway (WAF) in the VNet | No public endpoint at all. Easy Auth still works because the browser reaches Entra ID directly. Requires DNS planning. |
| **D. A + Front Door Premium with WAF** | Front Door with Private Link to the environment | Adds WAF rules and DDoS protection at the edge. Higher cost and complexity. |

---

## 14. Verify the deployment

Run these checks and keep the output with your deployment records.

```bash
# 1. unauthenticated browser request → redirect to sign-in (302)
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "https://$FQDN/"

# 2. a forged identity header must NOT get in (expect 302 or 401, never 200)
curl -s -o /dev/null -w "%{http_code}\n" -H "x-ms-client-principal-name: attacker@example.com" "https://$FQDN/api/me"

# 3. API without a session → no data (expect 302 or 401)
curl -s -o /dev/null -w "%{http_code}\n" "https://$FQDN/api/assessments"

# 4. health endpoint (excluded from auth) → {"ok":true}
curl -s "https://$FQDN/healthz"; echo

# 5. plain HTTP is not served
curl -s -o /dev/null -w "%{http_code}\n" "http://$FQDN/"            # expect 301/308 to https or no connection

# 6. the database has no public endpoint
az postgres flexible-server show -g "$RG" -n "$PG" --query "network.publicNetworkAccess" -o tsv   # expect Disabled

# 7. app logs show the version and database type
az containerapp logs show -g "$RG" -n "$APP" --tail 20 | grep "listening"
```

In the browser:
1. Open `https://$FQDN` and sign in as `$ADMIN_EMAIL`. The top bar shows *Users* (administrator), your name and the app version (e.g. *v0.4.0*).
2. Load the tutorial product, scan the *Cloud service* component (*Components & SBOMs → Scan*): after a few seconds findings from OSV.dev appear. Check *Activity*: your UPN is listed as the actor.
3. Sign in with a second assessor account: it sees no products until you add it under *Product → Members*.
4. Sign in with a user **not** assigned in Entra: Entra shows AADSTS50105.
5. *Releases → Freeze release* and download the ZIP; check `manifest.json`.

---

## 15. Operations

### Updates

```bash
export APP_VERSION="0.3.2"
cd app && az acr build -r "$ACR" -t "cra-risk-assessment:$APP_VERSION" . && cd ..
az containerapp update -g "$RG" -n "$APP" --image "$ACR.azurecr.io/cra-risk-assessment:$APP_VERSION"
```

Single-revision mode replaces the running revision with zero downtime. **Rollback:** run the same `update` with the previous tag. Database changes are additive (`CREATE TABLE IF NOT EXISTS`), so older versions keep working with the same database.

### Secret rotation

| Secret | Where | How |
|---|---|---|
| Easy Auth client secret | Key Vault `easyauth-client-secret` | Before expiry: `az ad app credential reset --append …` → new Key Vault version. Picked up within 30 min (or restart the revision). Then remove the old credential from the app registration. |
| App database password | Key Vault `database-url` | `ALTER ROLE cra_app PASSWORD '…'` (via a job as in 8.2) → new Key Vault version of `database-url`. |
| PostgreSQL admin password | Key Vault `pg-admin-url` | `az postgres flexible-server update --admin-password …`. The app does not use it. |

Set **expiry dates** on the Key Vault secrets and use Key Vault *near expiry* events or Azure Monitor alerts to get reminded.

### Backups and retention

- PostgreSQL keeps automated backups for the configured retention (here **35 days**, the maximum) with point-in-time restore.
- **Technical documentation must be kept for at least 10 years after placing on the market, or for the support period if longer (CRA Art. 13(13)).** The database backups do not cover this. For long-term evidence:
  1. Freeze a version in the app for every release and **archive the frozen PDF and JSON exports** in your document management system. Each export carries a SHA-256 fingerprint.
  2. Optionally run a scheduled Container Apps job that writes a `pg_dump` to a Storage account with **immutable (WORM) blob storage** and a time-based retention policy.

### Monitoring

- Application and platform logs: Log Analytics workspace `$LAW` (`ContainerAppConsoleLogs_CL`, `ContainerAppSystemLogs_CL`).
- Recommended alerts: replica restarts, HTTP 5xx rate, `/healthz` availability test (Application Insights standard test), PostgreSQL CPU/storage > 80 %.
- Turn on **Microsoft Defender for Cloud** (Containers and open-source relational databases plans) for image vulnerability scanning and database threat detection.
- Enable PostgreSQL diagnostic settings → Log Analytics (`PostgreSQLLogs`) if you need connection auditing.

### Azure RBAC for operators

| Who | Role | Scope |
|---|---|---|
| Deployment pipeline | Contributor (+ AcrPush on the registry) | resource group |
| Operators who restart / view logs | Reader + *Log Analytics Reader*; a custom role with `Microsoft.App/containerApps/read`, `…/revisions/restart/action` (no `listSecrets`) | resource group |
| Nobody routinely | Container Apps Contributor / Operator, Key Vault Secrets Officer | — grant temporarily via PIM |

---

## 16. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| App shows `{"error":"Missing identity header x-ms-client-principal-name …"}` | Authentication is not enabled, or `AUTH_HEADER` is misspelled. Check `az containerapp auth show -g "$RG" -n "$APP"`. |
| Entra error **AADSTS50011** (redirect URI mismatch) | The redirect URI in the app registration must be exactly `https://<host>/.auth/login/aad/callback` for every host name you use. |
| Entra error **AADSTS50105** | The user is not assigned to the enterprise application (step 11). |
| Revision fails, logs show `self-signed certificate in certificate chain` / `unable to verify the first certificate` | TLS to PostgreSQL is intercepted, or a corporate CA is in the path. Prefer fixing the path. As a temporary workaround set `PGSSLMODE=require` (encrypted, no certificate check). |
| Revision fails with `password authentication failed for user "cra_app"` | Step 8.2 did not run, or the password in `database-url` differs. Re-run the job; check that the password has no characters that need URL encoding. |
| Revision fails with `permission denied for schema public` | The `GRANT USAGE, CREATE ON SCHEMA public` in 8.2 is missing. |
| `getaddrinfo ENOTFOUND <server>.postgres.database.azure.com` | Private DNS zone not linked to the VNet: *Private DNS zones → $PG_DNS_ZONE → Virtual network links*. |
| Key Vault reference shows *Authentication failed* in *Secrets* | Identity lacks **Key Vault Secrets User** on the vault, or the role assignment is still propagating. |
| Users see "Sign-in session expired" | Normal after the session lifetime. Follow the dialog: sign in in a new tab, click *Save now*. Adjust the lifetime in 10.3 if it happens often. |
| PDF export times out for very large assessments | Increase the container to `cpu: 1.0`, `memory: 2Gi`. |

---

## 17. Security checklist

- [ ] Authentication enabled, *Require authentication*, provider Microsoft, `require-https = true`
- [ ] `AUTH_MODE=header`, `AUTH_HEADER=x-ms-client-principal-name`
- [ ] Forged-header test (14.2) returns 302/401
- [ ] Enterprise application: **Assignment required = Yes**, only the assessor group assigned
- [ ] `INITIAL_ADMIN_EMAIL` set; app roles (`CRA.Admin`, …) assigned only to the intended groups
- [ ] Product memberships reviewed per product (owners, approvers separate from editors)
- [ ] Conditional Access policy (MFA, device compliance) active for the app
- [ ] Ingress `allowInsecure: false`; optional IP allow-list or private environment
- [ ] Dedicated Container Apps environment, no unrelated apps in it
- [ ] PostgreSQL: private access only, public network access *Disabled*, `PGSSLMODE=verify-full`
- [ ] App uses `cra_app` (least privilege), not the server admin; db-init job deleted
- [ ] All secrets in Key Vault (RBAC, purge protection); none as plain values in the app configuration
- [ ] ACR admin user disabled; image pulled via managed identity; explicit version tags
- [ ] Easy Auth client secret expiry date recorded; rotation owner named
- [ ] Logs to Log Analytics; alerts on restarts, 5xx and health
- [ ] Defender for Cloud plans enabled (containers, databases)
- [ ] Documentation release ZIPs archived outside the app for ≥ 10 years / support period (the database also holds them – keep its backups)
- [ ] Outbound access to the vulnerability databases allowed (or `VULN_LOOKUP=off` with imports); NVD API key in Key Vault
- [ ] Operator roles reviewed: no standing *Container Apps Contributor/Operator* (they can read secrets)

---

### References

- Container Apps authentication: <https://learn.microsoft.com/azure/container-apps/authentication> and <https://learn.microsoft.com/azure/container-apps/authentication-azure-active-directory>
- Restrict an Entra app to a set of users: <https://learn.microsoft.com/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users>
- Container Apps secrets / Key Vault references: <https://learn.microsoft.com/azure/container-apps/manage-secrets>
- Container Apps virtual networks: <https://learn.microsoft.com/azure/container-apps/custom-virtual-networks>
- PostgreSQL Flexible Server private access: <https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-private>
- CLI reference `az containerapp auth`: <https://learn.microsoft.com/cli/azure/containerapp/auth>
