---
id: P121
name: CloudStorageExposure
refs: ASVS V17.x / WSTG-CONF / CS: Cloud native storage
---

# P121 — Cloud Storage Exposure

## Preconditions

The code interacts with external storage services.


## Overview
Cloud storage exposure occurs when objects stored in object storage — S3, GCS, Azure Blob, Backblaze B2, R2 — are reachable by parties who should never see them: anonymous internet users, cross-account principals, or anyone holding a leaked URL. The root cause is almost always a **policy shape mismatch between intent and grant**: a developer makes a bucket "public" to host one asset and forgets it also exposes the database backups beside it, an IAM/bucket policy uses `Principal: "*"` with `s3:GetObject` on the whole prefix, or a pre-signed URL is minted with a long expiry and leaked into logs, a client bundle, or a public repo. Unlike an application-layer leak, object storage has no authentication layer of its own once a policy opens it — the cloud provider happily serves the bytes to anyone who asks.

## What to check
- Are any buckets/containers configured with **public read** (`aws s3api put-bucket-acl --acl public-read`, `allUsers` / `allAuthenticatedUsers` IAM grants, GCS `uniformBucketLevelAccess` with `roles/storage.objectViewer`, Azure container access tier `blob` / `container`)?
- Does a bucket or IAM policy use `Principal: "*"` (or `"AWS": "*"`) combined with `s3:GetObject` / `storage.objects.get` / `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` — and is that scoped to a single public prefix, or to the whole bucket?
- Are wildcard resource patterns like `arn:aws:s3:::data/*` paired with a wildcard principal? Check for the conjunction, not either grant in isolation.
- Are **block public access** (S3 `BlockPublicAccess`, `PublicAccessBlockConfiguration`) and **object ownership** (`BucketOwnerEnforced`) disabled, or is the bucket created before 2023 with defaults that allowed ACLs?
- Are **pre-signed URLs** minted with long expiries (hours/days), generated from long-lived keys rather than STS sessions, and do they appear in source, logs (`console.log(url)`), client bundles, error pages, or analytics?
- Are pre-signed URLs minted for `PUT`/`POST` where only `GET` was needed — granting anonymous write on the object key?
- Does bucket **CORS** (`cors`, `cors_rules`) allow `AllowedOrigins: ["*"]` with `AllowedMethods` including `GET` and credentials/headers — letting any origin read object contents cross-site?
- Are **sensitive object keys** co-located with public ones under a shared prefix (e.g., `s3://app-assets/` holds both `logo.png` and `db-backup.sql.gz`, `users-export.csv`, `secrets.env`, `.env`)?
- Are object listings enumerable — bucket has `ListBucket` granted to `*` (then keys are guessable via `?list-type=2`), or directory indexes served?
- Are static-site / SPA buckets hosting server-side artifacts: `config.json` with API keys, `.map` files, `.git/`, terraform state, SQLite DBs, snapshot exports?
- Do **IAM roles** over-grant — a Lambda/Cloud Run service role with `s3:*` on `*` instead of `s3:GetObject` on one prefix, so a compromise pivots to read-all?
- Are **access keys / connection strings** (AWS access key id, GCS service account JSON, Azure storage account key) committed to VCS, baked into container images, or shipped in client code — turning a single repo leak into bucket-wide compromise?

## Static signals
Public / over-permissive policy blocks (Terraform / CloudFormation / SAM / Pulumi / CDK):
- `aws_s3_bucket_acl acl = "public-read"` / `"public-read-write"`
- `aws_s3_bucket_policy` / `aws_iam_policy` with `"Principal": "*"`, `"AWS": "*"`, `"Action": "s3:GetObject"`, `"Resource": "arn:aws:s3:::bucket/*"`
- `aws_s3_bucket_public_access_block block_public_acls = false`, `restrict_public_buckets = false`
- GCS: `google_storage_bucket_iam_binding` members = `["allUsers", "allAuthenticatedUsers"]`, role `roles/storage.objectViewer`
- Azure: `azurerm_storage_container` `container_access_type = "blob"` / `"container"` (vs `"private"`); `azurerm_storage_account_network_rulesets` default_action = `"Allow"`
- CFN/CDK: `BlockPublicAccess` absent, `AccessControl: PublicRead`

Pre-signed URLs and key leakage (Node / Python / Java / Go / Ruby / PHP):
- Node: `s3.getSignedUrl('getObject', { Key: 'db-backup.sql' })` with no/long `Expires`; `new AWS.S3({ accessKeyId, secretAccessKey })` reading from env shipped to client
- Python: `s3.generate_presigned_url('get_object', Params={...}, ExpiresIn=604800)`; `boto3.client('s3', aws_access_key_id=...)` hardcoded
- Java: `generatePresignedUrlRequest.setExpiration(Date + 7 days)`; AWS creds in `application.properties`
- Go: `presign` with `s3.NewFromConfig` and long durations; `os.Getenv("AWS_SECRET_ACCESS_KEY")` baked into a public SPA
- Ruby/PHP: `Aws::S3::Presigner` / `$s3->createPresignedRequest` — long TTL, logged URL

CORS misconfiguration:
- `AllowedOrigins: ["*"]` + `AllowedMethods: ["GET"]` on a private-data bucket
- `cors_rules { allowed_origins = ["*"] allowed_methods = ["GET", "PUT"] }` (Terraform `aws_s3_bucket_cors_configuration`)

Sensitive-key exposure / co-location signals:
- Static hosting of `index.html` alongside `.env`, `*.sqlite`, `*.sql.gz`, `terraform.tfstate`, `*.pem`, `serviceAccount.json`, `app.config.js` with API keys
- Build artifacts publishing `*.map` files to a public bucket
- Hardcoded creds that authenticate to storage: `AKIA[0-9A-Z]{16}`, `GOOG[A-Z0-9]{16}`, `DefaultEndpointsProtocol=https;AccountKey=...`

## False positives
- The bucket is a **legitimate public CDN/static site** (`assets.example.com`) hosting only hashed, non-sensitive files, with `ListBucket` denied so contents are not enumerable, and sensitive data lives in a separate private bucket.
- `Principal: "*"` is intentionally scoped to a single `public/` prefix via a separate resource ARN (`arn:aws:s3:::bucket/public/*`) and the rest of the bucket is private — verify the resource constraint, not just the principal.
- Pre-signed URLs are short-lived (minutes), minted per-request via STS, and never logged or returned in client-accessible error paths.
- CORS `AllowedOrigins: ["*"]` is on a bucket serving only public content where cross-origin read is intended and no credentials are involved.
- Block public access is enabled at account level (`s3:PutPublicAccessBlock`) and the resource-level settings are overridden — confirm the effective state, not the bucket-level block alone.

## Attack scenario
1. Attacker enumerates `https://app-assets.example.com/` (a bucket fronted by CloudFront) and discovers `?list-type=2` returns an XML object listing because `ListBucket` was granted to `*`.
2. The listing reveals `db-backup-2026-06-30.sql.gz`, `users-export.csv`, and `terraform.tfstate` beside the public `logo.png`.
3. Attacker `GET`s each object directly (the same `s3:GetObject`-to-`*` grant serves them) — no credentials required.
4. From `terraform.tfstate` the attacker recovers the DB password and an IAM access key; from the export they get full PII for every user.
5. Alternatively: a pre-signed GET URL for a private report is minted with a 7-day expiry and logged in the browser history / shared in a support ticket; the attacker reuses it long after the report was meant to be private. In a CORS variant, a malicious page `fetch()`es the bucket cross-origin because `AllowedOrigins: ["*"]` permitted it.

## Impact
- **Confidentiality**: full disclosure of stored data — PII, PHI, secrets, source, backups. Often the single most damaging cloud misconfiguration.
- **Integrity**: with over-permissive PUT pre-signed URLs or `s3:PutObject` grants, attackers can deface, plant malware, or poison backups and CI artifacts (e.g., overwrite a Lambda zip or a container layer).
- **Availability**: deletion or ransomware-style encryption of objects if `s3:DeleteObject` is exposed; bucket quota abuse; account abuse for cryptomining if keys are leaked.
- Severity scales with content sensitivity and grant breadth: a public logo bucket is informational; a public backup bucket with credentials and PII is critical. Leaked long-lived keys elevate any finding to bucket/account-wide compromise.

## Remediation
Private by default; scope grants to the least resource and principal:
```hcl
# VULNERABLE — public read of everything in the bucket
resource "aws_s3_bucket_policy" "bad" {
  policy = jsonencode({
    Principal = "*"
    Action   = "s3:GetObject"
    Resource = "arn:aws:s3:::company-data/*"   # includes backups, secrets
  })
}

# SAFE — private bucket, block public access, per-object pre-signed URLs only
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# public assets live in a SEPARATE bucket, ListBucket denied, list denied
```
Mint pre-signed URLs server-side with a short `ExpiresIn` (minutes), via STS-scoped credentials, and never log or return them in client bundles. Enable MFA-delete and versioning on sensitive buckets, alert on anonymous access via CloudTrail/Cloud Logging data-plane events, and scan secrets at upload (Macie / Secret Manager rotation) as defense-in-depth.

## References
- OWASP ASVS V17.x — Cloud and infrastructure security controls
- OWASP WSTG-CONF — Configuration and deployment management testing (cloud storage / S3 bucket exposure)
- OWASP Cheat Sheet: Cloud native storage
