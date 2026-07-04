---
id: P117
name: SubdomainTakeover
area: V13 Configuration
refs: ASVS V14.x / WSTG-CONF / CS: Cloud subdomain takeover
---

# P117 — SubdomainTakeover

## Overview
Subdomain takeover occurs when a DNS record (typically a `CNAME` or `A`) still points at a cloud resource — an S3 bucket, GitHub Pages site, Heroku/Azure app, Firebase project, or static-site hosting endpoint — that has been **decommissioned, renamed, or never claimed**, but the DNS entry was never cleaned up. The provider then offers that resource name back into its global namespace; whoever creates a new resource with the same name effectively controls what the trusted subdomain serves. The root cause is the decoupling of DNS ownership (controlled by the domain owner) from resource ownership (controlled by the cloud provider), combined with the absence of a decommissioning checklist that removes DNS records alongside deleted resources. Because the content is served from the victim's own subdomain over the victim's TLS certificate, browsers and users trust it implicitly.

## What to check
- Inventory all `CNAME`, `A`, and `AAAA` records and resolve each one. Flag any whose target returns a provider "not found /NoSuchBucket / There isn't a GitHub Pages site here / No such app" style response — the canonical takeover signal.
- For each CNAME pointing at a provider namespace, verify the named resource still exists and is owned by you: `*.s3.amazonaws.com`, `*.cloudfront.net`, `*.github.io`, `*.herokuapp.com`, `*.azurewebsites.net` / `*.cloudapp.net`, `*.firebaseapp.com`, `*.elasticbeanstalk.com`, `*.zendesk.com`, `*.shopify.com`, `*.fastly.net`, `*.pantheon.io`, `*.surge.sh`, `*.ngrok.io`.
- Check DNS records for resources provisioned in Terraform/CloudFormation/Pulumi that were `destroy`ed without a matching `aws_route53_record` deletion — the most common drift source.
- Confirm A/AAAA records are not orphaned pointing at reclaimed EC2/Elastic IPs or released cloud VMs.
- For vanity/naked domains, verify the apex `A`/`ALIAS` does not point at a decommissioned load balancer or CDN distribution.
- Look for `CNAME` chains that flatten through a provider vanity domain whose underlying distribution/bucket was deleted while the record lingered.
- Verify certificate/private key material (ACM, `*.pem` in repo) is not left behind for subdomains whose resources are gone — these widen impact after takeover.
- Check whether dangling records point at services that allow arbitrary custom-domain registration without verifying prior ownership (GitHub Pages, Heroku, Surge, etc. — high takeover feasibility).

## Static signals
Infrastructure-as-Code orphan indicators:
- Terraform: a resource block referencing a record whose target was removed
  - `aws_route53_record { name = "app.example.com" records = ["examplebucket.s3.amazonaws.com"] }` with **no matching** `aws_s3_bucket` named `examplebucket`
  - `resource "aws_route53_record" "www" { ... records = ["yourname.github.io"] }` with no corroborating GitHub Pages config
- CloudFormation: `AWS::Route53::RecordSet` whose `HostedZoneName`/`AliasTarget` target stack was deleted (retain deletion policy leaving DNS behind).
- CDK/Pulumi: `ARecord`/`CnameRecord` constructs pointing at a `Bucket` or `Distribution` later removed from the stack while the record was retained.

CI/CD and deploy scripts that create DNS without teardown:
- `aws route53 change-resource-record-sets ...` in a deploy script with no inverse in a destroy/teardown target.
- GitHub Actions / GitLab CI steps that `heroku domains:add` or `gh api repos/.../pages` but never remove them on environment teardown.

Config files referencing custom domains for hosted services:
- `CNAME` file in a repo root (GitHub Pages custom domain) whose value is no longer in DNS or vice-versa.
- Firebase `.firebaserc` / `firebase.json` `"hosting": { "site": "..." }` paired with a DNS record but no live site.
- S3 static-website `WebsiteConfiguration` removed but the `aws_s3_bucket_website_configuration`-bound Route53 record persists.

Domain ownership/verification drift:
- `.well-known/` or `TXT` verification records (`_github-pages-challenge-*`, `google-site-verification`) referencing domains no longer controlled.
- SSL/TLS certs provisioned via Let's Encrypt DNS-01 leaving `_acme-challenge` CNAMEs after cert retirement.

## False positives
- The provider returns a generic landing/404 page but still validates ownership on re-creation (e.g., AWS CloudFront distributions always respond, but the distribution name is account-scoped — takeover requires the original account). Distinguish account-scoped namespaces from globally-first-come namespaces.
- The CNAME target is a third-party SaaS that **verifies domain ownership** (Zendesk, Shopify, WorkSpace) before serving — re-registration is blocked without the verification token.
- The record is intentionally transient (blue/green, DNS failover) and the alternate target is live — confirm both endpoints.
- A/AAAA records pointing at RFC1918/private space or a CDN that returns a benign 404 but is not a takeover candidate.
- The "dangling" record is a `MX`/`TXT`/`SPF` record — these are not directly takeable but may enable related email spoofing; out of scope for this perspective.

## Attack scenario
1. Attacker enumerates the victim's DNS zone (zone transfer, brute-force subdomain wordlists, CT logs, `subfinder`/`amass`) and finds `legacy.example.com CNAME examplecorp-static.herokuapp.com`.
2. Resolving the CNAME returns Heroku's "No such app" page — the Heroku app was deleted months ago but the Route53 record remains.
3. Attacker creates a new Heroku app named `examplecorp-static` (globally unique, no prior-ownership check) and registers `legacy.example.com` as its custom domain.
4. Heroku now serves attacker-controlled content from `https://legacy.example.com` using the victim's domain; modern browsers show a valid lock if the victim still holds a wildcard cert or the provider provisions one.
5. Attacker ships a credential-harvesting clone of the corporate login page, phishing victims who trust the `example.com` subdomain, and reads any cookies scoped to `.example.com` via the served page — pivoting into the primary application.

## Impact
- **Confidentiality**: cookies (incl. session/JWT scoped to parent domain), OAuth tokens, and any data the browser sends to the trusted subdomain are exposed to the attacker.
- **Integrity**: attacker serves arbitrary content, phishing pages, or malware under a brand-trusted, TLS-valid origin; can manipulate anyone trusting the subdomain.
- **Availability**: legitimate traffic to the subdomain can be redirected, defaced, or held for ransom.
- Severity is **High/Critical** when the dangling subdomain is cookie- or cert-adjacent to a sensitive apex (e.g., `auth.*`, `admin.*`, or shares a parent-domain cookie scope), turning takeover into account compromise or broader foothold.

## Remediation
Treat DNS records as code and couple their lifecycle to the resources they point at:
```hcl
# VULNERABLE — Route53 record outlives the bucket it points at
resource "aws_route53_record" "docs" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "docs.example.com"
  type    = "CNAME"
  records = ["docs-bucket.s3.amazonaws.com"]   # bucket later destroyed; record retained
}

# SAFE — record + target share a lifecycle, and remove on destroy
resource "aws_route53_record" "docs" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "docs.example.com"
  type    = "CNAME"
  ttl     = 60
  records = [aws_s3_bucket_website_configuration.docs.website_endpoint]

  lifecycle { prevent_destroy = false }   # Terraform destroy also removes this record
}
```
Run continuous DNS-asset monitoring (e.g., `subjack`, `nuclei` takeover templates, `can-i-take-over-xyz` fingerprints) against your zones, alert on any provider-known "claimable" fingerprint, and require a decommissioning checklist that deletes the DNS record in the same change set as the resource teardown — DNS hygiene is the only durable defense-in-depth here.

## References
- OWASP ASVS V14.x — Configuration and architecture (build/deploy integrity, environment separation)
- OWASP WSTG-CONF — Testing for infrastructure / subdomain takeover configuration
- OWASP Cheat Sheet Series: Cloud subdomain takeover (dangling-DNS fingerprints and remediation)
