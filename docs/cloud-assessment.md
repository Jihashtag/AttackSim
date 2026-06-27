# Credentialed Cloud Assessment

Every module in the toolkit runs credential-free by default. The **credentialed cloud
path** is the one deliberate, opt-in exception — and even then the toolkit **never
accepts cloud keys from you**. Instead it reproduces what a real attacker who lands on a
compromised host actually does: it **discovers** whatever cloud credentials the host
already holds and operates as that identity.

## Credential discovery

Sources ([`sandbox/cloud_creds.py`](../sandbox/cloud_creds.py) + [`sandbox/cloud_creds_extended.py`](../sandbox/cloud_creds_extended.py)):

- EC2/GCE/Azure **instance-metadata role** (IMDSv2 first)
- On-disk profiles (`~/.aws/credentials`, `~/.config/gcloud`, `~/.azure`)
- `AWS_*`, `GOOGLE_*`, `AZURE_*` environment variables
- Extended providers: `SCW_*`, `OVH_*`, `OCI_CLI_*`, `NUTANIX_*`, `DIGITALOCEAN_*`,
  `HCLOUD_*`, `LINODE_*`, `VULTR_*`, `ALIBABA_CLOUD_*`, `CONFLUENT_*` env vars
- Extended config files: `~/.config/scw/`, `~/.oci/config`, `~/.config/doctl/`,
  `~/.config/linode-cli`, `~/.confluent/config.json`

Discovery runs **before** the credential guard scrubs the environment; the in-memory
inventory is then handed **only** to the cloud modules. Every other module still runs
credential-free, and credentials are never written to the report.

## Activation

The cloud path is **dormant unless something is discovered**. With no ambient credentials
present, the modules do nothing.

```bash
# Discover ambient cloud credentials and run read-only recon + active IAM analysis:
python3 main.py --use-discovered-cloud-creds

# Skip instance metadata (env vars + on-disk profiles only):
python3 main.py --use-discovered-cloud-creds --no-imds

# Add the harmless, persistent grant-nothing principal proof:
python3 main.py --use-discovered-cloud-creds --prove-access
```

## Cloud modules

| Module | What it does | Outcome = EXPLOITED when… |
|---|---|---|
| `cloud-recon` | Validates the discovered credential (`sts:GetCallerIdentity` / GCP project list / Azure subscription list) and enumerates IAM inventory | a discovered credential authenticates |
| `cloud-enum` | Enumerates internet-exposed resources — EC2 with public IPs, open security groups, public RDS. Every action is read-only-guarded **before** signing | a public EC2/RDS or world-open security group is found |
| `cloud-service-exposure` | Application-service exposure: Lambda public function-URLs (`AuthType: NONE`), SNS/SQS `Principal:*` policies, Secrets Manager enumeration + public resource policies, SSM parameters, KMS world-open key policies, Transfer Family `PUBLIC` SFTP endpoints. Never fetches secret **values** | a public function-URL/policy or world-open resource is found |
| `cloud-iam-analyzer` | Resolves *effective permissions* via `iam:SimulatePrincipalPolicy` / `testIamPermissions`, walks role-assumption chains, simulates known IAM privilege-escalation primitives | a sensitive permission is allowed or a privesc primitive is reachable |
| `cloud-posture` | Read-only security-posture review: CloudTrail, public AMIs/EBS snapshots, IAM password policy, root access keys, MFA | a critical posture gap is found |
| `cloud-pivot` | Maps SSM-reachable EC2 instances and their subnet peers; simulates `ssm:SendCommand`/`StartSession` (NEVER executed) | a simulated SSM path to internal hosts is reachable |
| `cloud-multicloud-enum` | Resource enumeration on extended providers (Scaleway, DigitalOcean, Hetzner, Linode, Vultr, Confluent Cloud) using discovered credentials | accessible resources found on at least one provider |
| `public-storage-enum` | Anonymously-listable public S3/GCS/Azure storage buckets | a public bucket is listable |
| `access-prover` (cloud) | Creates one grant-nothing principal (off unless `--prove-access`) | a persistent grant-nothing principal is created |
| `waf-firewall-proof` (cloud) | Creates a lowest-priority allow rule on WAFs/firewalls proving write access (off unless `--prove-access`) | rule successfully added |

## Extended cloud providers

The `cloud-multicloud-enum` module and `sandbox/cloud_creds_extended.py` add support for:

| Provider | Credential discovery | Enumeration |
|---|---|---|
| **OVH** | `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` | Projects, instances, storage, databases, networks, users |
| **Scaleway** | `SCW_ACCESS_KEY`, `SCW_SECRET_KEY`, `~/.config/scw/config.yaml` | Instances, buckets, databases, Kubernetes clusters |
| **OCI (Oracle)** | `OCI_CLI_TENANCY`, `OCI_CLI_USER`, `~/.oci/config` | Compute instances, VCNs, security lists, object storage, databases, IAM users |
| **Nutanix** | `NUTANIX_ENDPOINT`, `NUTANIX_USERNAME`, `NUTANIX_PASSWORD` | VMs, clusters, subnets, Flow security rules, projects |
| **DigitalOcean** | `DIGITALOCEAN_ACCESS_TOKEN`, `~/.config/doctl/config.yaml` | Droplets, spaces, databases, Kubernetes, firewalls |
| **Hetzner** | `HCLOUD_TOKEN` | Servers, volumes, firewalls |
| **Linode** | `LINODE_TOKEN`, `~/.config/linode-cli` | Instances, node balancers, object storage, databases |
| **Vultr** | `VULTR_API_KEY` | Instances, block storage, Kubernetes, firewalls, databases |
| **Alibaba Cloud** | `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALICLOUD_ACCESS_KEY` | ECS instances, security groups, RDS databases, SLB load balancers |
| **Confluent Cloud** | `CONFLUENT_CLOUD_API_KEY`, `~/.confluent/config.json` | Environments, clusters, service accounts |

### Network appliance credentials

| Provider | Credential discovery | Enumeration |
|----------|---------------------|-------------|
| **F5 BIG-IP** | `F5_HOST`, `F5_USER`, `F5_PASSWORD`, `F5_TOKEN` | Virtual servers, pools, nodes, iRules, ASM/WAF policies, firewall policies |
| **Fortinet FortiGate** | `FORTIOS_HOST`, `FORTIOS_ACCESS_TOKEN` | Firewall policies, interfaces, routes, VPN tunnels, SSL-VPN |
| **Cisco Meraki** | `MERAKI_DASHBOARD_API_KEY` | Organizations, networks, devices, L3 firewall rules |
| **Cisco ASA/FTD** | `CISCO_ASA_HOST`, `CISCO_ASA_USER`, `CISCO_ASA_PASSWORD` | Interfaces, ACLs, static routes |
| **Cisco ISE** | `ISE_HOST`, `ISE_USER`, `ISE_PASSWORD` | Network devices, endpoint groups |
| **Cisco Catalyst Center** | `DNAC_HOST`, `DNAC_USER`, `DNAC_PASSWORD` | Network devices, site topology |

All enumeration is **read-only** (list/describe only). Credential discovery follows the
same ambient-search model as AWS/GCP/Azure: env vars → config files → IMDS.

## IAM privilege-escalation analysis

`cloud-iam-analyzer` answers *"what can this identity actually do, and where can it
pivot?"* — without mutating the account:

- `SimulatePrincipalPolicy`/`testIamPermissions` evaluate policy without performing
  any action.
- `AssumeRole` only issues temporary credentials *to the assessor* (changes nothing).
- The walk is depth- and count-bounded (`CLOUD_MAX_ASSUME_DEPTH`, `CLOUD_MAX_PRINCIPALS`).

Privesc rules are defined in [`data/iam/privesc_rules.json`](../data/iam/privesc_rules.json).

## Grant-nothing proof (cloud)

Under `--prove-access`, `access-prover` creates the cloud equivalent of a `/tmp`
marker file — a single principal that grants nothing:

| Provider | Artifact | Guardrails |
|---|---|---|
| **AWS** | IAM user `sectest-proof-grant-nothing-*` with explicit deny-all inline policy, no access key | tagged `AUTHORIZED-ASSESSMENT=safe-to-delete` |
| **GCP** | Service account with no keys and no role bindings | labelled for discovery |
| **Azure** | Custom role definition with empty permissions and no assignment | labelled for discovery |

Hard guardrails (enforced in code):

- **Simulate-first:** the create is only attempted if the create permission simulates
  as *allowed*; otherwise skipped.
- **Forbidden, always:** creating any usable credential (`CreateAccessKey`,
  `CreateLoginProfile`, `serviceAccountKeys`, role *assignments*), attaching any *allow*
  policy, or touching any existing principal.

Policy documents: [`policies/`](../policies/) (`aws_iam_grant_nothing.json`,
`gcp_iam_grant_nothing.json`, `azure_role_grant_nothing.json`).
