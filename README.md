**Bitwarden Automation Lambda**

Proof of concept for automating Bitwarden organisation administration using the CLI (private Vault API) and the Public API running on AWS Lambdas. 

Infrastructure manually set up in AWS console for now:

- ECR registry 
- Lambda function
- IAM Role for lambda function to assume
- IAM Policy to allowing reading of secrets 
- SecetsManager Secrets: User vault: client id, client secret, master password. Organization: client id, client secret.


The Lambda must be setup with the env var:

```
BITWARDENCLI_APPDATA_DIR = /tmp
```

Otherwise the Bitwarden CLI will silently fail.

You need to increase the available memory to take advantage of async as more memory corresponds to more VCPUs. 512MB takes ~ 58s, 10240MB takes ~6s. You may need to adjust the timeout accordingly.

Lambda Input:

```json
{
  "collection_name": "test-collection-1",
  "collection_external_id": "ext-id-1234",
  "member_id": "86bf30cc-8887-4ee6-a0de-afd400e31971"
}
```

Rust tests require .env to be populated with valid credentials and require running with nightly (for mockable):

```rust
cargo +nightly test -- --nocapture
```
