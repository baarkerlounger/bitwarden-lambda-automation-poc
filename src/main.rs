use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> Result<(), Error> {
    aws::init_lambda_tracing();
    run(service_fn(function_handler)).await?;
    Ok(())
}

async fn function_handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let organization_id = String::from("a325f354-6cf1-5187-af18-af8211e56bbf");
    let vault_client_id = aws::get_sm_secret_value("bw-vault-api-client-id").await;
    let vault_client_secret = aws::get_sm_secret_value("bw-vault-api-client-secret").await;
    let password = aws::get_sm_secret_value("bw-master-password").await;
    let org_client_id = aws::get_sm_secret_value("bw-org-api-client-id").await;
    let org_client_secret = aws::get_sm_secret_value("bw-org-api-client-secret").await;

    let login_response = bw_cli::cli_login(vault_client_id, vault_client_secret)
        .await
        .unwrap();
    println!("{:?}", login_response);

    let session_token = bw_cli::unlock(password).await.unwrap();

    let (event, _context) = event.into_parts();
    let collection_name = event["collection_name"].as_str().unwrap();
    let collection_external_id = event["collection_external_id"].as_str().unwrap_or("123");

    let create_collection_response = bw_cli::create_collection(
        &collection_name,
        &collection_external_id,
        &session_token,
        &organization_id,
    )
    .await?;

    let collection: Value = serde_json::from_str(&create_collection_response).unwrap();
    let collection_id = collection["id"].as_str().unwrap();
    let group_name: &str = &[collection_id, "-group"].concat();
    let create_group_response = bw_public_api::create_group(
        &org_client_id,
        &org_client_secret,
        group_name,
        collection_id,
    )
    .await?;

    let group: Value = serde_json::from_str(&create_group_response).unwrap();
    let group_id = group["id"].as_str().unwrap();
    let member_id = event["member_id"].as_str().unwrap();
    bw_public_api::add_member_to_group(&org_client_id, &org_client_secret, member_id, group_id)
        .await?;

    let logout_response = bw_cli::cli_logout().await.unwrap();
    println!("{:?}", logout_response);

    Ok(json!({
        "message":
            format!(
                "Created collection, {} and added member {}!",
                collection_name, member_id
            )
    }))
}

mod bw_cli {
    use base64::{engine::general_purpose, Engine as _};
    use lambda_runtime::Error;
    use serde::Serialize;
    use std::process::Command;

    pub async fn cli_login(client_id: String, client_secret: String) -> Result<String, Error> {
        let output = Command::new("./bw")
            .args(&["login", "--apikey"])
            .env("BW_CLIENTID", client_id)
            .env("BW_CLIENTSECRET", client_secret)
            .output()
            .expect("Couldn't log in to Bitwarden");
        let parsed = String::from_utf8(strip_ansi_escapes::strip(output.stdout).unwrap()).unwrap();
        Ok(parsed)
    }

    pub async fn cli_logout() -> Result<String, Error> {
        let output = Command::new("./bw")
            .args(&["logout"])
            .output()
            .expect("Couldn't logout");
        let parsed = String::from_utf8(strip_ansi_escapes::strip(output.stdout).unwrap()).unwrap();
        Ok(parsed)
    }

    pub async fn unlock(password: String) -> Result<String, Error> {
        let output = Command::new("./bw")
            .args(&["unlock", &password])
            .output()
            .expect("Couldn't unlock");
        let parsed = String::from_utf8(strip_ansi_escapes::strip(output.stdout).unwrap()).unwrap();
        let mut split: Vec<&str> = parsed.split_whitespace().collect();
        let session_token = split.pop().expect("No session token").to_string();
        Ok(session_token)
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CollectionTemplate {
        organization_id: String,
        name: String,
        external_id: String,
    }

    pub async fn create_collection(
        name: &str,
        external_id: &str,
        session_token: &str,
        organization_id: &str,
    ) -> Result<String, Error> {
        let collection_template = CollectionTemplate {
            organization_id: organization_id.to_string(),
            name: name.to_string(),
            external_id: external_id.to_string(),
        };
        let json_template = serde_json::to_string(&collection_template)?;
        let base64_template = general_purpose::STANDARD.encode(&json_template);

        // You have to pass organizationid as a CLI arg even though it's also encoded in the
        // org-collection template
        let output = Command::new("./bw")
            .args(&[
                "create",
                "org-collection",
                &format!("--organizationid={}", &organization_id),
                &base64_template,
                "--session",
                &session_token,
            ])
            .output()
            .expect("Couldn't create collection");
        let parsed = String::from_utf8(strip_ansi_escapes::strip(output.stdout).unwrap()).unwrap();
        Ok(parsed)
    }
}

mod bw_public_api {
    use lambda_runtime::Error;
    use oauth2::basic::BasicClient;
    use oauth2::reqwest::async_http_client;
    use oauth2::TokenResponse;
    use oauth2::{AuthUrl, ClientId, ClientSecret, Scope, TokenUrl};
    use reqwest::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        Client as ReqwestClient,
    };
    use serde_json::{Map, Value};

    pub async fn public_api_token(client_id: &str, client_secret: &str) -> String {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new("https://identity.bitwarden.com/connect/token".to_string()).unwrap(),
            Some(
                TokenUrl::new("https://identity.bitwarden.com/connect/token".to_string()).unwrap(),
            ),
        );

        let token_result = client
            .exchange_client_credentials()
            .add_scope(Scope::new("api.organization".to_string()))
            .request_async(async_http_client)
            .await
            .expect("Failed to get token");
        token_result.access_token().secret().to_string()
    }

    pub async fn create_group(
        client_id: &str,
        client_secret: &str,
        group_name: &str,
        collection_id: &str,
    ) -> Result<String, Error> {
        let auth_header: &str =
            &["Bearer ", &public_api_token(client_id, client_secret).await].concat();
        let mut body = Map::new();
        let mut collections: Vec<Value> = Vec::new();
        let mut collection = Map::new();
        collection.insert("id".to_string(), Value::String(collection_id.to_string()));
        collection.insert("readOnly".to_string(), Value::Bool(false));
        collections.push(Value::Object(collection));
        body.insert("name".to_string(), Value::String(group_name.to_string()));
        body.insert("accessAll".to_string(), Value::Bool(false));
        body.insert(
            "externalId".to_string(),
            Value::String(String::from("dummy value")),
        );
        body.insert("collections".to_string(), Value::Array(collections));

        let client = ReqwestClient::new();
        let req = client
            .post("https://api.bitwarden.com/public/groups")
            .header(AUTHORIZATION, auth_header)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;
        let res = req.text().await?;

        Ok(res)
    }

    pub async fn add_member_to_group(
        client_id: &str,
        client_secret: &str,
        member_id: &str,
        group_id: &str,
    ) -> Result<String, Error> {
        let auth_header: &str =
            &["Bearer ", &public_api_token(client_id, client_secret).await].concat();
        let client = ReqwestClient::new();
        let req = client
            .get(format!(
                "https://api.bitwarden.com/public/members/{}/group-ids",
                member_id
            ))
            .header(AUTHORIZATION, auth_header)
            .send()
            .await?;
        let res = req.text().await?;
        let mut members_group_ids: Value = serde_json::from_str(&res).unwrap();
        members_group_ids
            .as_array_mut()
            .expect("Failed to retrieve group list")
            .push(group_id.into());
        let mut group_ids = Map::new();
        group_ids.insert("groupIds".to_string(), members_group_ids);
        let req = client
            .put(format!(
                "https://api.bitwarden.com/public/members/{}/group-ids",
                member_id
            ))
            .header(AUTHORIZATION, auth_header)
            .json(&group_ids)
            .send()
            .await?;
        let res = req.text().await?;

        Ok(res)
    }
}

mod aws {
    use aws_sdk_secretsmanager::Client;
    use std::collections::HashMap;

    pub async fn get_sm_secret_value(secret_id: &str) -> String {
        let config = aws_config::from_env().region("eu-west-2").load().await;
        let client = Client::new(&config);

        let resp = client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .unwrap();

        let secret_string = resp.secret_string().unwrap();
        let parsed_response =
            serde_json::from_str::<HashMap<String, String>>(secret_string).unwrap();

        parsed_response.values().collect::<Vec<_>>()[0].to_string()
    }

    pub fn init_lambda_tracing() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            // disable printing the name of the module in every log line.
            .with_target(false)
            // disabling time is handy because CloudWatch will add the ingestion time.
            .without_time()
            .init();
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use dotenvy::dotenv;
    use lambda_runtime::Context;
    use std::env;

    #[tokio::test]
    async fn cli_login_test() {
        dotenv().expect(".env file not found");
        let client_id =
            env::var("VAULT_API_CLIENT_ID").expect("VAULT_API_CLIENT_ID not found in .env");
        let client_secret =
            env::var("VAULT_API_CLIENT_SECRET").expect("VAULT_API_CLIENT_SECRET not found in .env");
        let result = bw_cli::cli_login(client_id, client_secret).await.unwrap();
        assert_eq!(result.contains("You are logged in!"), true);
        let result = bw_cli::cli_logout().await.unwrap();
        assert_eq!(result.contains("You have logged out"), true);
    }
}
