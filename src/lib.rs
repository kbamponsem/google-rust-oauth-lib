use jsonwebtoken::{
    decode,
    errors::{self},
    Algorithm, DecodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleOAuthClaims {
    pub iss: String,
    pub aud: String,
    pub azp: String,
    pub exp: usize,
    pub iat: usize,
    pub sub: String,
    pub email: String,
    pub at_hash: String,
    pub email_verified: bool,
    pub name: String,
    pub picture: String,
    pub given_name: String,
    pub family_name: String,
    pub locale: String,
}

struct Params {
    kid: String,
    algorithm: Algorithm,
}

impl From<Header> for Params {
    fn from(value: Header) -> Self {
        let kid = match value.kid {
            Some(kid) => kid,
            None => panic!("No kid found in header"),
        };

        let algorithm = value.alg;

        Params { kid, algorithm }
    }
}

impl GoogleOAuthClaims {
    fn verify_google_jwt(
        token: &str,
        public_key: &str,
        algorithm: Algorithm,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        println!(
            r#"
        Received: 
            token: {}
            public_key: {}
            algorithm: {:?}
        "#,
            token, public_key, algorithm
        );
        let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())?;

        let _claims = decode::<Self>(token, &decoding_key, &Validation::new(algorithm))?;

        return Ok(_claims.claims);
    }
    async fn fetch_google_public_key(key_id: &str) -> Result<String, String> {
        let url = "https://www.googleapis.com/oauth2/v1/certs";

        // Send a GET request to the public keys endpoint
        let response = reqwest::get(url).await.unwrap();

        // Check if the request was successful
        let response = response.error_for_status().unwrap();

        // Parse the JSON response
        let json: Value = response.json().await.unwrap();

        // Extract the public key for the specified key ID
        let public_key = match json.as_object() {
            Some(keys) => match keys.get(key_id) {
                Some(key) => {
                    if let Some(key_str) = key.as_str() {
                        Ok(key_str.to_string())
                    } else {
                        Err("Public key is not a string".to_string())
                    }
                }
                None => Err("Key ID not found in JSON response".to_string()),
            },
            None => Err("JSON response is not an object".to_string()),
        }?;

        // Return the public key and trim any whitespace
        Ok(public_key.trim().to_string())
    }

    fn get_params_from_token(token: &str) -> Result<Params, errors::Error> {
        let header = jsonwebtoken::decode_header(token)?;
        println!("Header: {:?}", header);

        let params: Params = header.into();

        Ok(params)
    }
    pub async fn decode_jwt(token: &str) -> Result<Self, errors::Error> {
        let params = Self::get_params_from_token(token)?;
        let kid = params.kid;
        let pem = Self::fetch_google_public_key(&kid).await.unwrap();

        return Self::verify_google_jwt(token, &pem, params.algorithm);
    }
}
