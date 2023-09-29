use jsonwebtoken::{decode, errors, Algorithm, DecodingKey, Validation};
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

impl GoogleOAuthClaims {
    fn verify_google_jwt(
        token: &str,
        public_key: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())?;

        let _claims = decode::<Self>(token, &decoding_key, &Validation::new(Algorithm::RS256))?;

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

        Ok(public_key)
    }

    fn get_key_id_from_jwt(token: &str) -> String {
        let header = jsonwebtoken::decode_header(token).unwrap();
        println!("Header: {:?}", header);

        let key_id = match header.kid {
            Some(key_id) => key_id,
            None => panic!("Key ID not found in JWT header"),
        };

        key_id.to_string()
    }
    pub async fn decode_jwt(token: &str) -> Result<Self, errors::Error> {
        let key_id = Self::get_key_id_from_jwt(token);
        let pem = Self::fetch_google_public_key(&key_id).await.unwrap();
        println!("PEM: {}", pem);

        return Self::verify_google_jwt(token, &pem);
    }
}
