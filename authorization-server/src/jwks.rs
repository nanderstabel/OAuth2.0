use axum::response::Json;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::PublicKeyParts;
use rsa::pkcs8::DecodePublicKey; // Import the DecodePublicKey trait for PKCS#8
use serde::Serialize;
use std::fs;
use tracing;

#[derive(Serialize)]
struct Jwk {
    kty: String,
    kid: String,
    use_: String,
    alg: String,
    n: String,
    e: String,
}

#[derive(Serialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

pub async fn jwks() -> Json<Jwks> {
    // Read the public key from the `public.pem` file
    let public_key_pem = fs::read_to_string("public.pem").expect("Failed to read public.pem");

    // Parse the public key to extract the modulus (n) and exponent (e)
    let public_key = rsa::RsaPublicKey::from_public_key_pem(&public_key_pem)
        .expect("Failed to parse public key");

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    tracing::info!("Constructing JWKS with modulus (n): {}", n);
    tracing::info!("Constructing JWKS with exponent (e): {}", e);

    // Construct the JWK
    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: "key-id-1".to_string(),
        use_: "sig".to_string(),
        alg: "RS256".to_string(),
        n,
        e,
    };

    Json(Jwks { keys: vec![jwk] })
}
