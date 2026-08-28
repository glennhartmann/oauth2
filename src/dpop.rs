use base64ct::LineEnding;
use ecdsa::{Signature, SigningKey, elliptic_curve::Generate, signature::Signer};
use p256::{
    NistP256, PublicKey, SecretKey,
    elliptic_curve::point::AffineCoordinates,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use rand::{
    SeedableRng, TryRng,
    rngs::{StdRng, SysRng},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The data from a public/private keypair that is relevant to DPoP creation.
pub struct KeyData {
    /// The x coordinate of the public key's elliptic curve point.
    public_key_x: Vec<u8>,

    /// The y coordinate of the public key's elliptic curve point.
    public_key_y: Vec<u8>,

    /// The signing key that corresponds to the private key which is paired with the above public
    /// key data.
    signing_key: SigningKey<NistP256>,
}

impl KeyData {
    /// Creates a new `KeyData`.
    pub fn new(
        public_key_x: Vec<u8>,
        public_key_y: Vec<u8>,
        signing_key: SigningKey<NistP256>,
    ) -> Self {
        Self {
            public_key_x,
            public_key_y,
            signing_key,
        }
    }
}

impl From<&Keypair> for KeyData {
    /// Extracts `KeyData` from a `Keypair`.
    fn from(keypair: &Keypair) -> Self {
        let signing_key = SigningKey::from(&keypair.private_key);

        let public_key_affine_point = keypair.public_key.as_affine();
        let (public_key_x, public_key_y) =
            (public_key_affine_point.x(), public_key_affine_point.y());

        KeyData::new(public_key_x.to_vec(), public_key_y.to_vec(), signing_key)
    }
}

/// A public/private keypair.
pub struct Keypair {
    /// The public key.
    public_key: PublicKey,

    /// The private key.
    private_key: SecretKey,
}

impl Keypair {
    /// Creates a new `Keypair`.
    pub fn new(public_key: PublicKey, private_key: SecretKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Generates a new secure random P-256 elliptic curve public/private keypair.
    pub fn generate() -> anyhow::Result<Keypair> {
        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let private_key = SecretKey::generate_from_rng(&mut rng);

        Ok(Keypair {
            public_key: private_key.public_key(),
            private_key,
        })
    }
}

impl TryFrom<&KeypairPemPkcs8> for Keypair {
    type Error = &'static str;

    /// Attempts to decode a PEM PKCS#8 encoded keypair.
    fn try_from(keypair_pem_pkcs8: &KeypairPemPkcs8) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: PublicKey::from_public_key_pem(&keypair_pem_pkcs8.public_key)
                .map_err(|_| "failed to parse public key")?,
            private_key: SecretKey::from_pkcs8_pem(&keypair_pem_pkcs8.private_key)
                .map_err(|_| "failed to parse private key")?,
        })
    }
}

/// PEM PKCS#8 encoded public/private keypair.
pub struct KeypairPemPkcs8 {
    /// The PEM PKCS#8 encoded public key.
    pub public_key: String,

    /// The PEM PKCS#8 encoded private key.
    pub private_key: Zeroizing<String>,
}

impl KeypairPemPkcs8 {
    /// Creates a new `KeypairPemPkcs8`.
    pub fn new(public_key: String, private_key: Zeroizing<String>) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

impl TryFrom<&Keypair> for KeypairPemPkcs8 {
    type Error = &'static str;

    /// Attempts to convert a `Keypair` into a `KeypairPemPkcs8`.
    fn try_from(keypair: &Keypair) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: keypair
                .public_key
                .to_public_key_pem(LineEnding::default())
                .map_err(|_| "failed to convert public key to PEM")?,
            private_key: keypair
                .private_key
                .to_pkcs8_pem(LineEnding::default())
                .map_err(|_| "failed to convert private key to PKCS#8 PEM")?,
        })
    }
}

/// The DPoP header, as defined at
/// <https://developers.google.com/identity/protocols/oauth2/native-app#constructing-dpop-proof>.
#[derive(Serialize)]
struct DpopHeader<'a> {
    /// Type of DPoP. Must always be "dpop+jwt".
    typ: &'a str,

    /// The algorithm used in the DPoP. Must always be "ES256".
    alg: &'a str,

    /// The DPoP's JSON Web Key.
    jwk: Jwk<'a>,
}

impl<'a> From<&KeyData> for DpopHeader<'a> {
    /// Creates a `DPoP` header from `KeyData`.
    fn from(key_data: &KeyData) -> Self {
        Self {
            typ: "dpop+jwt",
            alg: "ES256",
            jwk: key_data.into(),
        }
    }
}

/// A JSON Web Key for a DPoP, as defined at
/// <https://developers.google.com/identity/protocols/oauth2/native-app#constructing-dpop-proof>.
#[derive(Serialize)]
struct Jwk<'a> {
    /// Key type. Must be "EC".
    kty: &'a str,

    /// The Base64URL-encoded x coordinate of the public key's elliptic curve point.
    x: String,

    /// The Base64URL-encoded y coordinate of the public key's elliptic curve point.
    y: String,

    /// Elliptic curve type. Must be "P-256".
    crv: &'a str,
}

impl<'a> From<&KeyData> for Jwk<'a> {
    /// Creates a new `Jwk` from `KeyData`.
    fn from(key_data: &KeyData) -> Self {
        Self {
            kty: "EC",
            x: base64_url::encode(&key_data.public_key_x),
            y: base64_url::encode(&key_data.public_key_y),
            crv: "P-256",
        }
    }
}

/// DPoP payload, as defined at
/// <https://developers.google.com/identity/protocols/oauth2/native-app#constructing-dpop-proof>.
#[derive(Serialize)]
struct DpopPayload<'a> {
    /// "JWT ID". For auth exchanges, this must be `BASE64URL(SHA256(AUTHORIZATION_CODE))`. For
    /// refresh exchanges, it must be a unique (never reused) request identifier.
    jti: &'a str,

    /// HTTP method. Must be "POST".
    htm: &'a str,

    /// HTTP URL. Must match the URL that this request is being sent to.
    htu: &'a str,

    /// Current time as a UNIX timestamp in seconds.
    iat: i64,

    /// DPoP nonce returned in the previous request, or None if this is the first request.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

impl<'a> DpopPayload<'a> {
    /// Creates a new `DpopPayload`.
    fn new(jti: &'a str, token_server_url: &'a str, nonce: Option<&'a str>) -> Self {
        Self {
            jti,
            htm: "POST",
            htu: token_server_url,
            iat: chrono::Local::now().timestamp(),
            nonce,
        }
    }
}

/// Creates a DPoP for an auth request.
pub fn create_auth(
    key_data: &KeyData,
    auth_code: &str,
    token_server_url: &str,
) -> anyhow::Result<String> {
    let jti = &base64_url::encode(&Sha256::digest(auth_code));
    create(key_data, token_server_url, None /* nonce */, jti)
}

/// Creates a DPoP for a refresh request.
pub fn create_refresh(
    key_data: &KeyData,
    token_server_url: &str,
    nonce: &str,
) -> anyhow::Result<String> {
    create(
        key_data,
        token_server_url,
        Some(nonce),
        &create_random_jti()?,
    )
}

/// Creates a DPoP with the given `jti`, as described at
/// <https://developers.google.com/identity/protocols/oauth2/native-app#constructing-dpop-proof>.
pub fn create(
    key_data: &KeyData,
    token_server_url: &str,
    nonce: Option<&str>,
    jti: &str,
) -> anyhow::Result<String> {
    let dpop_header: DpopHeader = key_data.into();
    let dpop_header_json = serde_json::to_string(&dpop_header)?;
    let encoded_dpop_header = base64_url::encode(&dpop_header_json);

    let dpop_payload = DpopPayload::new(jti, token_server_url, nonce);
    let dpop_payload_json = serde_json::to_string(&dpop_payload)?;
    let encoded_dpop_payload = base64_url::encode(&dpop_payload_json);

    let unsigned_dpop = format!("{}.{}", encoded_dpop_header, encoded_dpop_payload);
    let signature: Signature<NistP256> = key_data.signing_key.try_sign(unsigned_dpop.as_bytes())?;
    let raw_signature_bytes_struct = signature.to_bytes();
    let raw_signature_bytes = raw_signature_bytes_struct.as_slice();

    let encoded_raw_signature = base64_url::encode(raw_signature_bytes);
    let dpop = format!("{}.{}", unsigned_dpop, encoded_raw_signature);

    Ok(dpop)
}

/// Generate 128 cryptographically random bytes, then Base64URL-encode them. The JTI appears to
/// accept only characters within the base64 alphabet, despite there being no documentation to that
/// effect.
fn create_random_jti() -> anyhow::Result<String> {
    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    let mut jti = [0; 128];
    rng.try_fill_bytes(&mut jti);
    Ok(base64_url::encode(&jti))
}
