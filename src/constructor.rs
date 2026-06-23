use chrono::Utc;
use hmac_crate::algorithms::hmac_sha_256::hmac_sha256;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeserializeError};
use subtle::ConstantTimeEq;

use crate::{
    header::Header, payload::Payload, errors::Error
};

fn deserialize_payload<'de, D>(deserializer: D) -> Result<Payload, D::Error> where D: Deserializer<'de> {
    let deserialize: String = Deserialize::deserialize(deserializer)?;
    let payload: Payload = serde_json::from_str(&deserialize)
        .map_err(|error| DeserializeError::custom(error.to_string()))?;
    
    Payload::check_bounds_of_data(&payload.username(), &payload.role, &payload.sub, &payload.iss, payload.nbf, payload.exp)
        .map_err(|error| DeserializeError::custom(error.to_string()))?;

    Ok(payload)
}

///
/// The constructor for a token 
/// 
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenPieces {
    header: Header,
    #[serde(deserialize_with = "deserialize_payload")]
    payload: Payload,
    // Check this when verifying the token, reject if invalid.
    signature: String
}

impl TokenPieces {
    pub fn new(
        header: Header,
        payload: Payload
    ) -> Self {
        Self {
            header,
            payload,
            signature: String::new()
        }
    }

    ///
    /// Returns the `'Header'` of a given token
    /// 
    pub fn get_header(&self) -> Header {
        self.header.clone()
    }

    /// 
    /// Returns the `'Payload'` of a given token
    /// 
    pub fn get_payload(&self) -> Payload {
        self.payload.clone()
    }

    ///
    /// Returns the signature of a token
    /// 
    pub fn get_signature(&self) -> String {
        self.signature.clone()
    }

    ///
    /// Create the JWT
    /// 
    pub fn build_jwt(&self, master_key: &str) -> Result<String, Error> {
        let data = format!("{}.{}", &self.get_header().header()?, &self.get_payload().payload()?);
        let output: String = base64_url::encode(&hmac_sha256(master_key.as_bytes().to_vec(), data.as_bytes().to_vec()));
        
        Ok(format!("{data}.{output}"))
    }

    ///
    /// Verify the token
    /// 
    pub fn verify_jwt(&self, master_key: &str, token: &str) -> Result<Self, Error> {
        let mut token = Self::try_from(token)?;
        let token_signature = token.get_signature();
        let data = format!("{}.{}", &self.get_header().header()?, &self.get_payload().payload()?);
        let signature = base64_url::encode(&hmac_sha256(master_key.as_bytes().to_vec(), data.as_bytes().to_vec()));
        let current_timestamp = Utc::now().timestamp();
        let check = bool::from(token_signature.as_bytes().ct_eq(signature.as_bytes()));
        
        if !check {
            return Err(Error::InvalidSignature);
        }

        if current_timestamp < token.payload.nbf {
            return Err(Error::NotYetValidToken)
        } else if current_timestamp > token.payload.exp {
            return Err(Error::ExpiredToken)
        }
        token.payload.set_is_active(true);
        
        let header = token.get_header();
        let payload = token.get_payload();

        Ok(Self { header, payload, signature })
    }
}

impl TryFrom<&str> for TokenPieces {
    fn try_from(token: &str) -> Result<Self, Self::Error> {
        let chunks: Vec<&str> = token.split(".").collect();
        
        if chunks.len() != 3 {
            return Err(Error::LengthError("Token length".into()))
        }

        let (header, payload,) = (base64_url::decode(chunks[0])?, base64_url::decode(chunks[1])?,);
        let header = serde_json::from_slice::<Header>(&header)?;
        let payload = serde_json::from_slice::<Payload>(&payload)?;
        let signature = chunks[2];

        

        if payload.exp < Utc::now().timestamp() {
            return Err(Error::ExpiredToken)
        }
        if signature.len() > 1_000 {
            return Err(Error::LengthError("Invalid algorithm name".into()))
        }

        Ok(Self { header, payload, signature: signature.into() })
    }
    
    type Error = Error;
}

#[cfg(test)]
pub mod test {
    use chrono::Utc;
    use uuid::Uuid;

    use crate::{constructor::TokenPieces, header::{Algorithm, Header, TokenType}, payload::Payload, };

    #[test]
    fn can_verify_jwt() {
        let now = Utc::now().timestamp();
        let header = Header::new(Algorithm::HS256, TokenType::Jwt).unwrap();
        let payload = Payload::new("Test auth".into(), now + 3600, "Test".into(), Uuid::new_v4(), "admin".into(), now, "test".into()).unwrap();
        let token = TokenPieces::new(header, payload);
        let token_string = &token.build_jwt("testing_key000000000000000000000").unwrap();
        let authentic = token
            .verify_jwt("testing_key000000000000000000000".into(), token_string)
            .unwrap()
            .payload
            .is_active;

        println!("This token is valid: {authentic}");
    }

    #[test]
    fn rejects_invalid_jwt_bad_role() {
        let now = Utc::now().timestamp();
        let payload = Payload::new("Test auth".into(), now + 3600, "Test".into(), Uuid::new_v4(), "Invalid role name".into(), now, "test".into());

        assert!(payload.is_err());
    }

    #[test]
    fn rejects_invalid_jwt_bad_username() {
        let now = Utc::now().timestamp();
        let payload = Payload::new("Some auth".into(), now + 3600, "Test".into(), Uuid::new_v4(), "admin".into(), now, "testing username this should be invalid, so something really long...".into());
        
        assert!(payload.is_err());
    }

    #[test]
    fn rejects_invalid_jwt_bad_subject() {
        let now = Utc::now().timestamp();
        let payload = Payload::new("123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901".into(), now + 3600, "Test".into(), Uuid::new_v4(), "admin".into(), now, "test".into());
        
        assert!(payload.is_err());
    }

    #[test]
    fn rejects_invalid_jwt_bad_issuer() {
        let now = Utc::now().timestamp();
        let payload = Payload::new("Some auth".into(), now + 3600, "Some bad issuer name with random numbers for padding 12345678901234567890123456789012345678901234567890".into(), Uuid::new_v4(), "admin".into(), now, "test".into());
        
        assert!(payload.is_err());
    }

    #[test]
    fn rejects_invalid_jwt_expired() {
        let now = Utc::now().timestamp();
        let payload = Payload::new("Some auth".into(), now - 1, "Test".into(), Uuid::new_v4(), "admin".into(), now, "test".into());
        
        assert!(payload.is_err());
    }

    #[test]
    fn rejects_invalid_jwt_not_yet_valid() {
        let now = Utc::now().timestamp();
        let payload = Payload::new("Some auth".into(), now + 3600, "Test".into(), Uuid::new_v4(), "admin".into(), now + 5, "testing".into());
        
        assert!(payload.is_err());
    }
}
