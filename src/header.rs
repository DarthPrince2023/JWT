use serde::{Deserialize, Serialize};
use base64_url::encode;

use crate::errors::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: TokenType,
}

impl Header {
    pub fn new(alg: Algorithm, typ: TokenType) -> Result<Self, Error> {
        Ok(Self { alg, typ })
    }

    pub fn with_alg(&mut self, alg: Algorithm) -> &mut Self {
        self.alg = alg;

        self
    }

    pub fn with_typ(&mut self, typ: TokenType) -> &mut Self {
        self.typ = typ;

        self
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Algorithm {
    #[serde(rename = "HS256")]
    HS256
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TokenType {
    #[serde(rename = "JWT")]
    Jwt
}

impl Header {
    pub fn header(&self) -> Result<String, Error> {
        Ok(encode(&serde_json::to_string(self)?))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn can_parse_header() {
        let typ: String = serde_json::to_string(&TokenType::Jwt).unwrap();
        let header: Header = serde_json::from_str(r#"{"typ":"JWT","alg":{"name": "HS256"}}"#).unwrap();
        let header_type: String = serde_json::to_string(&header.typ).unwrap();

        assert_eq!(header_type, typ);
    }
}