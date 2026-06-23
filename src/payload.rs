use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use base64_url::encode;
use serde_json;
use uuid::Uuid;

use crate::errors::Error;

#[derive(Debug, Deserialize, Serialize)]
pub enum ReservedClaims<'b> {
    #[serde(rename = "exp")]
    ExpirationTime,
    #[serde(rename = "iss")]
    Issuer,
    #[serde(rename = "sub")]
    Subject,
    #[serde(rename = "aud")]
    Audience,
    Other(&'b str)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadBytes<'b>(&'b str);

impl<'b> From<&'b str> for PayloadBytes<'b> {
    fn from(data: &'b str) -> Self {
        Self(data)
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Payload {
    pub sub: String,
    pub exp: i64,
    pub iss: String,
    pub nbf: i64,
    pub jti: Uuid,
    pub role: String,
    pub is_active: bool,
    pub username: String
}

impl Payload {
    pub fn new(
        subject: String,
        expiration: i64,
        issuer: String,
        jti: Uuid,
        role: String,
        not_valid_before: i64,
        username: String
    ) -> Result<Self, Error> {
        Payload::check_bounds_of_data(&username, &role, &subject, &issuer, not_valid_before, expiration)?;

        Ok(Self {
            sub: subject,
            exp: expiration,
            iss: issuer,
            jti,
            role,
            nbf: not_valid_before,
            is_active: false,
            username
        })
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn set_username(&mut self, username: String) -> Result<&mut Self, Error> {
        if Self::validate_input(&username, &String::from("^[A-Za-z0-9]{1,50}$"))? {
            self.username = username;
        }

        Ok(self)
    }

    pub fn payload(&self) -> Result<String, Error> {
        Ok(encode(&serde_json::to_string(self)?))
    }

    pub fn set_jti(&mut self, jti: Uuid) -> &mut Self {
        self.jti = jti;

        self
    }

    pub fn jti(&self) -> Uuid {
        self.jti
    }

    pub fn set_is_active(&mut self, is_active: bool) -> &mut Self {
        self.is_active = is_active;

        self
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn set_subject(&mut self, subject: String) -> Result<&mut Self, Error> {
        if Self::validate_input(&subject, &String::from("^[A-Za-z0-9\\s]{1,200}$"))? {
            self.sub = subject;
        }

        Ok(self)
    }

    pub fn subject(&self) -> &String {
        &self.sub
    }

    pub fn set_expiration(&mut self, expiration: i64) -> Result<&mut Self, Error> {
        if expiration < Utc::now().timestamp() {
            return Err(Error::ExpiredToken)
        }
        self.exp = expiration;

        Ok(self)
    }

    pub fn expiration(&self) -> i64 {
        self.exp
    }

    pub fn set_issuer(&mut self, issuer: String) -> Result<&mut Self, Error> {
        if Self::validate_input(&issuer, &String::from("^[A-Za-z0-9]{1,100}$"))? {
            self.iss = issuer;
        }

        Ok(self)
    }

    pub fn issuer(&self) -> &String {
        &self.iss
    }

    pub fn set_not_valid_before(&mut self, not_valid_before: i64) -> Result<&mut Self, Error> {
        if not_valid_before > Utc::now().timestamp() {
            return Err(Error::NotYetValidToken)
        }
        self.nbf = not_valid_before;

        Ok(self)
    }

    pub fn not_valid_before(&self) -> i64 {
        self.nbf
    }

    pub fn validate_input(value: &str, pattern: &str) -> Result<bool, Error> {
        let regex = Regex::new(pattern)?;
        
        if regex.captures(value).is_some() {
            Ok(true)
        } else {
            Err(Error::InvalidValue(String::from(value), String::from("Invalid value provided")))
        }
    }

    pub fn check_bounds_of_data(
        username: &str,
        role: &str,
        subject: &str,
        issuer: &str,
        not_valid_before: i64,
        expiration: i64
    ) -> Result<(), Error> {
        if !Self::validate_input(username, &String::from("^[A-Za-z0-9]{1,50}$"))? {
            return Err(Error::InvalidLength("Username".into(), 1, 50, username.len() as u64))
        }
        if !Self::validate_input(subject, &String::from("^[A-Za-z0-9\\s]{1,200}$"))? {
            return Err(Error::InvalidLength("Subject".into(), 1, 200, subject.len() as u64))
        }
        if !Self::validate_input(role, &String::from("^[A-Za-z0-9]{1,15}$"))? {
            return Err(Error::InvalidLength("Role".into(), 1, 15, role.len() as u64))
        }
        if !Self::validate_input(issuer, &String::from("^[A-Za-z0-9]{1,100}$"))? {
            return Err(Error::InvalidLength("Issuer".into(), 1, 100, issuer.len() as u64))
        }
        if expiration < Utc::now().timestamp() {
            return Err(Error::ExpiredToken)
        }
        if not_valid_before > Utc::now().timestamp() {
            return Err(Error::NotYetValidToken)
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    pub fn cannot_set_invalid_issuer() {
        let mut payload = Payload::default();
        let payload = payload.set_issuer("INVALID Username".to_string());

        assert!(payload.is_err());
    }

    #[test]
    pub fn cannot_set_invalid_subject() {
        let mut payload = Payload::default();
        let payload = payload.set_subject("Invalidl.''.'.subject".to_string());

        assert!(payload.is_err());
    }
}