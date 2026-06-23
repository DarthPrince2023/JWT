use std::{env::VarError, fmt::Display, str::Utf8Error};
use regex::Error as RegexError;
use serde_json::Error as DeserializeError;
use base64_url::base64::DecodeError;

#[derive(Debug)]
pub enum Error {
    Base64DecodeError(DecodeError),
    EnvLoadError(VarError),
    DeserializationError(DeserializeError),
    Utf8ParseError(Utf8Error),
    LengthError(String),
    ExpiredToken,
    NotYetValidToken,
    InvalidSignature,
    InvalidLength(String, i16, i16, u64),
    InvalidValue(String, String),
    RegexError(String)
}

impl From<RegexError> for Error {
    fn from(value: RegexError) -> Self {
        Self::RegexError(value.to_string())
    }
}

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Self::Utf8ParseError(value)
    }
}

impl From<DecodeError> for Error {
    fn from(value: DecodeError) -> Self {
        Self::Base64DecodeError(value)
    }
}

impl From<VarError> for Error {
    fn from(value: VarError) -> Self {
        Self::EnvLoadError(value)
    }
}

impl From<DeserializeError> for Error {
    fn from(value: DeserializeError) -> Self {
        Self::DeserializationError(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64DecodeError(error) => write!(f, "Could not decode given data => {error}"),
            Self::EnvLoadError(error) => write!(f, "Error loading environment => {error}"),
            Self::DeserializationError(error) => write!(f, "Could not deserialize payload => {error}"),
            Self::Utf8ParseError(error) => write!(f, "Could not parse given bytes as UTF-8 => {error}"),
            Self::LengthError(error) => write!(f, "Invalid length at => {error}"),
            Self::ExpiredToken => write!(f, "This token has expired"),
            Self::NotYetValidToken => write!(f, "Token not yet active"),
            Self::InvalidSignature => write!(f, "Could not validate token by signature"),
            Self::InvalidLength(value, min_length, max_length, provided_length) => write!(f, "Invalid data value length => {value}, minimum => {min_length}, maximum => {max_length}, provided length => {provided_length}"),
            Self::RegexError(error) => write!(f, "Invalid value provided => {error}"),
            Self::InvalidValue(error, cause) => write!(f, "Invalid value provided => {error}; problem => {cause}")
        }
    }
}