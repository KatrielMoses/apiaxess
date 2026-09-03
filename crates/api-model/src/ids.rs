//! Strong opaque identifiers and endpoint-key value types.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::error::ModelError;

macro_rules! opaque_id {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("Stable opaque identifier for a provenance ", $kind, ".")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated ", $kind, " identifier.")]
            ///
            /// # Errors
            ///
            /// Rejects empty, oversized, or control-character-containing IDs.
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_opaque_id(&value, $kind)?;
                Ok(Self(value))
            }

            /// Returns the stable string representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

opaque_id!(EntityId, "entity");
opaque_id!(ActivityId, "activity");
opaque_id!(AgentId, "agent");
opaque_id!(RunId, "run");
opaque_id!(CandidateId, "candidate");

fn validate_opaque_id(value: &str, kind: &'static str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::InvalidValue {
            kind,
            value: value.to_owned(),
            reason: "must not be empty",
        });
    }
    if value.len() > 256 {
        return Err(ModelError::InvalidValue {
            kind,
            value: value.to_owned(),
            reason: "must not exceed 256 bytes",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ModelError::InvalidValue {
            kind,
            value: value.to_owned(),
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Normalized HTTP method used in endpoint identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct HttpMethod(String);

impl HttpMethod {
    /// Creates an uppercase HTTP token.
    ///
    /// # Errors
    ///
    /// Rejects an empty value or any character outside the HTTP token grammar.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref().to_ascii_uppercase();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(ModelError::InvalidValue {
                kind: "HTTP method",
                value,
                reason: "must be a non-empty RFC 9110 token",
            });
        }
        Ok(Self(value))
    }

    /// Returns the normalized method.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for HttpMethod {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for HttpMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A route template without query or fragment components.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PathTemplate(String);

impl PathTemplate {
    /// Creates a validated absolute path template.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute paths, queries, fragments, and control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !value.starts_with('/') {
            return Err(ModelError::InvalidValue {
                kind: "path template",
                value,
                reason: "must start with `/`",
            });
        }
        if value.contains('?') || value.contains('#') {
            return Err(ModelError::InvalidValue {
                kind: "path template",
                value,
                reason: "must not contain a query or fragment",
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ModelError::InvalidValue {
                kind: "path template",
                value,
                reason: "must not contain control characters",
            });
        }
        Ok(Self(value))
    }

    /// Returns the template string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PathTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PathTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Query-parameter name. It is metadata and never part of endpoint identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ParameterName(String);

impl ParameterName {
    /// Creates a validated parameter name.
    ///
    /// # Errors
    ///
    /// Rejects empty names and control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(ModelError::InvalidValue {
                kind: "parameter name",
                value,
                reason: "must be non-empty and contain no control characters",
            });
        }
        Ok(Self(value))
    }

    /// Returns the original name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ParameterName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}
