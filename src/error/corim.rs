// SPDX-License-Identifier: MIT

/// Why loading a CRL file failed during trust-material setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X5chainCrlLoadErrorKind {
    InvalidPemBlockType,
    Parse(String),
}

#[derive(Debug)]
pub enum CorimError {
    InvalidConciseTagTypeChoice,
    InvalidCorimRole(String),
    InvalidFieldValue(String, String, String),
    UnsetMandatoryField(String, String),
    CoseHeaderNotSet(i64, String),
    InvalidCoseHeader(i64, String, String),
    InvalidCoseKey(String),
    InvalidSignature,
    OutsideValidityPeriod,
    X5chainHeaderNotSet,
    X5chainEmptyChain,
    X5chainVerificationFailed(String),
    X5chainCertificateExpired,
    X5chainCertificateRevoked,
    X5chainCrlExpired,
    X5chainCrlNotYetValid,
    X5chainInvalidCertificateSignature(String),
    X5chainSigningCertMustNotBeCa,
    X5chainSigningCertLacksDigitalSignature,
    X5chainCoseSignatureVerificationFailed(String),
    X5chainInvalidPemBlockType(String),
    X5chainCrlLoadError {
        path: String,
        kind: X5chainCrlLoadErrorKind,
    },
    Custom(String),
    Unknown,
}

impl CorimError {
    pub fn unset_mandatory_field<D: std::fmt::Display>(object: D, field: D) -> Self {
        CorimError::UnsetMandatoryField(object.to_string(), field.to_string())
    }

    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        CorimError::Custom(message.to_string())
    }
}

impl std::error::Error for CorimError {}

impl std::fmt::Display for CorimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConciseTagTypeChoice => {
                write!(f, "Invalid ConciseTagTypeChoice encountered")
            }
            Self::InvalidCorimRole(role) => {
                write!(f, "Invalid CoRIM role \"{role}\"")
            }
            Self::InvalidFieldValue(object, field, message) => {
                write!(f, " invalid {object}.{field} value: {message}")
            }
            Self::UnsetMandatoryField(object, field) => {
                write!(f, "{object} field(s) {field} must be set")
            }
            Self::CoseHeaderNotSet(value, label) => {
                write!(f, "COSE header {value} ({label}) not set")
            }
            Self::InvalidCoseHeader(value, label, message) => {
                write!(
                    f,
                    "invalid value for COSE header {value} ({label}): {message}"
                )
            }
            Self::InvalidCoseKey(message) => {
                write!(f, "invalid COSE key: {message}")
            }
            Self::OutsideValidityPeriod => {
                write!(f, "current time is outside manifest's validity period")
            }
            Self::InvalidSignature => f.write_str("invalid signature"),
            Self::X5chainHeaderNotSet => f.write_str("x5chain: header not set in CoRIM"),
            Self::X5chainEmptyChain => f.write_str("x5chain: empty chain"),
            Self::X5chainVerificationFailed(reason) => {
                write!(f, "x5chain verification failed: {reason}")
            }
            Self::X5chainCertificateExpired => f.write_str("x5chain: certificate has expired"),
            Self::X5chainCertificateRevoked => f.write_str("x5chain: certificate revoked"),
            Self::X5chainCrlExpired => f.write_str("x5chain: CRL has expired"),
            Self::X5chainCrlNotYetValid => f.write_str("x5chain: CRL is not yet valid"),
            Self::X5chainInvalidCertificateSignature(detail) => {
                write!(f, "x5chain: {detail}")
            }
            Self::X5chainSigningCertMustNotBeCa => {
                f.write_str("x5chain: signing certificate must not be a CA")
            }
            Self::X5chainSigningCertLacksDigitalSignature => {
                f.write_str("x5chain: signing certificate lacks digitalSignature key usage")
            }
            Self::X5chainCoseSignatureVerificationFailed(detail) => {
                write!(f, "x5chain: COSE signature verification failed: {detail}")
            }
            Self::X5chainInvalidPemBlockType(label) => {
                write!(f, "x5chain: invalid PEM block type {label:?}")
            }
            Self::X5chainCrlLoadError { path, kind } => match kind {
                X5chainCrlLoadErrorKind::InvalidPemBlockType => {
                    write!(
                        f,
                        "x5chain: parsing CRL from {path}: invalid PEM block type"
                    )
                }
                X5chainCrlLoadErrorKind::Parse(detail) => {
                    write!(f, "x5chain: parsing CRL from {path}: {detail}")
                }
            },
            Self::Custom(message) => f.write_str(message.as_str()),
            Self::Unknown => write!(f, "unknown CorimError encountered"),
        }
    }
}
