use crate::{
    CorimError, CoseAlgorithm, CoseEllipticCurve, CoseKey, CoseKeyOwner, CoseKty, CoseSigner,
    CoseVerifier,
};
use foreign_types::ForeignTypeRef;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::{Signer, Verifier},
    x509::{X509CrlRef, X509Ref, X509},
};
use openssl_sys as ffi;
use std::collections::HashSet;
use std::os::raw::c_int;
use std::ptr;

/// A limited implementation of a COSE signer using openssl crate that support EC2 keys, and
/// enforces the recommendations in the COSE spec, i.e. ES256 w/ prime256v1, ES384 w/ secp384r1,
/// and ES512 w/ secp521r1.
pub struct OpensslSigner {
    key: CoseKey,
}

impl OpensslSigner {
    pub fn private_key_from_pem(bytes: &[u8]) -> Result<Self, CorimError> {
        let ec_key = EcKey::private_key_from_pem(bytes)?;

        let crv = match ec_key.group().curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
            Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
            Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
            Some(other) => Err(CorimError::Custom(format!(
                "unsupported EC curve {}",
                other.short_name()?
            ))),
            None => Err(CorimError::custom("could not get EC curve from key")),
        }?;

        Ok(Self {
            key: CoseKey {
                kty: CoseKty::Ec2,
                alg: None,
                crv: Some(crv),
                x: None,
                y: None,
                d: Some(ec_key.private_key().to_vec().into()),
                key_ops: None,
                base_iv: None,
                k: None,
                kid: None,
            },
        })
    }

    pub fn public_key_from_pem(bytes: &[u8]) -> Result<Self, CorimError> {
        let ec_key = EcKey::public_key_from_pem(bytes)?;
        let group = ec_key.group();

        let crv = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
            Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
            Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
            Some(other) => Err(CorimError::Custom(format!(
                "unsupported EC curve {}",
                other.short_name()?
            ))),
            None => Err(CorimError::custom("could not get EC curve from key")),
        }?;

        let ec_point = ec_key.public_key();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        ec_point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        Ok(Self {
            key: CoseKey {
                kty: CoseKty::Ec2,
                alg: None,
                crv: Some(crv),
                x: Some(x.to_vec().into()),
                y: Some(y.to_vec().into()),
                d: None,
                key_ops: None,
                base_iv: None,
                k: None,
                kid: None,
            },
        })
    }

    /// Build a verifier from the public key in an X.509 certificate.
    pub(crate) fn public_key_from_x509(cert: &X509Ref) -> Result<Self, CorimError> {
        let pkey = cert.public_key()?;
        let ec_key = pkey
            .ec_key()
            .map_err(|_| CorimError::custom("unsupported key type in x5chain"))?;
        let group = ec_key.group();

        let crv = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
            Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
            Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
            Some(other) => Err(CorimError::Custom(format!(
                "unsupported EC curve {}",
                other.short_name()?
            ))),
            None => Err(CorimError::custom("could not get EC curve from key")),
        }?;

        let ec_point = ec_key.public_key();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        ec_point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        Ok(Self {
            key: CoseKey {
                kty: CoseKty::Ec2,
                alg: None,
                crv: Some(crv),
                x: Some(x.to_vec().into()),
                y: Some(y.to_vec().into()),
                d: None,
                key_ops: None,
                base_iv: None,
                k: None,
                kid: None,
            },
        })
    }
}

impl From<CoseKey> for OpensslSigner {
    fn from(key: CoseKey) -> Self {
        Self { key }
    }
}

impl CoseKeyOwner for OpensslSigner {
    fn to_cose_key(&self) -> CoseKey {
        self.key.clone()
    }
}

impl From<openssl::error::ErrorStack> for CorimError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        CorimError::custom(value.to_string())
    }
}

impl CoseSigner for OpensslSigner {
    fn sign(&self, alg: CoseAlgorithm, data: &[u8]) -> Result<Vec<u8>, CorimError> {
        let message_digest = match alg {
            CoseAlgorithm::ES256 => MessageDigest::sha256(),
            CoseAlgorithm::ES384 => MessageDigest::sha384(),
            CoseAlgorithm::ES512 => MessageDigest::sha512(),
            other => {
                return Err(CorimError::Custom(format!(
                    "unexpected COSE algorithm {other}"
                )))
            }
        };

        let key_bytes;
        let key_number;
        let group;
        match self.key.kty {
            CoseKty::Ec2 => {
                if self.key.d.is_none() {
                    return Err(CorimError::custom("key missing private component d"));
                }

                key_bytes = self.key.d.as_ref().unwrap();
                key_number = BigNum::from_slice(key_bytes).map_err(CorimError::custom)?;
                group = match self
                    .key
                    .crv
                    .as_ref()
                    .ok_or(CorimError::unset_mandatory_field("CoseKey", "crv"))?
                {
                    CoseEllipticCurve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
                    CoseEllipticCurve::P384 => EcGroup::from_curve_name(Nid::SECP384R1)?,
                    CoseEllipticCurve::P521 => EcGroup::from_curve_name(Nid::SECP521R1)?,
                    other => {
                        return Err(CorimError::InvalidFieldValue(
                            "CoseKey".to_string(),
                            "crv".to_string(),
                            other.to_string(),
                        ));
                    }
                }
            }
            other => return Err(CorimError::Custom(format!("unsupported key type {other}"))),
        }

        let ec_key =
            EcKey::from_private_components(&group, &key_number, &EcPoint::new(&group).unwrap())?;
        let final_key = PKey::from_ec_key(ec_key)?;

        let mut signer = Signer::new(message_digest, &final_key)?;
        signer.update(data)?;

        let der_sig = signer.sign_to_vec()?;
        let priv_comp = EcdsaSig::from_der(&der_sig)?;

        let size: i32 = key_bytes.len() as i32;
        let mut s = priv_comp.r().to_vec_padded(size)?;
        s.append(&mut priv_comp.s().to_vec_padded(size)?);
        Ok(s)
    }
}

impl CoseVerifier for OpensslSigner {
    fn verify_signature(
        &self,
        alg: CoseAlgorithm,
        sig: &[u8],
        data: &[u8],
    ) -> Result<(), CorimError> {
        let message_digest = match alg {
            CoseAlgorithm::ES256 => MessageDigest::sha256(),
            CoseAlgorithm::ES384 => MessageDigest::sha384(),
            CoseAlgorithm::ES512 => MessageDigest::sha512(),
            other => {
                return Err(CorimError::Custom(format!(
                    "unexpected COSE algorithm {other}"
                )))
            }
        };

        let size;
        let group;
        let mut pub_key_bytes;
        match self.key.kty {
            CoseKty::Ec2 => {
                if self.key.y.is_none() {
                    return Err(CorimError::custom("key missing public component x"));
                }

                let mut x = self.key.x.as_ref().unwrap().to_vec();
                size = x.len();

                if self.key.y.is_some() && self.key.y.as_ref().unwrap().len() > 0 {
                    let mut y = self.key.y.as_ref().unwrap().to_vec();
                    pub_key_bytes = vec![4]; // SEC1 EC2 no point compression
                    pub_key_bytes.append(&mut x);
                    pub_key_bytes.append(&mut y);
                } else {
                    pub_key_bytes = vec![3]; // SEC1 EC2 w/ point compression
                    pub_key_bytes.append(&mut x);
                }

                group = match self
                    .key
                    .crv
                    .as_ref()
                    .ok_or(CorimError::unset_mandatory_field("CoseKey", "crv"))?
                {
                    CoseEllipticCurve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
                    CoseEllipticCurve::P384 => EcGroup::from_curve_name(Nid::SECP384R1)?,
                    CoseEllipticCurve::P521 => EcGroup::from_curve_name(Nid::SECP521R1)?,
                    other => {
                        return Err(CorimError::InvalidFieldValue(
                            "CoseKey".to_string(),
                            "crv".to_string(),
                            other.to_string(),
                        ));
                    }
                }
            }
            other => return Err(CorimError::Custom(format!("unsupported key type {other}"))),
        }

        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, &pub_key_bytes, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&group, &point)?;
        let verif_key = PKey::from_ec_key(ec_key)?;

        let mut verifier = Verifier::new(message_digest, &verif_key)?;
        verifier.update(&data)?;

        let ecdsa_sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&sig[..size])?,
            BigNum::from_slice(&sig[size..])?,
        )?;

        if verifier.verify(&ecdsa_sig.to_der()?)? {
            Ok(())
        } else {
            Err(CorimError::InvalidSignature)
        }
    }
}

#[repr(C)]
struct BasicConstraintsSt {
    ca: c_int,
    pathlen: *mut std::ffi::c_void,
}

extern "C" {
    fn BASIC_CONSTRAINTS_free(bc: *mut BasicConstraintsSt);
}

/// OpenSSL returns `UINT32_MAX` from `X509_get_key_usage` when the KeyUsage
/// extension is absent (distinct from present-with-zero-bits).
const X509_KU_ABSENT: u32 = 0xffff_ffff;

fn certificate_is_ca(cert: &X509Ref) -> Result<bool, CorimError> {
    // SAFETY: `cert` is a valid `X509Ref`. `X509_get_ext_d2i` allocates a BasicConstraints
    // struct that must be freed with `BASIC_CONSTRAINTS_free` before returning.
    unsafe {
        let bc = ffi::X509_get_ext_d2i(
            cert.as_ptr(),
            ffi::NID_basic_constraints,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if bc.is_null() {
            return Ok(false);
        }
        let bc_ptr = bc.cast::<BasicConstraintsSt>();
        let is_ca = (*bc_ptr).ca != 0;
        BASIC_CONSTRAINTS_free(bc_ptr);
        Ok(is_ca)
    }
}

/// Leaf signing-certificate policy (Go `validateLeafSigningCert` parity).
pub(crate) fn validate_signing_certificate(cert: &X509Ref) -> Result<(), CorimError> {
    if certificate_is_ca(cert)? {
        return Err(CorimError::X5chainSigningCertMustNotBeCa);
    }

    // SAFETY: `cert` is a valid `X509Ref` for the call; `X509_get_key_usage` only reads
    // certificate state and does not retain pointers past the call.
    let ku = unsafe { ffi::X509_get_key_usage(cert.as_ptr()) };
    if ku != X509_KU_ABSENT && (ku & ffi::X509v3_KU_DIGITAL_SIGNATURE) == 0 {
        return Err(CorimError::X5chainSigningCertLacksDigitalSignature);
    }

    Ok(())
}

pub(crate) fn pem_block_label(block: &[u8]) -> Result<String, CorimError> {
    let s =
        std::str::from_utf8(block).map_err(|e| CorimError::custom(format!("reading PEM: {e}")))?;
    let begin = "-----BEGIN ";
    let end = "-----";
    let start = s
        .find(begin)
        .ok_or_else(|| CorimError::custom("reading PEM: missing BEGIN"))?;
    let after_begin = &s[start + begin.len()..];
    let label_end = after_begin
        .find(end)
        .ok_or_else(|| CorimError::custom("reading PEM: missing label end"))?;
    Ok(after_begin[..label_end].trim().to_string())
}

pub(crate) fn advance_pem_block(data: &[u8]) -> Result<&[u8], CorimError> {
    let s =
        std::str::from_utf8(data).map_err(|e| CorimError::custom(format!("reading PEM: {e}")))?;
    let end_marker = "-----END ";
    let end_start = s
        .find(end_marker)
        .ok_or_else(|| CorimError::custom("reading PEM: missing END"))?;
    let after_end_tag = &s[end_start + end_marker.len()..];
    let footer_end = after_end_tag
        .find("-----")
        .ok_or_else(|| CorimError::custom("reading PEM: truncated END line"))?;
    let consumed = end_start + end_marker.len() + footer_end + 5;
    let mut rest = &data[consumed.min(data.len())..];
    while let [first, tail @ ..] = rest {
        if *first == b'\n' || *first == b'\r' {
            rest = tail;
        } else {
            break;
        }
    }
    Ok(rest)
}

pub(crate) fn cert_to_der(cert: &X509Ref) -> Result<Vec<u8>, CorimError> {
    cert.to_der()
        .map_err(|e| CorimError::custom(format!("encoding certificate: {e}")))
}

/// Parse a DER length octet (X.690 §8.1.3).
///
/// Short form: high bit clear, length = value of the single octet.
/// Long form: high bit set, low 7 bits = count of subsequent length octets,
/// whose big-endian value is the length.
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), CorimError> {
    if data.is_empty() {
        return Err(CorimError::custom("decoding DER: truncated length"));
    }
    if data[0] & 0x80 == 0 {
        return Ok((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > (usize::BITS / 8) as usize || data.len() < 1 + num_bytes {
        return Err(CorimError::custom("decoding DER: invalid long-form length"));
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = len
            .checked_shl(8)
            .and_then(|v| v.checked_add(data[1 + i] as usize))
            .ok_or_else(|| CorimError::custom("decoding DER: length overflow"))?;
    }
    Ok((len, 1 + num_bytes))
}

/// Total byte length of a DER SEQUENCE TLV starting at `data[0]`.
pub(crate) fn der_tlv_total_len(data: &[u8]) -> Result<usize, CorimError> {
    if data.is_empty() {
        return Err(CorimError::custom("decoding DER: empty input"));
    }
    if data[0] != 0x30 {
        return Err(CorimError::custom(format!(
            "decoding DER: expected SEQUENCE tag, got 0x{:02x}",
            data[0]
        )));
    }
    let (content_len, header_len) = parse_der_length(&data[1..])?;
    let total = 1usize
        .checked_add(header_len)
        .and_then(|v| v.checked_add(content_len))
        .ok_or_else(|| CorimError::custom("decoding DER: length overflow"))?;
    if total > data.len() {
        return Err(CorimError::custom(
            "decoding DER: TLV length exceeds remaining input",
        ));
    }
    Ok(total)
}

/// Parse a single DER certificate or PEM `CERTIFICATE` block; returns DER bytes.
pub(crate) fn certificate_der_from_pem_or_der(data: &[u8]) -> Result<Vec<u8>, CorimError> {
    if let Ok(cert) = X509::from_pem(data) {
        return cert_to_der(&cert);
    }

    let len = der_tlv_total_len(data)?;
    certificate_from_der(&data[..len])?;
    Ok(data[..len].to_vec())
}

pub(crate) fn certificate_from_der(der: &[u8]) -> Result<X509, CorimError> {
    let len = der_tlv_total_len(der)?;
    if len != der.len() {
        return Err(CorimError::custom(
            "parsing certificate: trailing data after DER TLV",
        ));
    }
    X509::from_der(der).map_err(|e| CorimError::custom(format!("parsing certificate: {e}")))
}

pub(crate) fn verify_cert_signed_by(cert: &X509Ref, issuer: &X509Ref) -> Result<(), CorimError> {
    let key = issuer
        .public_key()
        .map_err(|e| CorimError::X5chainInvalidCertificateSignature(e.to_string()))?;
    if !cert
        .verify(&key)
        .map_err(|e| CorimError::X5chainInvalidCertificateSignature(e.to_string()))?
    {
        return Err(CorimError::X5chainInvalidCertificateSignature(
            "certificate signature invalid".into(),
        ));
    }
    Ok(())
}

/// Structural chain check: each cert must be signed by the next (no PKIX trust).
pub(crate) fn verify_certificate_chain_signed_by(
    chain_ders: &[impl AsRef<[u8]>],
) -> Result<(), CorimError> {
    match chain_ders.len() {
        0 => Err(CorimError::X5chainEmptyChain),
        1 => Ok(()),
        _ => {
            let certs: Vec<X509> = chain_ders
                .iter()
                .map(|der| certificate_from_der(der.as_ref()))
                .collect::<Result<Vec<_>, _>>()?;
            for i in 0..certs.len() - 1 {
                verify_cert_signed_by(&certs[i], &certs[i + 1])?;
            }
            Ok(())
        }
    }
}

pub(crate) fn crl_signed_by_issuer(crl: &X509CrlRef, issuer: &X509Ref) -> bool {
    let Ok(issuer_key) = issuer.public_key() else {
        return false;
    };
    crl.verify(&issuer_key).unwrap_or(false)
}

/// Trust-anchor loader with DER deduplication cache.
pub(crate) struct AnchorLoader {
    certs: Vec<X509>,
    der_set: HashSet<Vec<u8>>,
}

impl AnchorLoader {
    pub(crate) fn new() -> Self {
        Self {
            certs: Vec::new(),
            der_set: HashSet::new(),
        }
    }

    pub(crate) fn push_deduped(&mut self, cert: X509) -> Result<(), CorimError> {
        let der = cert_to_der(&cert)?;
        if self.der_set.insert(der) {
            self.certs.push(cert);
        }
        Ok(())
    }

    pub(crate) fn into_certs(self) -> Vec<X509> {
        self.certs
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_openssl_ec_sign_verify() {
        let priv_pem = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGcXyKllYJ/Ll0jUI9LfK/7uokvFibisW5lM8DZaRO+toAoGCCqGSM49
AwEHoUQDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpoeCJsPxG2h
zMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END EC PRIVATE KEY-----
"#;
        let pub_pem = r#"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4Q
hU80ttXzJ7waTpoeCJsPxG2hzMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END PUBLIC KEY-----
"#;
        let message = "Hello, World!";

        let signer = OpensslSigner::private_key_from_pem(priv_pem.as_bytes()).unwrap();
        let sig = signer
            .sign(CoseAlgorithm::ES256, message.as_bytes())
            .unwrap();

        let verifier = OpensslSigner::public_key_from_pem(pub_pem.as_bytes()).unwrap();
        verifier
            .verify_signature(CoseAlgorithm::ES256, &sig, message.as_bytes())
            .unwrap();
    }
}
