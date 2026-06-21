// SPDX-License-Identifier: MIT

use crate::corim::SignedCorim;
use crate::openssl::OpensslSigner;
use crate::CorimError;
use openssl::asn1::Asn1Time;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509Crl, X509PurposeId, X509Ref, X509};
use rustls_native_certs::load_native_certs;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::error::PEMError;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Trusted root CAs and optional CRLs for x5chain validation.
///
/// `roots` holds trusted root CAs for PKIX path validation.
/// `current_time` is used for certificate and CRL validity checks; `None` means now.
pub struct TrustedRoots {
    roots: Vec<X509>,
    crls: Vec<X509Crl>,
    current_time: Option<i64>,
}

impl TrustedRoots {
    /// Override validation time (Unix seconds). Used mainly in tests.
    pub fn with_validation_time(mut self, unix_secs: i64) -> Self {
        self.current_time = Some(unix_secs);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_roots(roots: Vec<X509>) -> Self {
        Self {
            roots,
            crls: Vec::new(),
            current_time: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_roots_and_crls(roots: Vec<X509>, crls: Vec<X509Crl>) -> Self {
        Self {
            roots,
            crls,
            current_time: None,
        }
    }
}

fn read_pem_block(buf: &[u8], expected_label: &str) -> Result<Option<Vec<u8>>, CorimError> {
    let mut cursor = Cursor::new(buf);
    match Pem::read(&mut cursor) {
        Ok((pem, _)) => {
            if pem.label != expected_label {
                return Err(CorimError::custom(format!(
                    "invalid PEM block type {:?}",
                    pem.label
                )));
            }
            Ok(Some(pem.contents))
        }
        Err(PEMError::IncompletePEM) | Err(PEMError::MissingHeader) => Ok(None),
        Err(err) => Err(CorimError::custom(format!("reading PEM: {err}"))),
    }
}

/// Parse a DER-encoded certificate or a PEM block of type CERTIFICATE.
pub fn parse_certificate_der_or_pem(data: &[u8]) -> Result<X509, CorimError> {
    let der = if let Some(der) = read_pem_block(data, "CERTIFICATE")? {
        der
    } else {
        data.to_vec()
    };

    X509::from_der(&der).map_err(|e| CorimError::custom(format!("parsing certificate: {e}")))
}

/// Parse a DER-encoded CRL or a PEM block of type X509 CRL.
pub fn parse_revocation_list_der_or_pem(data: &[u8]) -> Result<X509Crl, CorimError> {
    let der = if let Some(der) = read_pem_block(data, "X509 CRL")? {
        der
    } else {
        data.to_vec()
    };

    X509Crl::from_der(&der).map_err(|e| CorimError::custom(format!("parsing CRL: {e}")))
}

/// Load trusted roots for x5chain validation. When `include_system_roots` is
/// true, system root CAs are included in `roots` and certificates from
/// `root_paths` are added; when false, only `root_paths` are trusted. CRLs are
/// loaded from `crl_paths` when supplied.
///
/// CLI tools typically derive `include_system_roots` from
/// [`include_system_roots_for_verify`].
pub fn trusted_root_pool<F>(
    read_file: F,
    root_paths: &[impl AsRef<str>],
    crl_paths: &[impl AsRef<str>],
    include_system_roots: bool,
) -> Result<TrustedRoots, CorimError>
where
    F: Fn(&str) -> Result<Vec<u8>, CorimError>,
{
    let mut roots = Vec::new();

    if include_system_roots {
        let native = load_native_certs();
        if !native.errors.is_empty() {
            let msgs: Vec<String> = native.errors.iter().map(|e| e.to_string()).collect();
            return Err(CorimError::custom(format!(
                "loading system cert pool: {}",
                msgs.join("; ")
            )));
        }

        for cert in native.certs {
            if let Ok(parsed) = X509::from_der(cert.as_ref()) {
                push_root_deduped(&mut roots, parsed);
            }
        }
    }

    for path in root_paths {
        let path = path.as_ref();
        let data = read_file(path).map_err(|e| {
            CorimError::custom(format!("loading root certificate from {path}: {e}"))
        })?;
        let cert = parse_certificate_der_or_pem(&data).map_err(|e| {
            CorimError::custom(format!("parsing root certificate from {path}: {e}"))
        })?;
        push_root_deduped(&mut roots, cert);
    }

    let mut crls = Vec::new();
    for path in crl_paths {
        let path = path.as_ref();
        let data = read_file(path)
            .map_err(|e| CorimError::custom(format!("loading CRL from {path}: {e}")))?;
        let crl = parse_revocation_list_der_or_pem(&data)
            .map_err(|e| CorimError::custom(format!("parsing CRL from {path}: {e}")))?;
        crls.push(crl);
    }

    Ok(TrustedRoots {
        roots,
        crls,
        current_time: None,
    })
}

fn verify_cert_signed_by(cert: &X509Ref, issuer: &X509Ref) -> Result<(), CorimError> {
    let key = issuer
        .public_key()
        .map_err(|e| CorimError::custom(format!("x5chain: {e}")))?;
    if !cert
        .verify(&key)
        .map_err(|e| CorimError::custom(format!("x5chain: {e}")))?
    {
        return Err(CorimError::custom("x5chain: certificate signature invalid"));
    }
    Ok(())
}

/// Check that each certificate in the chain was signed by the next.
/// A single-certificate chain is accepted without further checks.
pub fn verify_x509_chain(certs: &[X509]) -> Result<(), CorimError> {
    match certs.len() {
        0 => Err(CorimError::custom("empty chain")),
        1 => Ok(()),
        _ => {
            for i in 0..certs.len() - 1 {
                verify_cert_signed_by(&certs[i], &certs[i + 1])?;
            }
            Ok(())
        }
    }
}

fn validation_time(trusted: &TrustedRoots) -> Result<i64, CorimError> {
    match trusted.current_time {
        Some(secs) => Ok(secs),
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CorimError::custom(format!("system time before Unix epoch: {e}")))
            .map(|duration| duration.as_secs() as i64),
    }
}

fn cert_der(cert: &X509Ref) -> Result<Vec<u8>, CorimError> {
    cert.to_der()
        .map_err(|e| CorimError::custom(format!("encoding certificate: {e}")))
}

fn roots_contain(roots: &[X509], cert: &X509Ref) -> bool {
    cert_der(cert).ok().is_some_and(|der| {
        roots
            .iter()
            .any(|existing| cert_der(existing).ok().as_deref() == Some(der.as_slice()))
    })
}

fn push_root_deduped(roots: &mut Vec<X509>, cert: X509) {
    if !roots_contain(roots, &cert) {
        roots.push(cert);
    }
}

fn intermediates_from_chain(chain: &[X509]) -> Result<Stack<X509>, CorimError> {
    let mut stack = Stack::new().map_err(CorimError::custom)?;

    for cert in chain.iter().skip(1) {
        stack.push(cert.clone()).map_err(CorimError::custom)?;
    }

    Ok(stack)
}

fn x509_name_string(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .filter_map(|entry| entry.data().as_utf8().ok())
        .map(|data| data.to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn crls_for_issuer<'a>(issuer: &X509Ref, crls: &'a [X509Crl]) -> Vec<&'a X509Crl> {
    crls.iter()
        .filter(|crl| {
            issuer
                .public_key()
                .ok()
                .is_some_and(|key| crl.verify(&key).unwrap_or(false))
        })
        .collect()
}

fn check_crl_validity(crl: &X509Crl, now_secs: i64) -> Result<(), CorimError> {
    let now = Asn1Time::from_unix(now_secs).map_err(CorimError::custom)?;
    let this_update = crl.last_update();
    if *this_update > *now {
        let issuer = x509_name_string(crl.issuer_name());
        return Err(CorimError::custom(format!(
            "x5chain: CRL from {issuer:?} is not yet valid"
        )));
    }

    if let Some(next_update) = crl.next_update() {
        if *next_update < *now {
            let issuer = x509_name_string(crl.issuer_name());
            return Err(CorimError::custom(format!(
                "x5chain: CRL from {issuer:?} has expired"
            )));
        }
    }

    Ok(())
}

fn serial_revoked(serial: &openssl::bn::BigNumRef, crls: &[&X509Crl]) -> bool {
    crls.iter().any(|crl| {
        crl.get_revoked()
            .map(|revoked| {
                (0..revoked.len()).any(|i| {
                    revoked
                        .get(i)
                        .and_then(|entry| entry.serial_number().to_bn().ok())
                        .is_some_and(|entry_serial| entry_serial == *serial)
                })
            })
            .unwrap_or(false)
    })
}

fn check_revocation(chain: &[X509], crls: &[X509Crl], now_secs: i64) -> Result<(), CorimError> {
    if crls.is_empty() {
        return Ok(());
    }

    for (i, cert) in chain.iter().enumerate() {
        if i + 1 >= chain.len() {
            break;
        }

        let issuer = &chain[i + 1];
        let issuer_crls = crls_for_issuer(issuer, crls);
        if issuer_crls.is_empty() {
            continue;
        }

        for crl in &issuer_crls {
            check_crl_validity(crl, now_secs)?;
        }

        let serial = cert
            .serial_number()
            .to_bn()
            .map_err(|e| CorimError::custom(format!("reading certificate serial: {e}")))?;

        if serial_revoked(&serial, &issuer_crls) {
            let subject = x509_name_string(cert.subject_name());
            return Err(CorimError::custom(format!(
                "x5chain: certificate {subject:?} is revoked"
            )));
        }
    }

    Ok(())
}

fn validate_signing_certificate(cert: &X509Ref) -> Result<(), CorimError> {
    let der = cert
        .to_der()
        .map_err(|e| CorimError::custom(format!("encoding signing certificate: {e}")))?;
    let (_, parsed) = X509Certificate::from_der(&der)
        .map_err(|e| CorimError::custom(format!("parsing signing certificate: {e}")))?;

    if parsed.is_ca() {
        return Err(CorimError::custom(
            "x5chain: signing certificate must not be a CA",
        ));
    }

    if let Ok(Some(ku)) = parsed.key_usage() {
        if ku.value.flags != 0 && !ku.value.digital_signature() {
            return Err(CorimError::custom(
                "x5chain: signing certificate lacks digitalSignature key usage",
            ));
        }
    }

    Ok(())
}

fn verify_pkix(
    leaf: &X509Ref,
    intermediates: &Stack<X509>,
    trusted: &TrustedRoots,
    now_secs: i64,
) -> Result<Vec<X509>, CorimError> {
    let mut store_builder = X509StoreBuilder::new().map_err(CorimError::custom)?;
    for root in &trusted.roots {
        store_builder
            .add_cert(root.clone())
            .map_err(CorimError::custom)?;
    }

    let mut verify_params = X509VerifyParam::new().map_err(CorimError::custom)?;
    verify_params.set_time(now_secs);
    verify_params
        .set_purpose(X509PurposeId::ANY)
        .map_err(CorimError::custom)?;
    store_builder
        .set_param(&verify_params)
        .map_err(CorimError::custom)?;

    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new().map_err(CorimError::custom)?;

    let mut verified_chain: Vec<X509> = Vec::new();

    let reason = ctx
        .init(&store, leaf, intermediates, |ctx| match ctx.verify_cert() {
            Ok(true) => {
                if let Some(chain) = ctx.chain() {
                    verified_chain = chain.iter().map(X509Ref::to_owned).collect();
                }
                Ok(String::new())
            }
            Ok(false) => Ok(ctx.error().to_string()),
            Err(err) => Err(err),
        })
        .map_err(|e| CorimError::custom(format!("x5chain verification failed: {e}")))?;

    if !reason.is_empty() {
        return Err(CorimError::custom(format!(
            "x5chain verification failed: {reason}"
        )));
    }

    if verified_chain.is_empty() {
        return Err(CorimError::custom(
            "x5chain verification failed: no verified chain",
        ));
    }

    Ok(verified_chain)
}

/// Whether to include the operating-system root CAs when building a
/// [`TrustedRoots`] pool for CLI-style verification.
///
/// When no explicit `--root` paths are supplied, system roots are used. When
/// explicit roots are supplied, system roots are included only if `system_roots`
/// is true. This helper does not apply to key-based verification, which skips
/// PKIX path validation entirely.
pub fn include_system_roots_for_verify(explicit_root_count: usize, system_roots: bool) -> bool {
    explicit_root_count == 0 || system_roots
}

/// Validates an x5chain using PKIX path validation against trusted roots, then
/// optional CRL checks. `chain_ders` must contain the leaf (signing) certificate
/// first, followed by any intermediates.
pub fn verify_x509_chain_trust(
    chain_ders: &[impl AsRef<[u8]>],
    trusted: &TrustedRoots,
) -> Result<(), CorimError> {
    if chain_ders.is_empty() {
        return Err(CorimError::custom("empty chain"));
    }

    let chain: Vec<X509> = chain_ders
        .iter()
        .map(|der| {
            X509::from_der(der.as_ref())
                .map_err(|e| CorimError::custom(format!("parsing x5chain cert: {e}")))
        })
        .collect::<std::result::Result<Vec<_>, CorimError>>()?;

    validate_signing_certificate(&chain[0])?;

    let now_secs = validation_time(trusted)?;
    let intermediates = intermediates_from_chain(&chain)?;
    let verified_chain = verify_pkix(&chain[0], &intermediates, trusted, now_secs)?;
    check_revocation(&verified_chain, &trusted.crls, now_secs)?;

    Ok(())
}

impl SignedCorim<'_> {
    /// Returns DER-encoded certificates from the x5chain in order, starting with
    /// the signing (leaf) certificate.
    pub fn x509_certificate_ders(&self) -> Result<Vec<Vec<u8>>, CorimError> {
        let Some(ref x5chain) = self.x5chain else {
            return Err(CorimError::custom("x5chain header not set in CoRIM"));
        };

        Ok(x5chain.iter().map(|b| b.to_vec()).collect())
    }

    /// Validates the embedded x5chain using PKIX path validation (validity, CA/basic
    /// constraints, key usage, and chain building to trusted roots), optional CRL
    /// checks, then verifies the COSE signature using the public key from the
    /// signing certificate.
    ///
    /// Callers that verify with an external JWK or PEM public key should use
    /// [`Self::verify_signature`] instead; PKIX and `--root` / `--system-roots`
    /// trust flags do not apply on that path.
    pub fn verify_x509_chain_trust(&self, trusted: &TrustedRoots) -> Result<(), CorimError> {
        let chain_ders = self.x509_certificate_ders()?;
        verify_x509_chain_trust(&chain_ders, trusted)?;

        let verifier = OpensslSigner::public_key_from_x509_der(&chain_ders[0])?;
        self.verify_signature(verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Bytes, CoseAlgorithm, OneOrMore};
    use crate::corim::{Corim, CorimMap, CorimMetaMap, SignedCorimBuilder};
    use crate::openssl::OpensslSigner;
    use std::fs::File;
    use std::path::PathBuf;

    fn cert_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/x509/certs")
            .join(name)
    }

    fn test_data_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    fn load_cert(name: &str) -> X509 {
        let data = std::fs::read(cert_path(name)).unwrap();
        parse_certificate_der_or_pem(&data).unwrap()
    }

    fn chain_ders(names: &[&str]) -> Vec<Vec<u8>> {
        names
            .iter()
            .map(|name| {
                let data = std::fs::read(cert_path(name)).unwrap();
                parse_certificate_der_or_pem(&data)
                    .unwrap()
                    .to_der()
                    .unwrap()
            })
            .collect()
    }

    fn trusted_with_root() -> TrustedRoots {
        TrustedRoots::with_roots(vec![load_cert("root.cert.pem")])
    }

    fn build_signed_x5chain_corim(intermediates: &[&str]) -> Vec<u8> {
        let corim_map = {
            let file = File::open(test_data_path("good-corim.json")).unwrap();
            CorimMap::from_json(file).unwrap()
        };
        let meta = {
            let file = File::open(test_data_path("meta.json")).unwrap();
            CorimMetaMap::from_json(file).unwrap()
        };

        let mut chain: Vec<Bytes> = vec![load_cert("leaf.cert.pem").to_der().unwrap().into()];
        for name in intermediates {
            chain.push(load_cert(name).to_der().unwrap().into());
        }

        let x5chain = match chain.len() {
            1 => OneOrMore::One(chain.into_iter().next().unwrap()),
            _ => OneOrMore::More(chain),
        };

        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let signer = OpensslSigner::private_key_from_pem(&signer_pem).unwrap();

        let signed = SignedCorimBuilder::new()
            .alg(CoseAlgorithm::ES256)
            .kid(b"test-kid".to_vec())
            .x5chain(x5chain)
            .meta(meta)
            .corim_map(corim_map)
            .build_and_sign(signer)
            .unwrap();

        Corim::from(signed).to_cbor().unwrap()
    }

    fn build_signed_corim_without_x5chain() -> Vec<u8> {
        let corim_map = {
            let file = File::open(test_data_path("good-corim.json")).unwrap();
            CorimMap::from_json(file).unwrap()
        };
        let meta = {
            let file = File::open(test_data_path("meta.json")).unwrap();
            CorimMetaMap::from_json(file).unwrap()
        };

        let signer_pem = std::fs::read(cert_path("key.priv.pem")).unwrap();
        let signer = OpensslSigner::private_key_from_pem(&signer_pem).unwrap();

        let signed = SignedCorimBuilder::new()
            .alg(CoseAlgorithm::ES256)
            .kid(b"test-kid".to_vec())
            .meta(meta)
            .corim_map(corim_map)
            .build_and_sign(signer)
            .unwrap();

        Corim::from(signed).to_cbor().unwrap()
    }

    fn signed_from_cbor(cbor: &[u8]) -> crate::corim::SignedCorim<'static> {
        let corim = Corim::from_cbor(cbor).unwrap();
        corim.as_signed().expect("expected signed CoRIM")
    }

    #[test]
    fn verify_x509_chain_ok() {
        verify_x509_chain(&[load_cert("int.cert.pem"), load_cert("root.cert.pem")]).unwrap();
    }

    #[test]
    fn verify_x509_chain_single_cert() {
        verify_x509_chain(&[load_cert("root.cert.pem")]).unwrap();
    }

    #[test]
    fn verify_x509_chain_empty() {
        let err = verify_x509_chain(&[]).unwrap_err();
        assert!(err.to_string().contains("empty chain"));
    }

    #[test]
    fn verify_x509_chain_bad_order() {
        let err = verify_x509_chain(&[load_cert("root.cert.pem"), load_cert("int.cert.pem")])
            .unwrap_err();
        assert!(err.to_string().contains("x5chain:"));
    }

    #[test]
    fn include_system_roots_for_verify_cli_policy() {
        assert!(include_system_roots_for_verify(0, false));
        assert!(include_system_roots_for_verify(0, true));
        assert!(!include_system_roots_for_verify(1, false));
        assert!(include_system_roots_for_verify(1, true));
    }

    #[test]
    fn verify_x509_chain_trust_ok() {
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem"]);
        verify_x509_chain_trust(&chain, &trusted_with_root()).unwrap();
    }

    #[test]
    fn verify_x509_chain_trust_untrusted_root() {
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem", "root.cert.pem"]);
        let trusted = TrustedRoots::with_roots(Vec::new());
        let err = verify_x509_chain_trust(&chain, &trusted).unwrap_err();
        assert!(err.to_string().contains("x5chain verification failed"));
    }

    #[test]
    fn verify_x509_chain_trust_wrong_explicit_root_fails() {
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem", "root.cert.pem"]);
        let trusted = TrustedRoots::with_roots(vec![load_cert("int.cert.pem")]);

        let err = verify_x509_chain_trust(&chain, &trusted).unwrap_err();
        assert!(
            err.to_string().contains("x5chain verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn trusted_root_pool_excludes_system_roots_when_disabled() {
        let root_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let trusted = trusted_root_pool(
            |path| {
                if path != "root.pem" {
                    panic!("unexpected path {path}");
                }
                Ok(root_pem.clone())
            },
            &["root.pem"],
            &[] as &[&str],
            false,
        )
        .unwrap();

        assert_eq!(trusted.roots.len(), 1);
    }

    #[test]
    fn verify_x509_chain_trust_expired() {
        let chain = chain_ders(&["leaf.cert.pem", "int.cert.pem"]);
        let trusted = trusted_with_root().with_validation_time(4_102_444_800);

        let err = verify_x509_chain_trust(&chain, &trusted).unwrap_err();
        assert!(
            err.to_string().contains("expired"),
            "expected expired certificate error, got: {err}"
        );
    }

    #[test]
    fn signed_corim_verify_x509_chain_trust_ok() {
        let cbor = build_signed_x5chain_corim(&["int.cert.pem"]);
        let signed = signed_from_cbor(&cbor);
        signed
            .verify_x509_chain_trust(&trusted_with_root())
            .unwrap();
    }

    #[test]
    fn signed_corim_verify_x509_chain_trust_no_x5chain() {
        let cbor = build_signed_corim_without_x5chain();
        let signed = signed_from_cbor(&cbor);
        let err = signed
            .verify_x509_chain_trust(&trusted_with_root())
            .unwrap_err();
        assert!(err.to_string().contains("x5chain header not set"));
    }

    #[test]
    fn signed_corim_verify_x509_chain_trust_tampered_payload() {
        let mut cbor = build_signed_x5chain_corim(&["int.cert.pem"]);
        let last = cbor.len() - 1;
        cbor[last] ^= 0xff;

        let signed = signed_from_cbor(&cbor);
        let err = signed
            .verify_x509_chain_trust(&trusted_with_root())
            .unwrap_err();
        assert!(
            err.to_string().contains("signature")
                || err.to_string().contains("verify")
                || err.to_string().contains("COSE"),
            "expected signature verification failure, got: {err}"
        );
    }

    #[test]
    fn validate_signing_certificate_rejects_ca() {
        let root = load_cert("root.cert.pem");
        let err = validate_signing_certificate(&root).unwrap_err();
        assert!(err
            .to_string()
            .contains("signing certificate must not be a CA"));
    }

    #[test]
    fn parse_certificate_der_or_pem_der() {
        let der = chain_ders(&["root.cert.pem"]).pop().unwrap();
        parse_certificate_der_or_pem(&der).unwrap();
    }

    #[test]
    fn parse_certificate_der_or_pem_pem() {
        let pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        assert!(parse_certificate_der_or_pem(&pem).is_ok());
    }

    #[test]
    fn trusted_root_pool_dedupes_duplicate_roots() {
        let root_pem = std::fs::read(cert_path("root.cert.pem")).unwrap();
        let root_der = parse_certificate_der_or_pem(&root_pem)
            .unwrap()
            .to_der()
            .unwrap();

        let trusted = trusted_root_pool(
            |_| Ok(root_pem.clone()),
            &["root-a.pem", "root-b.pem"],
            &[] as &[&str],
            true,
        )
        .unwrap();

        let root_count = trusted
            .roots
            .iter()
            .filter(|cert| cert.to_der().unwrap() == root_der)
            .count();
        assert_eq!(
            root_count, 1,
            "duplicate root DER must appear once in roots"
        );
    }

    #[test]
    fn parse_revocation_list_der_or_pem_rejects_certificate_pem() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        match parse_revocation_list_der_or_pem(pem) {
            Err(err) => assert!(err.to_string().contains("invalid PEM block type")),
            Ok(_) => panic!("expected PEM type error"),
        }
    }

    mod crl_helpers {
        use super::*;
        use foreign_types_shared::{ForeignType, ForeignTypeRef};
        use openssl::asn1::{Asn1Integer, Asn1Time};
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::{PKey, Private};
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        use openssl::x509::{X509Crl, X509NameBuilder, X509};
        use openssl_sys as ffi;

        fn unix_now() -> i64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        }

        fn ec_key() -> PKey<Private> {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
        }

        fn ca_name() -> openssl::x509::X509Name {
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_nid(Nid::COMMONNAME, "Test CA")
                .unwrap();
            name.build()
        }

        pub(super) fn make_ca() -> (X509, PKey<Private>) {
            let key = ec_key();
            let name = ca_name();
            let now = unix_now();

            let mut builder = X509::builder().unwrap();
            builder.set_version(2).unwrap();
            builder
                .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
                .unwrap();
            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(&name).unwrap();
            builder.set_pubkey(&key).unwrap();
            builder
                .set_not_before(&Asn1Time::from_unix(now - 3_600).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::from_unix(now + 3_600).unwrap())
                .unwrap();

            let bc = BasicConstraints::new().critical().ca().build().unwrap();
            builder.append_extension(bc).unwrap();
            let ku = KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap();
            builder.append_extension(ku).unwrap();

            builder.sign(&key, MessageDigest::sha256()).unwrap();
            (builder.build(), key)
        }

        pub(super) fn make_leaf(ca: &X509, ca_key: &PKey<Private>) -> X509 {
            let key = ec_key();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_nid(Nid::COMMONNAME, "Test Leaf")
                .unwrap();
            let name = name.build();
            let now = unix_now();

            let mut builder = X509::builder().unwrap();
            builder.set_version(2).unwrap();
            builder
                .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(2).unwrap()).unwrap())
                .unwrap();
            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(ca.subject_name()).unwrap();
            builder.set_pubkey(&key).unwrap();
            builder
                .set_not_before(&Asn1Time::from_unix(now - 3_600).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::from_unix(now + 3_600).unwrap())
                .unwrap();

            let ku = KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap();
            builder.append_extension(ku).unwrap();

            builder.sign(ca_key, MessageDigest::sha256()).unwrap();
            builder.build()
        }

        pub(super) fn make_crl_revoking_leaf(
            ca: &X509,
            ca_key: &PKey<Private>,
            leaf: &X509,
        ) -> X509Crl {
            unsafe {
                let crl = ffi::X509_CRL_new();
                assert!(!crl.is_null());
                ffi::X509_CRL_set_issuer_name(crl, ca.subject_name().as_ptr());

                let now = unix_now();
                let this_update = Asn1Time::from_unix(now - 60).unwrap();
                ffi::X509_CRL_set1_lastUpdate(crl, this_update.as_ptr());
                let next_update = Asn1Time::from_unix(now + 3_600).unwrap();
                ffi::X509_CRL_set1_nextUpdate(crl, next_update.as_ptr());

                let revoked = ffi::X509_REVOKED_new();
                assert!(!revoked.is_null());
                ffi::X509_REVOKED_set_serialNumber(
                    revoked,
                    leaf.serial_number().as_ptr() as *mut _,
                );
                let rev_date = Asn1Time::from_unix(now - 60).unwrap();
                ffi::X509_REVOKED_set_revocationDate(revoked, rev_date.as_ptr());
                ffi::X509_CRL_add0_revoked(crl, revoked);

                assert!(
                    ffi::X509_CRL_sign(crl, ca_key.as_ptr(), MessageDigest::sha256().as_ptr()) > 0,
                    "CRL signing failed"
                );

                X509Crl::from_ptr(crl)
            }
        }

        pub(super) fn make_expired_crl() -> X509Crl {
            unsafe {
                let issuer = ca_name();
                let crl = ffi::X509_CRL_new();
                assert!(!crl.is_null());
                ffi::X509_CRL_set_issuer_name(crl, issuer.as_ptr());

                let now = unix_now();
                let this_update = Asn1Time::from_unix(now - 7_200).unwrap();
                ffi::X509_CRL_set1_lastUpdate(crl, this_update.as_ptr());
                let next_update = Asn1Time::from_unix(now - 3_600).unwrap();
                ffi::X509_CRL_set1_nextUpdate(crl, next_update.as_ptr());

                X509Crl::from_ptr(crl)
            }
        }
    }

    #[test]
    fn check_revocation_rejects_revoked_leaf() {
        use crl_helpers::{make_ca, make_crl_revoking_leaf, make_leaf};

        let (ca, ca_key) = make_ca();
        let leaf = make_leaf(&ca, &ca_key);
        let crl = make_crl_revoking_leaf(&ca, &ca_key, &leaf);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let err = check_revocation(&[leaf, ca], &[crl], now).unwrap_err();
        assert!(
            err.to_string().contains("revoked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn check_crl_validity_rejects_expired() {
        use crl_helpers::make_expired_crl;

        let crl = make_expired_crl();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let err = check_crl_validity(&crl, now).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CRL from"), "unexpected error: {msg}");
        assert!(msg.contains("expired"), "unexpected error: {msg}");
    }

    #[test]
    fn check_revocation_expired_crl_issuer_not_in_chain_ignored() {
        use crl_helpers::{make_ca, make_expired_crl, make_leaf};

        let (ca, ca_key) = make_ca();
        let leaf = make_leaf(&ca, &ca_key);
        let expired_crl = make_expired_crl();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        check_revocation(&[leaf, ca], &[expired_crl], now)
            .expect("expired CRL from an issuer outside the chain must be ignored");
    }

    #[test]
    fn parse_revocation_list_der_or_pem_pem_ok() {
        use crl_helpers::{make_ca, make_crl_revoking_leaf, make_leaf};

        let (ca, ca_key) = make_ca();
        let leaf = make_leaf(&ca, &ca_key);
        let crl = make_crl_revoking_leaf(&ca, &ca_key, &leaf);
        let pem = crl.to_pem().unwrap();

        let parsed = parse_revocation_list_der_or_pem(&pem).unwrap();
        assert!(parsed.get_revoked().is_some_and(|stack| !stack.is_empty()));
    }

    #[test]
    fn verify_x509_chain_trust_rejects_revoked_leaf() {
        use crl_helpers::{make_ca, make_crl_revoking_leaf, make_leaf};

        let (ca, ca_key) = make_ca();
        let leaf = make_leaf(&ca, &ca_key);
        let crl = make_crl_revoking_leaf(&ca, &ca_key, &leaf);
        let chain = vec![leaf.to_der().unwrap(), ca.to_der().unwrap()];
        let trusted = TrustedRoots::with_roots_and_crls(vec![ca.clone()], vec![crl]);

        let err = verify_x509_chain_trust(&chain, &trusted).unwrap_err();
        assert!(
            err.to_string().contains("revoked"),
            "unexpected error: {err}"
        );
    }
}
