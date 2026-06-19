//! Test-only PKI fixture.
//!
//! Generates an in-memory ECDSA (P-256) certificate authority that issues a
//! server certificate (SAN `localhost` + `127.0.0.1`) and a client certificate,
//! writing them all to PEM files. Used by the mutual-TLS / server-verify /
//! Subset-146-PKI integration tests.

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509Name, X509NameBuilder, X509};

use std::path::{Path, PathBuf};

/// Paths to the generated PEM files.
pub struct TestPki {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

fn gen_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    PKey::from_ec_key(ec).unwrap()
}

fn name(cn: &str) -> X509Name {
    let mut b = X509NameBuilder::new().unwrap();
    b.append_entry_by_text("CN", cn).unwrap();
    b.build()
}

fn serial() -> openssl::asn1::Asn1Integer {
    let mut bn = BigNum::new().unwrap();
    bn.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    bn.to_asn1_integer().unwrap()
}

impl TestPki {
    /// Generate the CA + server + client certificates into `dir`.
    pub fn generate(dir: &Path) -> TestPki {
        // ── Certificate authority (self-signed, CA:TRUE) ──
        let ca_key = gen_key();
        let ca_name = name("SCG Test CA");
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&ca_name).unwrap();
        b.set_issuer_name(&ca_name).unwrap();
        b.set_pubkey(&ca_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca_cert = b.build();

        // ── Server leaf (SAN localhost + 127.0.0.1) ──
        let server_key = gen_key();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name("localhost")).unwrap();
        b.set_issuer_name(ca_cert.subject_name()).unwrap();
        b.set_pubkey(&server_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .ip("127.0.0.1")
            .build(&b.x509v3_context(Some(&ca_cert), None))
            .unwrap();
        b.append_extension(san).unwrap();
        b.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let server_cert = b.build();

        // ── Client leaf ──
        let client_key = gen_key();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name("test-client")).unwrap();
        b.set_issuer_name(ca_cert.subject_name()).unwrap();
        b.set_pubkey(&client_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
        b.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let client_cert = b.build();

        // ── Write PEM files ──
        let ca_cert_path = dir.join("ca.cert.pem");
        let server_cert_path = dir.join("server.cert.pem");
        let server_key_path = dir.join("server.key.pem");
        let client_cert_path = dir.join("client.cert.pem");
        let client_key_path = dir.join("client.key.pem");
        std::fs::write(&ca_cert_path, ca_cert.to_pem().unwrap()).unwrap();
        std::fs::write(&server_cert_path, server_cert.to_pem().unwrap()).unwrap();
        std::fs::write(
            &server_key_path,
            server_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        std::fs::write(&client_cert_path, client_cert.to_pem().unwrap()).unwrap();
        std::fs::write(
            &client_key_path,
            client_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();

        TestPki {
            ca_cert: ca_cert_path,
            server_cert: server_cert_path,
            server_key: server_key_path,
            client_cert: client_cert_path,
            client_key: client_key_path,
        }
    }
}
