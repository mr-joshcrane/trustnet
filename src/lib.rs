use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use rsa::oaep::Oaep;
use rsa::rand_core::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa as OSSLRSA;
use openssl::x509::{X509Builder, X509NameBuilder, X509};

use anyhow::{anyhow, Error, Ok};

pub struct Entity {
    pub name: String,
    pub certificate: Option<X509>,
    pub trust_store: TrustStore,
    private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

pub struct TrustStore {
    pub certificate_authorities: Vec<X509>,
}

impl TrustStore {
    pub fn new() -> Self {
        TrustStore { certificate_authorities: Vec::new() }
    }

    pub fn add_cert_authority(&mut self, cert: X509) {
        self.certificate_authorities.push(cert);
    }

    pub fn is_trusted_cert(&self, cert: &X509) -> bool {
        self.certificate_authorities.iter().any(|ca| {
            ca.public_key()
                .ok()
                .and_then(|pk| cert.verify(&pk).ok())
                .unwrap_or(false)
        })
    }
}

impl Entity {
    pub fn new(name: String) -> Result<Self, Error> {
        let trust_store = TrustStore::new();
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        let certificate = None;
        Ok(Self {
            name,
            certificate,
            trust_store,
            private_key,
            public_key,
        })
    }
    
    pub fn certificate_signing_request(&mut self, authority: &impl Authority) -> Result<(), Error> {
        let public_key = self.get_public_key();
        let certificate = authority.sign_entity(self.name.clone(), &public_key)?;
        self.certificate = Some(certificate);
        let root_certificate = authority.authority_certificate().ok_or(anyhow!("authority didn't return it's root certificate. Has it been initialised properly?"));
        self.trust_store.add_cert_authority(root_certificate?);
        Ok(())
    }

    pub fn decrypt(&self, msg: Vec<u8>) -> Result<String, Error> {
        let decrypted = self.private_key.decrypt(Oaep::new::<Sha256>(), &msg)?;
        let decrypted_string = String::from_utf8(decrypted)?;
        Ok(decrypted_string)
    }

    pub fn get_public_key(&self) -> RsaPublicKey {
        self.public_key.clone()
    }
}

fn encrypt(pub_key: RsaPublicKey, msg: &str) -> Result<Vec<u8>, Error> {
    let padding = Oaep::new::<Sha256>();
    Ok(pub_key.encrypt(&mut OsRng, padding, msg.as_bytes())?)
}

pub trait Authority {
    fn initialize_authority(&mut self) -> Result<(), Error>;
    fn authority_certificate(&self) -> Option<X509>;
    fn private_key(&self) -> Result<PKey<Private>, Error>;
    fn sign_entity(
        &self,
        subject: String,
        entity_public_key: &rsa::RsaPublicKey,
    ) -> Result<X509, Error>;
}

impl Authority for Entity {
    fn initialize_authority(&mut self) -> Result<(), Error> {
        let private_key = self.private_key()?;
        let public_key = self.public_key.clone();
        let pkey = rsa_public_key_to_pkey(&public_key)?;
        let certificate = make_certificate(self.name.clone(), self.name.clone(), &pkey, &private_key)?;
        self.certificate = Some(certificate.clone());
        self.trust_store.add_cert_authority(certificate);
        Ok(())
    }

    fn authority_certificate(&self) -> Option<X509> {
        self.certificate.clone()
    }

    fn private_key(&self) -> Result<PKey<Private>, Error> {
        let key = self.private_key.clone();
        let n = BigNum::from_slice(&key.n().to_bytes_be())?;
        let e = BigNum::from_slice(&key.e().to_bytes_be())?;
        let d = BigNum::from_slice(&key.d().to_bytes_be())?;
        let primes = key.primes();
        if primes.len() < 2 {
            return Err(anyhow::anyhow!("RSA key does not have enough primes"));
        }
        let p = BigNum::from_slice(&primes[0].to_bytes_be())?;
        let q = BigNum::from_slice(&primes[1].to_bytes_be())?;

        let openssl_rsa = OSSLRSA::from_private_components(
            n,
            e,
            d,
            p,
            q,
            BigNum::new()?,
            BigNum::new()?,
            BigNum::new()?,
        )?;
        Ok(openssl::pkey::PKey::from_rsa(openssl_rsa)?)
    }

    fn sign_entity(
        &self,
        subject_name: String,
        entity_public_key: &rsa::RsaPublicKey,
    ) -> Result<X509, Error> {
        let public_key = rsa_public_key_to_pkey(entity_public_key)?;
        let signing_key = self.private_key()?;
        make_certificate(subject_name, self.name.clone(), &public_key, &signing_key)
    }
}

fn make_certificate(
    subject_name: String,
    issuer_name: String,
    public_key: &PKey<Public>,
    signing_key: &PKey<Private>,
) -> Result<X509, Error> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", &subject_name)?;
    let subject_name = name_builder.build();
    let mut issuer_builder = X509NameBuilder::new()?;
    issuer_builder.append_entry_by_text("CN", &issuer_name)?;
    let issuer_name = issuer_builder.build();
    

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&subject_name)?;
    builder.set_pubkey(public_key)?;
    builder.set_issuer_name(&issuer_name)?;
    let serial_number = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;
    let time_before = Asn1Time::days_from_now(0)?;
    let time_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&time_before)?;
    builder.set_not_after(&time_after)?;
    builder.sign(signing_key, MessageDigest::sha256())?;
    Ok(builder.build())
}

fn rsa_public_key_to_pkey(key: &RsaPublicKey) -> Result<PKey<Public>, Error> {
    let n = BigNum::from_slice(&key.n().to_bytes_be())?;
    let e = BigNum::from_slice(&key.e().to_bytes_be())?;
    let openssl_rsa = OSSLRSA::from_public_components(n, e)?;
    Ok(PKey::from_rsa(openssl_rsa)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_can_decrypt_a_message_signed_with_its_public_key() {
        let entity = Entity::new("name".to_string()).unwrap();
        let message = "some message";
        let encrypted =
            encrypt(entity.get_public_key(), message).expect("message could not be encrypted");
        let result = entity.decrypt(encrypted).unwrap();
        assert_eq!(result, message, "expected {message}, got {result}")
    }

    #[test]
    fn second_entity_cant_decrypt_message_signed_with_someone_elses_public_key() {
        let e_one = Entity::new("e_one".to_string()).unwrap();
        let e_two = Entity::new("e_two".to_string()).unwrap();
        let message = "some message";
        let encrypted =
            encrypt(e_one.get_public_key(), message).expect("message could not be encrypted");
        e_two
            .decrypt(encrypted)
            .expect_err("shouldn't be able to decrypt someone elses message");
    }

    #[test]
    fn authority_initializes_with_self_signed_certificate() {
        let mut authority = Entity::new("certificate_authority".to_string()).unwrap();
        assert!(authority.certificate.is_none());
        authority.initialize_authority().unwrap();
        assert!(authority.certificate.is_some());
        assert!(authority.trust_store.certificate_authorities.len() == 1);
    }

    #[test]
    fn entity_gets_cert_and_trusts_ca_after_csr() {
        let mut authority = Entity::new("authority".to_string()).unwrap();
        authority.initialize_authority().unwrap();

        let mut client = Entity::new("client".to_string()).unwrap();
        assert!(client.certificate.is_none());
        assert_eq!(client.trust_store.certificate_authorities.len(), 0);

        client.certificate_signing_request(&authority).unwrap();
        assert!(client.certificate.is_some());
        assert_eq!(client.trust_store.certificate_authorities.len(), 1);
        let authority_certificate = authority.certificate.clone().unwrap();
        let client_trusted_certificate = client.trust_store.certificate_authorities[0].clone();
        assert_eq!(authority_certificate, client_trusted_certificate);
    }

    #[test]
    fn entity_can_differentiate_between_trusted_and_untrusted_authorities() {
        let mut authority = Entity::new("authority".to_string()).unwrap();
        authority.initialize_authority().unwrap();
        
        let mut evil_authority = Entity::new("untrustworthy".to_string()).unwrap();
        evil_authority.initialize_authority().unwrap();

        let mut entity = Entity::new("client".to_string()).unwrap();
        entity.certificate_signing_request(&authority).unwrap();
        let good_certificate = entity.certificate.as_ref().unwrap();
        assert!(entity.trust_store.is_trusted_cert(good_certificate));


        let mut evil_entity = Entity::new("evil_client".to_string()).unwrap();
        evil_entity.certificate_signing_request(&evil_authority).unwrap();
        let evil_certificate = evil_entity.certificate.as_ref().unwrap();
        assert!(!entity.trust_store.is_trusted_cert(evil_certificate));
    }
}
