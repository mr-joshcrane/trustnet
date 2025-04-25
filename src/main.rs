use trustnet::{Entity, Authority};

fn main() -> anyhow::Result<()> {
    // Create and initialize the authority entity (CA)
    let mut ca = Entity::new("certificate_authority".to_string())?;
    ca.initialize_authority()?;
    println!("CA initialized. Certificate present: {}", ca.certificate.is_some());

    // Create a new client entity
    let mut client = Entity::new("client".to_string())?;

    // The client submits a certificate signing request to the CA
    client.certificate_signing_request(&ca)?;

    // Display certificate information for the client
    if let Some(cert) = &client.certificate {
        println!("Client certificate (PEM):\n{}",
            String::from_utf8_lossy(&cert.to_pem()?));
        println!("Client certificate trusted by client? {}", client.trust_store.is_trusted_cert(cert));
    } else {
        println!("Client did not receive a certificate");
    }

    // For demonstration, display the CA's self-signed certificate
    if let Some(cert) = &ca.certificate {
        println!("CA certificate (PEM):\n{}",
            String::from_utf8_lossy(&cert.to_pem()?));
    }

    // Demonstrate that the client's trust store has the CA's certificate
    if let Some(ca_cert) = &ca.certificate {
        let found = client.trust_store.certificate_authorities.iter()
            .any(|c| *c == *ca_cert);
        println!("Client trust store contains CA cert: {found}");
    }

    Ok(())
}
