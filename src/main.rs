use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsIter};
use std::io::{Error, ErrorKind};

fn main() {
    println!("Looking for bad certificates...");
    
    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        println!("");
        println!("Checking {:?} domain...", domain);
        let ts = TrustSettings::new(*domain);
        let iter = ts
            .iter()
            .map_err(|err| Error::new(ErrorKind::Other, err));

        match iter {
            Ok(iter) => check_certs(iter, &ts),
            Err(err) => println!("Error: {:?}", err),
        }
    }
}

fn check_certs(iter: TrustSettingsIter, ts: &TrustSettings) {
    for cert in iter {
        println!("Certificate {:?}", cert.subject_summary());
        let _ = cert.to_der();

        match ts.tls_trust_settings_for_certificate(&cert) {
            Ok(_) => {},
            Err(err) => {
                println!("Error: {:?}", err);
            },
        }
    }
}