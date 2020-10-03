use hyper::{Request, Body, Response};
use crate::error::Error;
use hyper::client::HttpConnector;
use hyper::Client as HttpClient;

#[async_trait]
pub trait SecretStoreHttpClient  {
    async fn request(&self, request: Request<Body>) -> Result<Response<Body>, Error>;
}

/// hyper-based http client
pub struct SecretStoreHttpClientImpl {
    http_client: HttpClient<HttpConnector>
}

impl SecretStoreHttpClientImpl {
    pub fn new() -> Self {
        SecretStoreHttpClientImpl {
            http_client: HttpClient::new()
        }
    }
}

#[async_trait]
impl SecretStoreHttpClient for SecretStoreHttpClientImpl {
    async fn request(&self, request: Request<Body>) -> Result<Response<Body>, Error> {
        self.http_client.request(request).await
            .map_err(|http_err| http_err.into())
    }
}

#[cfg(test)]
pub mod test {
    use std::sync::Mutex;
    use crate::tests::{DummySecretStore, DummySecretStoreError};
    use hyper::{Request, Body, Response, Method};
    use crate::error::Error;
    use ethereum_types::{H256, Address};
    use parity_crypto::publickey::{Signature, Public};
    use crate::secret_store_http_client::SecretStoreHttpClient;
    use regex::Regex;
    use std::collections::BTreeSet;

    lazy_static! {
        static ref GEN_PATTERN: Regex = Regex::new(r"^/shadow/([A-Fa-f0-9]+)/([A-Fa-f0-9]+)/(\d+)$").unwrap();
        static ref STORE_PATTERN: Regex = Regex::new(r"^/shadow/([A-Fa-f0-9]+)/([A-Fa-f0-9]+)/([A-Fa-f0-9]+)/([A-Fa-f0-9]+)$").unwrap();
        static ref GET_PATTERN: Regex = Regex::new(r"^/shadow/([A-Fa-f0-9]+)/([A-Fa-f0-9]+)$").unwrap();
    }

    pub struct DummySecretStoreHttpClient {
        secret_store: Mutex<DummySecretStore>,
        blacklist: Mutex<BTreeSet<H256>>,
        access_log: Mutex<Vec<(H256,Address)>>
    }

    impl DummySecretStoreHttpClient {
        pub fn new(secret_store: DummySecretStore) -> Self {
            DummySecretStoreHttpClient {
                secret_store: Mutex::new(secret_store),
                blacklist: Mutex::new(BTreeSet::new()),
                access_log: Mutex::new(Vec::new()),
            }
        }

        pub fn blacklist(&self, document: &H256) {
            let mut blacklist = self.blacklist.lock().unwrap();
            blacklist.insert(document.clone());
        }

        pub fn get_access_log(&self) -> Vec<(H256,Address)> {
            self.access_log.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SecretStoreHttpClient for DummySecretStoreHttpClient {
        async fn request(&self, request: Request<Body>) -> Result<Response<Body>, Error> {
            if let Some(capture) = GEN_PATTERN.captures(request.uri().path()) {
                assert_eq!(request.method(), &Method::POST);
                // generation request
                let id: H256 = capture[1].parse().unwrap();
                // dummy doesn't check signature
                println!("uri={}", request.uri().path());
                println!("capture[3] = {}", &capture[3]);
                let threshold: u32 = capture[3].parse().unwrap();

                return match self.secret_store.lock().unwrap().generate_key(id, threshold) {
                    Ok(public) => Ok(Response::builder()
                        .status(200)
                        .body(Body::from(format!("\"0x{:x}\"", public))).unwrap()),
                    Err(DummySecretStoreError::DocumentNotFound) => Ok(Response::builder()
                        .status(404)
                        .body(Body::empty())
                        .unwrap()),
                    Err(DummySecretStoreError::DocumentAlreadyExists) => Ok(Response::builder()
                        .status(400)
                        .body(Body::empty())
                        .unwrap()),
                }
            }

            if let Some(capture) = STORE_PATTERN.captures(request.uri().path()) {
                assert_eq!(request.method(), &Method::POST);
                // store request
                let id: H256 = capture[1].parse().unwrap();
                // dummy doesn't check signature
                let common_point: Public = capture[3].parse().unwrap();
                let encrypted_point: Public = capture[4].parse().unwrap();

                return match self.secret_store.lock().unwrap().store_points(&id, common_point, encrypted_point) {
                    Ok(()) => Ok(Response::builder()
                        .status(200)
                        .body(Body::empty())
                        .unwrap()),
                    Err(DummySecretStoreError::DocumentNotFound) => Ok(Response::builder()
                        .status(404)
                        .body(Body::empty())
                        .unwrap()),
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
            }

            if let Some(capture) = GET_PATTERN.captures(request.uri().path()) {
                assert_eq!(request.method(), &Method::POST);
                // shadow decryption request
                let id: H256 = capture[1].parse().unwrap();
                let signature: Signature = capture[2].parse().unwrap();
                let public = parity_crypto::publickey::recover(&signature, &id).unwrap();
                // make log
                {
                    let address = parity_crypto::publickey::public_to_address(&public);
                    let mut log = self.access_log.lock().unwrap();
                    log.push((id, address));
                }
                // check against blacklist
                {
                    let blacklist = self.blacklist.lock().unwrap();
                    if blacklist.contains(&id) {
                        return Ok(Response::builder()
                            .status(403)
                            .body(Body::empty())
                            .unwrap());
                    }
                }
                return match self.secret_store.lock().unwrap().decrypt_shadow(&id, &public) {
                    Ok(shadows) => Ok(Response::builder()
                        .status(200)
                        .body(Body::from(serde_json::to_string(&shadows).unwrap()))
                        .unwrap()),
                    Err(DummySecretStoreError::DocumentNotFound) => Ok(Response::builder()
                        .status(404)
                        .body(Body::empty())
                        .unwrap()),
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
            }

            Err(Error::Eth(format!("unsupported request: {}", request.uri())))
        }
    }

    pub struct UnimplementedSecretStoreHttpClient {}

    #[async_trait]
    impl SecretStoreHttpClient for UnimplementedSecretStoreHttpClient {
        async fn request(&self, _: Request<Body>) -> Result<Response<Body>, Error> {
            unimplemented!()
        }
    }
}
