#![feature(termination_trait_lib)]
use std::net::IpAddr;
use parity_crypto::publickey::KeyPair;
use ethereum_types::Address;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate ethabi_contract;
#[macro_use]
extern crate async_trait;

pub mod client;
pub mod access_policy;
pub mod document;
pub mod error;

mod eth_client;
mod secret_store_http_client;

pub use eth_client::RpcEthClient;

#[derive(Clone)]
pub struct Configuration {
    pub secret_store_node_address: IpAddr,
    pub secret_store_node_port: u16,
    pub key_pair: KeyPair,
    pub eth_client_address: IpAddr,
    pub eth_client_port: u16,
    pub acl_contract_address: Address,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use ethereum_types::H256;
    use parity_crypto::publickey::{Public, Secret, Random, Generator, ec_math_utils};
    use crate::client::DocumentKeyCiphertext;

    #[derive(Debug)]
    pub enum DummySecretStoreError {
        DocumentAlreadyExists,
        DocumentNotFound,
    }

    struct DummyKey {
        server_key: Secret,
        common_point: Option<Public>,
        encrypted_point: Option<Public>,
    }

    /// test mock simulating the secret store nodes
    pub struct DummySecretStore {
        keys: BTreeMap<H256, DummyKey>
    }

    impl DummySecretStore {
        pub fn new() -> Self {
            DummySecretStore {
                keys: BTreeMap::new()
            }
        }

        pub fn generate_key(&mut self, id: H256, _threshold: u32) -> Result<Public, DummySecretStoreError> {
            if self.keys.get(&id).is_some() {
                return Err(DummySecretStoreError::DocumentAlreadyExists);
            }
            let keypair = Random.generate();
            self.keys.insert(id, DummyKey {
                server_key: keypair.secret().clone(),
                common_point: None,
                encrypted_point: None,
            });
            Ok(keypair.public().clone())
        }

        pub fn store_points(&mut self, id: &H256, common_point: Public, encrypted_point: Public) -> Result<(), DummySecretStoreError> {
            let mut key = self.keys.get_mut(id).ok_or(DummySecretStoreError::DocumentNotFound)?;
            key.common_point = Some(common_point);
            key.encrypted_point = Some(encrypted_point);
            Ok(())
        }

        pub fn decrypt_shadow(&self, id: &H256, requester: &Public) -> Result<DocumentKeyCiphertext, DummySecretStoreError> {
            let key = self.keys.get(id).ok_or(DummySecretStoreError::DocumentNotFound)?;
            let (common_point, encrypted_point) = match (&key.common_point, &key.encrypted_point) {
                (Some(common_point), Some(encrypted_point)) => (common_point, encrypted_point),
                _ => return Err(DummySecretStoreError::DocumentNotFound)
            };
            // secret store runs a thresold proxy decryption, but only the result is
            // visible for the client, so simply re-encrypt for requester
            let document_key = {
                let mut common_point = common_point.clone();
                ec_math_utils::public_mul_secret(&mut common_point, &key.server_key).unwrap();
                let mut document_key = encrypted_point.clone();
                ec_math_utils::public_sub(&mut document_key, &common_point).unwrap();
                document_key
            };
            let k = Random.generate().secret().clone();
            let mut new_common_point = ec_math_utils::generation_point();
            ec_math_utils::public_mul_secret(&mut new_common_point, &k).unwrap();
            let mut new_encrypted_point = requester.clone();
            ec_math_utils::public_mul_secret(&mut new_encrypted_point, &k).unwrap();
            ec_math_utils::public_add(&mut new_encrypted_point, &document_key).unwrap();
            Ok(DocumentKeyCiphertext {
                common_point: new_common_point,
                encrypted_point: new_encrypted_point
            })
        }
    }
}
