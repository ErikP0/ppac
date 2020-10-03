// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Secret Store.

// Parity Secret Store is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Secret Store is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Secret Store.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use parking_lot::{Mutex, RwLock};
use ethereum_types::{Address, U256};
use ethabi::FunctionOutputDecoder;
use blockchain::{SecretStoreChain, NewBlocksNotify, ContractAddress, BlockId};
use types::{Error, ServerKeyId};
use rustc_hex::ToHex;
use std::time::Duration;

use_contract!(acl_storage, "res/acl_storage.json");
use_contract!(acl_storage_payload, "res/acl_storage_payload.json");

pub const ACL_CHECKER_CONTRACT_REGISTRY_NAME: &'static str = "secretstore_acl_checker";

/// ACL storage of Secret Store
pub trait AclStorage: Send + Sync {
	/// Check if requester can access document with hash `document`
	fn check(&self, requester: Address, document: &ServerKeyId) -> Result<bool, Error>;
	fn check_with_payload(&self, requester: Address, document: &ServerKeyId, authorization_payload: &Vec<U256>) -> Result<bool, Error>;
}

/// On-chain ACL storage implementation.
pub struct OnChainAclStorage {
	/// Cached on-chain contract.
	contract: Mutex<CachedContract>,
}

/// Cached on-chain ACL storage contract.
struct CachedContract {
	/// Blockchain client.
	client: Arc<dyn SecretStoreChain>,
	/// Contract address source.
	address_source: ContractAddress,
	/// Current contract address.
	contract_address: Option<Address>,
}

/// Dummy ACL storage implementation (check always passed).
#[derive(Default, Debug)]
pub struct DummyAclStorage {
	prohibited: RwLock<HashMap<Address, HashSet<ServerKeyId>>>,
}

impl OnChainAclStorage {
	pub fn new(trusted_client: Arc<dyn SecretStoreChain>, address_source: ContractAddress) -> Result<Arc<Self>, Error> {
		let acl_storage = Arc::new(OnChainAclStorage {
			contract: Mutex::new(CachedContract::new(trusted_client.clone(), address_source)),
		});
		trusted_client.add_listener(acl_storage.clone());
		Ok(acl_storage)
	}
}

impl AclStorage for OnChainAclStorage {
	fn check(&self, requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
		self.contract.lock().check(requester, document)
	}

    fn check_with_payload(
        &self,
        requester: Address,
        document: &ServerKeyId,
        authorization_payload: &Vec<U256>,
    ) -> Result<bool, Error> {
        self.contract
            .lock()
            .check_with_payload(requester, document, authorization_payload)
    }
}

impl NewBlocksNotify for OnChainAclStorage {
	fn new_blocks(&self, _new_enacted_len: usize) {
		self.contract.lock().update_contract_address()
	}
}

impl CachedContract {
	pub fn new(client: Arc<dyn SecretStoreChain>, address_source: ContractAddress) -> Self {
		let mut contract = CachedContract {
			client,
			address_source,
			contract_address: None,
		};
		contract.update_contract_address();
		contract
	}

	pub fn update_contract_address(&mut self) {
		let contract_address = self.client.read_contract_address(
			ACL_CHECKER_CONTRACT_REGISTRY_NAME,
			&self.address_source
		);
		if contract_address != self.contract_address {
			trace!(target: "secretstore", "Configuring for ACL checker contract from address {:?}",
				contract_address);

			self.contract_address = contract_address;
		}
	}

	fn wait_for_trusted_client(&self) {
		let start = std::time::Instant::now();
		let timeout = std::time::Duration::from_secs(5);
		while start.elapsed() < timeout {
			if self.client.is_trusted() {
				return
			}else{
				std::thread::sleep(Duration::from_millis(100))
			}
		}
	}

	pub fn check(&mut self, requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
		self.wait_for_trusted_client();
		if self.client.is_trusted() {
			// call contract to check accesss
			match self.contract_address {
				Some(contract_address) => {
					let (encoded, decoder) = acl_storage::functions::check_permissions::call(requester, document.clone());
					let d = self.client.call_contract(BlockId::Latest, contract_address, encoded)
						.map_err(|e| Error::Internal(format!("ACL checker call error: {}", e.to_string())))?;
					decoder.decode(&d)
						.map_err(|e| Error::Internal(format!("ACL checker call error: {}", e.to_string())))
				},
				None => Err(Error::Internal("ACL checker contract is not configured".to_owned())),
			}
		} else {
			Err(Error::Internal("Calling ACL contract without trusted blockchain client".into()))
		}
	}

    pub fn check_with_payload(
        &mut self,
        requester: Address,
        document: &ServerKeyId,
        payload: &Vec<U256>,
    ) -> Result<bool, Error> {
		self.wait_for_trusted_client();
		let payload_as_str = {
			let mut payload_as_str = String::new();
			for (i,x) in payload.iter().map(|x| format!("{:x}",x)).enumerate() {
				payload_as_str.push_str(&x);
				if i < payload.len()-1 {
					payload_as_str.push_str(",");
				}
			}
			payload_as_str
		};
        if self.client.is_trusted() {
            // call contract to check accesss
            match self.contract_address {
                Some(contract_address) => {
                    let (encoded, decoder) =
                        acl_storage_payload::functions::check_permissions::call(
                            requester,
                            document.clone(),
                            payload.clone(),
                        );
					debug!(target: "secretstore", "Calling check_with_payload({:x},{:x},{})={}", requester, document, payload_as_str, encoded.to_hex());
                    let d = self
                        .client
						.call_contract(BlockId::Latest, contract_address, encoded)
                        .map_err(|e| {
							Error::Internal(format!("ACL checker call error: {}", e.to_string()))
                        })?;
                    decoder.decode(&d).map_err(|e| {
						Error::Internal(format!("ACL checker call error: {}", e.to_string()))
                    })
                }
                None => Err(Error::Internal(
                    "ACL checker contract is not configured".to_owned(),
                )),
            }
        } else {
            Err(Error::Internal(
				"Calling ACL contract without trusted blockchain client".into(),
            ))
        }
    }
}

impl DummyAclStorage {
	/// Prohibit given requester access to given documents
	#[cfg(test)]
	pub fn prohibit(&self, requester: Address, document: ServerKeyId) {
		self.prohibited.write()
			.entry(requester)
			.or_insert_with(Default::default)
			.insert(document);
	}
}

impl AclStorage for DummyAclStorage {
	fn check(&self, requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
		Ok(self.prohibited.read()
			.get(&requester)
			.map(|docs| !docs.contains(document))
			.unwrap_or(true))
	}

    fn check_with_payload(
        &self,
        requester: Address,
        document: &ServerKeyId,
        _: &Vec<U256>,
    ) -> Result<bool, Error> {
        // Dummy ignores payload
        self.check(requester, document)
    }
}
