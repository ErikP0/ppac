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

extern crate byteorder;
extern crate ethabi;
extern crate ethereum_types;
extern crate hyper;
extern crate secp256k1;
extern crate keccak_hash as hash;
extern crate kvdb;
extern crate kvdb_rocksdb;
extern crate parity_bytes as bytes;
extern crate parity_crypto as crypto;
extern crate parity_runtime;
extern crate parking_lot;
extern crate percent_encoding;
extern crate rustc_hex;
extern crate serde;
extern crate serde_json;
extern crate tiny_keccak;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_service;
extern crate url;
extern crate jsonrpc_server_utils;

extern crate ethabi_derive;
#[macro_use]
extern crate ethabi_contract;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

#[cfg(test)]
extern crate env_logger;
#[cfg(test)]
extern crate tempdir;
extern crate rlp;

extern crate jsonrpc_core_client;
#[cfg(test)]
extern crate jsonrpc_http_server;

mod key_server_cluster;
mod types;

mod traits;
mod acl_storage;
mod key_server;
mod key_storage;
mod serialization;
mod key_server_set;
mod node_key_pair;
mod listener;
mod blockchain;
mod migration;
mod transaction_signature;

use std::sync::Arc;
use kvdb::KeyValueDB;
use kvdb_rocksdb::{Database, DatabaseConfig};
use parity_runtime::Executor;

pub use types::{ServerKeyId, EncryptedDocumentKey, RequestSignature, Public,
	Error, NodeAddress, ServiceConfiguration, ClusterConfiguration};
pub use traits::KeyServer;
pub use blockchain::{SecretStoreChain, SigningKeyPair, ContractAddress, BlockId, BlockNumber, NewBlocksNotify, Filter};
pub use self::node_key_pair::PlainNodeKeyPair;
use blockchain::EthRpcClient;
use acl_storage::ACL_CHECKER_CONTRACT_REGISTRY_NAME;

/// Open a secret store DB using the given secret store data path. The DB path is one level beneath the data path.
pub fn open_secretstore_db(data_path: &str) -> Result<Arc<dyn KeyValueDB>, String> {
	use std::path::PathBuf;

	migration::upgrade_db(data_path).map_err(|e| e.to_string())?;

	let mut db_path = PathBuf::from(data_path);
	db_path.push("db");
	let db_path = db_path.to_str().ok_or_else(|| "Invalid secretstore path".to_string())?;

	let config = DatabaseConfig::with_columns(1);
	Ok(Arc::new(Database::open(&config, &db_path).map_err(|e| format!("Error opening database: {:?}", e))?))
}

/// Start new key server instance
pub fn start(trusted_client: Arc<dyn SecretStoreChain>, self_key_pair: Arc<dyn SigningKeyPair>, mut config: ServiceConfiguration,
	db: Arc<dyn KeyValueDB>, executor: Executor) -> Result<Box<dyn KeyServer>, Error>
{
	let acl_storage: Arc<dyn acl_storage::AclStorage> = match &config.acl_check_contract_address {
		Some(acl_check_contract_address) => acl_storage::OnChainAclStorage::new(trusted_client.clone(), acl_check_contract_address.clone())?,
		None => Arc::new(acl_storage::DummyAclStorage::default()),
	};

	let key_server_set = key_server_set::OnChainKeyServerSet::new(trusted_client.clone(), config.cluster_config.key_server_set_contract_address.take(),
		self_key_pair.clone(), config.cluster_config.auto_migrate_enabled, config.cluster_config.nodes.clone())?;
	let key_storage = Arc::new(key_storage::PersistentKeyStorage::new(db)?);
	let eth_client = Arc::new(EthRpcClient::new(executor.clone(), &config.http_rpc_address)?);
	info!("Using eth-client at {:?}", config.http_rpc_address);
	let log_contract_address = config.acl_check_contract_address.take().map(|acl_contract_address|trusted_client.read_contract_address(ACL_CHECKER_CONTRACT_REGISTRY_NAME, &acl_contract_address)).flatten();
	let key_server = Arc::new(key_server::KeyServerImpl::new(&config.cluster_config, key_server_set.clone(), self_key_pair.clone(),
		acl_storage.clone(), key_storage.clone(), log_contract_address,  eth_client, executor.clone())?);
	let cluster = key_server.cluster();
	let key_server: Arc<dyn KeyServer> = key_server;

	// prepare HTTP listener
	let http_listener = match config.listener_address {
		Some(listener_address) => Some(listener::http_listener::KeyServerHttpListener::start(listener_address, config.cors, Arc::downgrade(&key_server), executor)?),
		None => None,
	};

	// prepare service contract listeners
	let create_service_contract = |address, name, api_mask|
		Arc::new(listener::service_contract::OnChainServiceContract::new(
			api_mask,
			trusted_client.clone(),
			name,
			address,
			self_key_pair.clone()));

	let mut contracts: Vec<Arc<dyn listener::service_contract::ServiceContract>> = Vec::new();
	config.service_contract_address.map(|address|
		create_service_contract(address,
			listener::service_contract::SERVICE_CONTRACT_REGISTRY_NAME.to_owned(),
			listener::ApiMask::all()))
		.map(|l| contracts.push(l));
	config.service_contract_srv_gen_address.map(|address|
		create_service_contract(address,
			listener::service_contract::SRV_KEY_GEN_SERVICE_CONTRACT_REGISTRY_NAME.to_owned(),
			listener::ApiMask { server_key_generation_requests: true, ..Default::default() }))
		.map(|l| contracts.push(l));
	config.service_contract_srv_retr_address.map(|address|
		create_service_contract(address,
			listener::service_contract::SRV_KEY_RETR_SERVICE_CONTRACT_REGISTRY_NAME.to_owned(),
			listener::ApiMask { server_key_retrieval_requests: true, ..Default::default() }))
		.map(|l| contracts.push(l));
	config.service_contract_doc_store_address.map(|address|
		create_service_contract(address,
			listener::service_contract::DOC_KEY_STORE_SERVICE_CONTRACT_REGISTRY_NAME.to_owned(),
			listener::ApiMask { document_key_store_requests: true, ..Default::default() }))
		.map(|l| contracts.push(l));
	config.service_contract_doc_sretr_address.map(|address|
		create_service_contract(address,
			listener::service_contract::DOC_KEY_SRETR_SERVICE_CONTRACT_REGISTRY_NAME.to_owned(),
			listener::ApiMask { document_key_shadow_retrieval_requests: true, ..Default::default() }))
		.map(|l| contracts.push(l));

	let contract: Option<Arc<dyn listener::service_contract::ServiceContract>> = match contracts.len() {
		0 => None,
		1 => Some(contracts.pop().expect("contract.len() is 1; qed")),
		_ => Some(Arc::new(listener::service_contract_aggregate::OnChainServiceContractAggregate::new(contracts))),
	};

	let contract_listener = match contract {
		Some(contract) => Some({
			let listener = listener::service_contract_listener::ServiceContractListener::new(
				listener::service_contract_listener::ServiceContractListenerParams {
					contract: contract,
					self_key_pair: self_key_pair.clone(),
					key_server_set: key_server_set,
					acl_storage: acl_storage,
					cluster: cluster,
					key_storage: key_storage,
				}
			)?;
			trusted_client.add_listener(listener.clone());
			listener
		}),
		None => None,
	};

	Ok(Box::new(listener::Listener::new(key_server, http_listener, contract_listener)))
}

#[cfg(test)]
mod tests {
	use ::{SecretStoreChain, Filter};
	use ethereum_types::{Address, H256, U256, H160};
	use ethabi::{RawLog, Bytes, Token, Function, Param, ParamType};
	use std::sync::{Arc, Mutex};
	use ::{BlockId, NewBlocksNotify};
	use ::{ContractAddress, PlainNodeKeyPair};
	use acl_storage::AclStorage;
	use crypto::publickey::{KeyPair, Random, Generator, Secret, Public, Signature};
	use crypto::DEFAULT_MAC;
	use super::KeyServer;
	use parity_runtime::{Runtime, Executor};
	use ::{NodeAddress, ClusterConfiguration};
	use std::collections::{BTreeMap, BTreeSet};
	use ::{ServiceConfiguration, ServerKeyId};
	use tempdir::TempDir;
	use Error;
	use std::path::Path;
	use types::Requester;
	use futures::{Future, future, Stream};
	use key_server_cluster::math;
	use traits::JOINT_SIGNATURE_KEY_ID;
	use blockchain::{EthClient, EthRpcClient, TransactionByHash, DummyEthClient, EstimateGasArgs};
	use jsonrpc_http_server::{ServerBuilder, CloseHandle};
	use jsonrpc_http_server::jsonrpc_core::IoHandler;
	use jsonrpc_http_server::jsonrpc_core;
	use serde_json::{Value, json};
	use jsonrpc_server_utils::hosts::DomainsValidation;
	use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
	use std::net::{SocketAddr, AddrParseError};
	use std::time::Duration;
	use bytes::ToPretty;
	use std::str::FromStr;
	use rustc_hex::FromHex;
	use rlp::Rlp;
	use futures::sync::oneshot;
	use hyper::{Request, Body};
	use transaction_signature::RawTransaction;
	use key_server_cluster::decryption_session_with_payload::ProxyEncryptedDocumentKey;

	/// Version of the secret store database
	const SECRET_STORE_DB_VERSION: &str = "4";
	/// Version file name
	const SECRET_STORE_DB_VERSION_FILE_NAME: &str = "db_version";

	// created with https://abi.hashex.org/#
	// for ABI specification see https://ethereum.stackexchange.com/a/1171
	const CHECK_PERMISSIONS_SIGNATURE: &[u8; 4] = &[0xb3u8, 0x6au8, 0x9au8, 0x7cu8];
	const CHECK_PERMISSIONS_PAYLOAD_SIGNATURE: &[u8; 4] = &[0x47u8, 0xe3u8, 0x56u8, 0x28u8];

	struct ChainClientMock {
		acl_storage_callback: Arc<Mutex<dyn AclStorage>>,
		check_permissions: Function,
		check_permissions_payload: Function
	}

	impl ChainClientMock {
		pub fn new(callback: Arc<Mutex<dyn AclStorage>>) -> ChainClientMock {
			ChainClientMock {
				acl_storage_callback: callback,
				check_permissions: Function {
					name: "checkPermissions".into(),
					inputs: vec![Param{
						name: "user".into(),
						kind: ParamType::Address
					}, Param {
						name: "document".into(),
						kind: ParamType::FixedBytes(32)
					}],
					outputs: vec![Param{
						name: "".into(),
						kind: ParamType::Bool
					}],
					constant: true
				},
				check_permissions_payload: Function {
					name: "checkPermissions".into(),
					inputs: vec![Param{
						name: "user".into(),
						kind: ParamType::Address
					}, Param {
						name: "document".into(),
						kind: ParamType::FixedBytes(32)
					}, Param {
						name: "payload".into(),
						kind: ParamType::Array(Box::from(ParamType::Uint(256)))
					}],
					outputs: vec![Param{
						name: "".into(),
						kind: ParamType::Bool
					}],
					constant: true
				}
			}
		}
	}

	fn bytes32_to_array(bytes: &Vec<u8>) -> [u8; 32] {
		let mut array = [0; 32];
		assert_eq!(32, bytes.len());
		array.copy_from_slice(&bytes.as_slice());
		return array;
	}

	fn decode_input(function: &Function, signature: &[u8; 4], data: &Bytes) -> Result<Vec<Token>, ethabi::Error> {
		if data.len() < 4 || &data[0..4] != signature {
			Err(ethabi::Error::InvalidData)
		}else{
			function.decode_input(&data[4..])
		}
	}

	impl SecretStoreChain for ChainClientMock {
		fn add_listener(&self, _target: Arc<dyn NewBlocksNotify>) {
			// mock doesn't call listeners for new blocks
		}

		fn is_trusted(&self) -> bool {
			true
		}

		fn transact_contract(&self, _contract: Address, _tx_data: Bytes) -> Result<(), crypto::publickey::Error> {
			unimplemented!()
		}

		fn read_contract_address(&self, _registry_name: &str, address: &ContractAddress) -> Option<Address> {
			match address {
				ContractAddress::Address(addr) => Some(addr.clone()),
				_ => unimplemented!("in mock")
			}
		}

		fn call_contract(&self, _block_id: BlockId, _contract_address: Address, data: Bytes) -> Result<Bytes, String> {
			let check_permissions = decode_input(&self.check_permissions, CHECK_PERMISSIONS_SIGNATURE, &data);
			let check_permissions_payload = decode_input(&self.check_permissions_payload, CHECK_PERMISSIONS_PAYLOAD_SIGNATURE, &data);
			let res = match (check_permissions, check_permissions_payload) {
				(Ok(tokens), _) => {
					assert_eq!(2, tokens.len());
					match (&tokens[0], &tokens[1]) {
						(Token::Address(user), Token::FixedBytes(bytes)) => {
							let document_id = bytes32_to_array(bytes).into();
							self.acl_storage_callback.lock().unwrap().check(user.clone(), &document_id)
						}
						(_,_) => panic!("checkPermissions function called with invalid parameters")
					}
				}
				(_, Ok(tokens)) => {
					assert_eq!(3, tokens.len());
					match (&tokens[0], &tokens[1], &tokens[2]) {
						(Token::Address(user), Token::FixedBytes(bytes), Token::Array(array_tokens)) => {
							let payload = array_tokens.iter()
								.map(|tk| match tk {
									Token::Uint(uint) => uint.clone(),
									_ => panic!("Invalid types in payload array")
								})
								.collect();
							let document_id = bytes32_to_array(bytes).into();
							self.acl_storage_callback.lock().unwrap().check_with_payload(user.clone(), &document_id, &payload)
						}
						(_,_,_) => panic!("checkPermissions function called with invalid parameters")
					}
				}
				(_,_) => panic!("Unknown function called"),
			};
			let acl_decision = res.unwrap();
			Ok(ethabi::encode(vec![Token::Bool(acl_decision)].as_slice()))
		}


		fn block_hash(&self, _id: BlockId) -> Option<H256> {
			unimplemented!()
		}

		fn block_number(&self, _id: BlockId) -> Option<u64> {
			unimplemented!()
		}

		fn retrieve_last_logs(&self, _filter: Filter) -> Option<Vec<RawLog>> {
			unimplemented!()
		}

		fn get_confirmed_block_hash(&self) -> Option<H256> {
			unimplemented!()
		}
	}

	fn gen_key_pair() -> KeyPair {
		Random.generate()
	}

	/// creating a secret-store db in an empty directory produces a false migration error
	/// workaround from https://github.com/openethereum/openethereum/commit/2bcc31928eae46914cdf06e93a145a7da40210d6
	fn initialize_db(db_dir_path: &Path) {
		// Create a file containing the version of the database of the SecretStore
		// when no database exists yet
		if std::fs::read_dir(db_dir_path).map_or(false, |mut list| list.next().is_none ()) {
			std::fs::write(db_dir_path.clone().join(SECRET_STORE_DB_VERSION_FILE_NAME), SECRET_STORE_DB_VERSION).unwrap();
		}
	}

	fn start_key_servers(
		mut acl_callbacks: Vec<Arc<Mutex<dyn AclStorage>>>,
		acl_contract_addr: ContractAddress,
		runtime: &Runtime,
		base_port: u16,
		local_rpc_port: u16,
		http_port: Option<u16>
	) -> Vec<Box<dyn KeyServer>> {
		let keys: Vec<KeyPair> = (0..acl_callbacks.len()).map(|_| gen_key_pair()).collect();
		let addresses: Vec<NodeAddress> = (0..acl_callbacks.len()).map(|i| NodeAddress {
			address: "127.0.0.1".into(),
			port: base_port+ (i as u16)
		}).collect();
		let mut nodes = BTreeMap::new();
		keys.iter().zip(&addresses)
			.for_each(|(k,v)| {
				nodes.insert(k.public().clone(),v.clone());
			} );
		let key_servers: Vec<Box<dyn KeyServer>> = acl_callbacks
			.drain(..acl_callbacks.len())
			.enumerate()
			.map(|(i, acl_callback)| {
				let cluster_config = ClusterConfiguration {
					listener_address: (&addresses[i]).clone(),
					nodes: nodes.clone(),
					key_server_set_contract_address: None,
					allow_connecting_to_higher_nodes: false,
					admin_public: None,
					auto_migrate_enabled: false
				};
				let service_config = ServiceConfiguration {
					//for HTTP api
					listener_address: if i == 0 {
						http_port.map(|port| NodeAddress {
							address: "127.0.0.1".to_string(),
							port
						})
					}else{
						None
					},
					service_contract_address: None,
					service_contract_srv_gen_address: None,
					service_contract_srv_retr_address: None,
					service_contract_doc_store_address: None,
					service_contract_doc_sretr_address: None,
					acl_check_contract_address: Some(acl_contract_addr.clone()),
					cluster_config,
					cors: None,
					http_rpc_address: NodeAddress {
						address: "127.0.0.1".to_string(),
						port: local_rpc_port
					}
				};
				let client = Arc::new(ChainClientMock::new(acl_callback));
				let db_dir = TempDir::new("secret-store-db").unwrap();
				initialize_db(db_dir.path());
				let db = super::open_secretstore_db(db_dir.path().to_str().unwrap()).unwrap();
				let executor = runtime.executor();
				let key_pair = Arc::new(PlainNodeKeyPair::new(keys[i].clone()));
				super::start(client, key_pair, service_config, db, executor).unwrap()
		})
			.collect();
		::key_server::tests::wait_until_fully_connected(&key_servers);
		return key_servers;
	}

	struct EthServerMock {
		close_handle: CloseHandle
	}

	impl EthServerMock {
		pub fn start(runtime: &Runtime, callback: Arc<dyn EthClient>, port: u16) -> Result<EthServerMock, String> {
			let mut io = IoHandler::default();
			let callback_chain_id = callback.clone();
			let callback_get_transaction_count = callback.clone();
			let callback_gas_price = callback.clone();
			let callback_get_transaction_by_hash = callback.clone();
			let callback_send_raw_transaction = callback.clone();
			let callback_estimage_gas = callback.clone();
			io.add_method("eth_chainId", move |params| {
				assert_eq!(params, jsonrpc_core::Params::None);
				match callback_chain_id.get_chain_id() {
					Ok(Some(chain_id)) => Ok(json!(format!("0x{:x}", chain_id))),
					Ok(None) => Ok(Value::Null),
					Err(_) => Err(jsonrpc_core::Error::internal_error())
				}
			});
			io.add_method("eth_getTransactionCount", move |params| {
				let values = match params {
					jsonrpc_core::Params::Array(values) => values,
					_ => panic!("expected parameters")
				};
				assert_eq!(values.len(), 1);
				let address: Address = serde_json::from_value(values[0].clone()).unwrap();
				match callback_get_transaction_count.get_nonce_for_address(&address) {
					Ok(nonce) => Ok(serde_json::to_value(nonce).unwrap()),
					Err(_) => Err(jsonrpc_core::Error::internal_error()),
				}
			});
			io.add_method("eth_gasPrice", move |params| {
				assert_eq!(params, jsonrpc_core::Params::None);
				match callback_gas_price.get_gas_price() {
					Ok(gas_price) => Ok(serde_json::to_value(gas_price).unwrap()),
					Err(_) => Err(jsonrpc_core::Error::internal_error()),
				}
			});
			io.add_method("eth_getTransactionByHash", move |params| {
				let values = match params {
					jsonrpc_core::Params::Array(values) => values,
					_ => panic!("expected parameters")
				};
				assert_eq!(values.len(), 1);
				let hash: H256 = serde_json::from_value(values[0].clone()).unwrap();
				// if callback returns specific errors, we treat as transaction not found or transaction pending
				match callback_get_transaction_by_hash.get_transaction_by_hash(&hash, Duration::from_secs(30)) {
					Ok(raw) => Ok(serde_json::to_value(Self::transaction_by_hash_from_raw(hash, raw)).unwrap()),
					// Err("not found".into()) => Value::Null,
					Err(e) => if e == "not found".to_string() {
						Ok(Value::Null)
					}else if e == "pending".to_string() {
						Ok(serde_json::to_value(Self::transaction_by_hash_pending(hash)).unwrap())
					}else{
						Err(jsonrpc_core::Error::internal_error())
					}
				}
			});
			io.add_method("eth_sendRawTransaction", move |params| {
				let values = match params {
					jsonrpc_core::Params::Array(values) => values,
					_ => panic!("expected parameters")
				};
				assert_eq!(values.len(), 1);
				let raw_as_str: String = serde_json::from_value(values[0].clone()).unwrap();
				let raw: Vec<u8> = raw_as_str[2..].from_hex().unwrap();
				match callback_send_raw_transaction.submit_transaction(raw) {
					Ok(hash) => Ok(serde_json::to_value(hash).unwrap()),
					Err(_) => Err(jsonrpc_core::Error::internal_error()),
				}
			});
			io.add_method("eth_estimateGas", move |params| {
				#[derive(Deserialize)]
				struct Args {
					pub from: Address,
					pub to: Option<Address>,
					pub gas: Option<U256>,
					#[serde(rename="gasPrice")]
					pub gas_price: Option<U256>,
					pub value: Option<U256>,
					pub data: Option<String>,
				}
				let values = match params {
					jsonrpc_core::Params::Array(values) => values,
					_ => panic!("expected parameters")
				};
				assert_eq!(values.len(), 1);
				let args: Args = serde_json::from_value(values[0].clone()).unwrap();
				let estimate_gas_args = EstimateGasArgs {
					from: args.from,
					to: args.to,
					gas: args.gas,
					gas_price: args.gas_price,
					value: args.value,
					data: args.data.map(|data| data[2..].from_hex().unwrap())
				};
				match callback_estimage_gas.estimate_gas(estimate_gas_args) {
					Ok(gas) => Ok(serde_json::to_value(gas).unwrap()),
					Err(_) => Err(jsonrpc_core::Error::internal_error()),
				}
			});
			let address: SocketAddr = format!("127.0.0.1:{}", port).parse().map_err(|err: AddrParseError| err.to_string())?;
			let server = ServerBuilder::new(io)
				.cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Null]))
				.start_http(&address).map_err(|err| err.to_string())?;
			let close_handle = server.close_handle();
			runtime.executor().spawn(
				future::ok(())
					.map(move |_| server.wait())
			);
			Ok(EthServerMock {
				close_handle
			})
		}

		pub fn shutdown(self) {
			drop(self)
		}

		fn transaction_by_hash_pending(hash: H256) -> TransactionByHash {
			TransactionByHash {
				hash,
				nonce: U256::zero(),
				block_hash: None,
				block_number: None,
				transaction_index: Some(U256([0,0,0,0])),
				from: Address::default(),
				to: Some(Address::default()),
				value: U256::zero(),
				gas_price: U256::zero(),
				gas: U256::zero(),
				input: "0x".to_string(),
				v: U256::zero(),
				standard_v: "0x0".to_string(),
				r: U256::zero(),
				raw: "0x".to_string(),
				public_key: Public::default(),
				chain_id: U256::zero(),
				creates: None,
				condition: None
			}
		}

		fn transaction_by_hash_from_raw(hash: H256, raw: Vec<u8>) -> TransactionByHash {
			TransactionByHash {
				hash,
				nonce: U256::zero(),
				block_hash: Some("beab0aa2411b7ab17f30a99d3cb9c6ef2fc5426d6ad6fd9e2a26a6aed1d1055b".parse().unwrap()),
				block_number: Some(U256::from_str("15df").unwrap()),
				transaction_index: Some(U256([1,0,0,0])),
				from: Address::default(),
				to: Some(Address::default()),
				value: U256::zero(),
				gas_price: U256::zero(),
				gas: U256::zero(),
				input: "0x".to_string(),
				v: U256::zero(),
				standard_v: "0x0".to_string(),
				r: U256::zero(),
				raw: format!("0x{}",raw.to_hex()),
				public_key: Public::default(),
				chain_id: U256::zero(),
				creates: None,
				condition: None
			}
		}
	}

	impl Drop for EthServerMock {
		fn drop(&mut self) {
			let close_handle = self.close_handle.clone();
			close_handle.close()
		}
	}

	#[test]
	fn server_mock_sanity_test() {
		struct Callback {}
		impl EthClient for Callback {
			fn get_nonce_for_address(&self, _address: &Address) -> Result<U256, String> {
				Ok(U256([10,10,0,0]))
			}

			fn get_gas_price(&self) -> Result<U256, String> {
				Ok(U256([10000,0,0,0]))
			}

			fn get_chain_id(&self) -> Result<Option<u64>, String> {
				Ok(Some(1))
			}

			fn get_transaction_by_hash(&self, _hash: &H256, _timeout: Duration) -> Result<Vec<u8>, String> {
				Ok(vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
			}

			fn submit_transaction(&self, _raw: Vec<u8>) -> Result<H256, String> {
				Ok("c6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b".parse().unwrap())
			}

			fn estimate_gas(&self, _args: EstimateGasArgs) -> Result<U256, String> {
				Ok(U256::from(199050))
			}
		}

		let runtime = Runtime::with_thread_count(2);
		let callback = Arc::new(Callback {});
		let server = EthServerMock::start(&runtime, callback.clone(), 8545).unwrap();

		let client = EthRpcClient::new(runtime.executor(), &NodeAddress {
			address: "127.0.0.1".into(),
			port: 8545
		}).unwrap();

		assert_eq!(client.get_chain_id().unwrap(), Some(1));
		assert_eq!(client.get_nonce_for_address(&Address::default()).unwrap(), U256([10,10,0,0]));
		let hash: H256 = "c6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b".parse().unwrap();
		assert_eq!(client.get_transaction_by_hash(&hash, Duration::from_secs(10)).unwrap(), vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
		assert_eq!(client.submit_transaction(vec![]).unwrap(), hash);
		assert_eq!(
			client.estimate_gas(EstimateGasArgs {
				from: Default::default(),
				to: None,
				gas: None,
				gas_price: None,
				value: None,
				data: None
			}).unwrap(),
			U256::from(199050)
		);

		server.shutdown();
		drop(runtime);
	}

	fn decrypt(secret: &Secret, key: ProxyEncryptedDocumentKey) -> Public {
		use crypto::publickey::ec_math_utils;
		let mut c1 = key.common_point;
		let mut c2 = key.encrypted_point;
		ec_math_utils::public_mul_secret(&mut c1, secret).unwrap();
		ec_math_utils::public_sub(&mut c2, &c1).unwrap();
		c2
	}

	#[test]
	#[cfg_attr(feature = "ci", ignore = "CI cannot determine non-locking threadcount")]
	fn shadow_decryption_with_payload_works_for_3_nodes() {
		// let _ = ::env_logger::Builder::from_default_env()
		// 	.filter_level(log::LevelFilter::Debug)
		// 	.init();
		// let _ = ::env_logger::try_init();

		struct AclCallback {
			whitelist: BTreeSet<(Address,ServerKeyId, Vec<U256>)>
		}

		impl AclStorage for AclCallback {
			fn check(&self, _requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
				if document == &*JOINT_SIGNATURE_KEY_ID {
					Ok(true)
				}else{
					panic!("check should not be called");
				}
			}

			fn check_with_payload(&self, requester: Address, document: &ServerKeyId, authorization_payload: &Vec<U256>) -> Result<bool, Error> {
				let in_whitelist = self.whitelist.contains(&(requester, document.clone(), authorization_payload.clone()));
				Ok(in_whitelist)
			}
		}

		impl AclCallback {
			pub fn new() -> AclCallback {
				AclCallback {
					whitelist: BTreeSet::new()
				}
			}

			pub fn whitelist(&mut self, requester: Requester, document: ServerKeyId, payload: Vec<U256>) {
				self.whitelist.insert((requester.address(&document).unwrap(), document, payload));
			}
		}

		let callbacks: Vec<Arc<Mutex<AclCallback>>> = (0..3).map(|_| Arc::new(Mutex::new(AclCallback::new()))).collect();
		let acl_storages = callbacks.iter().map(|x| x.clone() as Arc<Mutex<dyn AclStorage>>).collect();
		let contract_address = ContractAddress::Address(H160([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]));
		let runtime = Runtime::with_default_thread_count();

		let rpc_server = EthServerMock::start(&runtime, Arc::new(DummyEthClient::new()), 9003).unwrap();

		let key_servers = start_key_servers(acl_storages, contract_address, &runtime, 9000, 9003, None);

		let master_server = &key_servers[0];
		let another_server = &key_servers[1];

		// generate a key first
		let document_id = ServerKeyId::default();
		let alice = gen_key_pair();
		let bob = gen_key_pair();
		let generation_result = another_server.generate_document_key(document_id.clone(), Requester::Public(alice.public().clone()), 2)
			.wait();
		let encrypted_document_key = generation_result.unwrap();
		let document_key = crypto::publickey::ecies::decrypt(&alice.secret(), &DEFAULT_MAC, &encrypted_document_key).unwrap();
		let document_key = Public::from_slice(&document_key);

		// signing key not yet generated
		{
			let payload = vec![U256([1,2,3,4])];
			let shadow_decryption_result = master_server.restore_document_key_shadow_payload(document_id.clone(), Requester::Public(bob.public().clone()), payload).wait();
			// master errors
			assert_eq!(shadow_decryption_result, Err(Error::SigningKeyIsNotFound));

			// generate signing key
			let _ = master_server.generate_joint_signature_key().wait().unwrap();
		}

		// make first access attempt
		{
			let payload = vec![U256([1,2,3,4])];
			let shadow_decryption_result = master_server.restore_document_key_shadow_payload(document_id.clone(), Requester::Public(bob.public().clone()), payload).wait();
			// all nodes rejected
			assert_eq!(shadow_decryption_result, Err(Error::ConsensusUnreachable));
		}

		let whitelisted_payload = vec![U256([0,0,0,0]), U256([0,1,0,1])];
		let whitelisted_requester = Requester::Public(bob.public().clone());
		// whitelist at 2 servers
		{
			let mut guard = callbacks[0].lock().unwrap();
			guard.whitelist(whitelisted_requester.clone(), document_id.clone(), whitelisted_payload.clone());
		}
		{
			let mut guard = callbacks[1].lock().unwrap();
			guard.whitelist(whitelisted_requester.clone(), document_id.clone(), whitelisted_payload.clone());
		}

		// make second access attempt (2 out of 3 agree -> not enough for t=2)
		{
			let shadow_decryption_result = master_server.restore_document_key_shadow_payload(document_id.clone(), whitelisted_requester.clone(), whitelisted_payload.clone()).wait();
			// rejected
			assert_eq!(shadow_decryption_result, Err(Error::ConsensusUnreachable));
		}

		// whitelist at the last server
		{
			let mut guard = callbacks[2].lock().unwrap();
			guard.whitelist(whitelisted_requester.clone(), document_id.clone(), whitelisted_payload.clone());
		}

		let proxy_encryption_result = master_server.restore_document_key_shadow_payload(document_id, whitelisted_requester, whitelisted_payload).wait();
		let decrypted_document_key = decrypt(bob.secret(), proxy_encryption_result.unwrap());
		assert_eq!(document_key, decrypted_document_key);

		rpc_server.shutdown();
	}

	#[test]
	#[cfg_attr(feature = "ci", ignore = "CI cannot determine non-locking threadcount")]
	fn shadow_decryption_passes_correct_payload() {
		// let _ = ::env_logger::Builder::from_default_env()
		// 	.filter_level(log::LevelFilter::Debug)
		// 	.init();

		struct AclStorageMock {
			pub presented_data: Mutex<Option<(Address, ServerKeyId, Vec<U256>)>>,
		}

		impl AclStorage for AclStorageMock {
			fn check(&self, _requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
				if document == &*JOINT_SIGNATURE_KEY_ID {
					Ok(true)
				}else{
					panic!("check should not be called");
				}
			}

			fn check_with_payload(&self, requester: Address, document: &ServerKeyId, authorization_payload: &Vec<U256>) -> Result<bool, Error> {
				let mut data = self.presented_data.lock().unwrap();
				*data = Some((requester, document.clone(), authorization_payload.clone()));
				return Ok(true);
			}
		}

		let user = gen_key_pair();
		let document: ServerKeyId = ServerKeyId::from(&gen_key_pair().secret().0);
		let empty_payload = vec![];
		let payload: Vec<U256> = vec![U256::from(&gen_key_pair().secret().0), U256::from(&gen_key_pair().secret().0), U256::from(&gen_key_pair().secret().0)];

		let acl_storage = Arc::new(Mutex::new(AclStorageMock {
			presented_data: Mutex::new(None)
		}));

		let contract_address = ContractAddress::Address(H160([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]));
		let runtime = Runtime::with_default_thread_count();
		let rpc_server = EthServerMock::start(&runtime, Arc::new(DummyEthClient::new()), 9007).unwrap();
		let key_servers = start_key_servers(vec![acl_storage.clone(), acl_storage.clone(), acl_storage.clone()], contract_address, &runtime, 9004, 9007, None);

		// generate signing key
		let _ = key_servers[0].generate_joint_signature_key().wait().unwrap();

		// first generate a key
		key_servers[0].generate_document_key(document.clone(), Requester::Public(user.public().clone()), 2).wait().unwrap();

		// then access key
		key_servers[1].restore_document_key_shadow_payload(document.clone(), Requester::Public(user.public().clone()), empty_payload.clone()).wait().unwrap();

		{
			let acl_storage = acl_storage.lock().unwrap();
			let data = acl_storage.presented_data.lock().unwrap();
			let (actual_user, actual_document, actual_payload) = data.as_ref().unwrap();
			assert_eq!(&user.address(), actual_user);
			assert_eq!(&document, actual_document);
			assert_eq!(&empty_payload, actual_payload)
		}

		// expect different payload
		key_servers[2].restore_document_key_shadow_payload(document.clone(), Requester::Public(user.public().clone()), payload.clone()).wait().unwrap();
		{
			let acl_storage = acl_storage.lock().unwrap();
			let data = acl_storage.presented_data.lock().unwrap();
			let (actual_user, actual_document, actual_payload) = data.as_ref().unwrap();
			assert_eq!(&user.address(), actual_user);
			assert_eq!(&document, actual_document);
			assert_eq!(&payload, actual_payload)
		}

		rpc_server.shutdown()
	}

	use_contract!(log_contract, "res/acl_log.json");

	fn assert_correct_log_transaction(expected_nonce: U256, expected_gas_price: U256, chain_id: u64, contract_address: &Address, document_id: &ServerKeyId, user: &Address, payload: &Vec<U256>, signing_public: &Public, transaction: &Vec<u8>) {
		// decode transaction
		let rlp = Rlp::new(&transaction);
		assert!(rlp.is_list());
		assert_eq!(rlp.item_count().unwrap(), 9);
		let nonce: U256 = rlp.val_at(0).unwrap();
		assert_eq!(nonce, expected_nonce);
		let gas_price: U256 = rlp.val_at(1).unwrap();
		assert_eq!(gas_price, expected_gas_price);
		let gas: U256 = rlp.val_at(2).unwrap();
		//TODO check that gas limit should be bigger than the expected cost of the log call
		let to: Address = rlp.val_at(3).unwrap();
		assert_eq!(&to, contract_address);
		// for a log contract call, no money is sent
		let value: U256 = rlp.val_at(4).unwrap();
		assert_eq!(value, U256::zero());
		let data: Vec<u8> = rlp.val_at(5).unwrap();

		let (expected_data, _) = log_contract::functions::log_access::call(user.clone(), document_id.clone(), payload.clone());
		assert_eq!(data, expected_data);

		let v: u64 = rlp.val_at::<u64>(6).unwrap() - chain_id * 2 - 35;
		let r: H256 = rlp.val_at(7).unwrap();
		let s: H256 = rlp.val_at(8).unwrap();

		let tx_hash = RawTransaction {
			nonce,
			to: Some(to),
			value,
			gas_price,
			gas,
			data,
			chain_id
		}.hash();

		let signature = Signature::from_rsv(&r, &s, v as u8);
		// verify signature
		assert!(parity_crypto::publickey::verify_public(signing_public, &signature, &tx_hash).unwrap());
	}

	#[test]
	#[cfg_attr(feature = "ci", ignore = "CI cannot determine non-locking threadcount")]
	fn shadow_decryption_correctly_submits_log_transaction() {

		struct AclStorageMock {
			pub accept: Mutex<bool>,
		}

		impl AclStorage for AclStorageMock {
			fn check(&self, _requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
				if document == &*JOINT_SIGNATURE_KEY_ID {
					Ok(true)
				}else{
					panic!("check should not be called");
				}
			}

			fn check_with_payload(&self, _requester: Address, _document: &ServerKeyId, _authorization_payload: &Vec<U256>) -> Result<bool, Error> {
				Ok(*self.accept.lock().unwrap())
			}
		}


		let user = gen_key_pair();
		let document: ServerKeyId = ServerKeyId::from(&gen_key_pair().secret().0);
		let empty_payload = vec![];
		let payload: Vec<U256> = vec![U256::from(&gen_key_pair().secret().0), U256::from(&gen_key_pair().secret().0), U256::from(&gen_key_pair().secret().0)];

		let acl_storage = Arc::new(Mutex::new(AclStorageMock {
			accept: Mutex::new(false)
		}));

		let contract_address: Address = H160([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
		let runtime = Runtime::with_default_thread_count(); // cannot determine non-locking threadcount in CI environment
		let eth_client = Arc::new(DummyEthClient::new());
		let rpc_server = EthServerMock::start(&runtime, eth_client.clone(), 9011).unwrap();
		let key_servers = start_key_servers(vec![acl_storage.clone(), acl_storage.clone(), acl_storage.clone()], ContractAddress::Address(contract_address.clone()), &runtime, 9008, 9011, None);

		// generate signing key
		let signing_public = key_servers[0].generate_joint_signature_key().wait().unwrap();
		let signing_address = parity_crypto::publickey::public_to_address(&signing_public);
		// first generate a key
		key_servers[0].generate_document_key(document.clone(), Requester::Public(user.public().clone()), 2).wait().unwrap();


		let nonce1 = eth_client.get_nonce_for_address(&signing_address).unwrap();
		let gas_price = eth_client.get_gas_price().unwrap();
		let chain_id = eth_client.get_chain_id().unwrap().unwrap();

		// then access key (all nodes deny access)
		let result = key_servers[1].restore_document_key_shadow_payload(document.clone(), Requester::Public(user.public().clone()), empty_payload.clone()).wait();
		assert_eq!(result, Err(Error::ConsensusUnreachable));
		// expect a log transaction
		{
			let transactions = eth_client.transactions();
			assert_eq!(transactions.len(), 1);
			let transactions_by_signature_key = transactions.get(&signing_address).unwrap();
			assert_eq!(transactions_by_signature_key.len(), 1);
			let (_, log_tx) = transactions_by_signature_key[0].clone();
			assert_correct_log_transaction(nonce1, gas_price, chain_id, &contract_address, &document, &user.address(), &empty_payload, &signing_public, &log_tx);
		}

		// now allow access
		{
			let acl_mutex = acl_storage.lock().unwrap();
			let mut accept = acl_mutex.accept.lock().unwrap();
			*accept = true;
		}

		let nonce2 = eth_client.get_nonce_for_address(&signing_address).unwrap();


		// try a different payload
		key_servers[2].restore_document_key_shadow_payload(document.clone(), Requester::Public(user.public().clone()), payload.clone()).wait().unwrap();
		{
			// we accept a second transaction
			let transactions = eth_client.transactions();
			// println!("state after 2: {:?}", transactions);
			assert_eq!(transactions.len(), 1);
			let transactions_by_signature_key = transactions.get(&signing_address).unwrap();
			assert_eq!(transactions_by_signature_key.len(), 2);
			let (_, log_tx) = transactions_by_signature_key[1].clone();
			assert_correct_log_transaction(nonce2, gas_price, chain_id, &contract_address, &document, &user.address(), &payload, &signing_public, &log_tx);
		}

		rpc_server.shutdown()
	}

	fn run<F,R,E>(executor: &Executor, f: F) -> Result<R,E> where F: Future<Item=R, Error=E> + Send + 'static, R: Send + 'static, E: Send + 'static {
		let (sender, receiver) = oneshot::channel();
		let f = f
			.then(|future_result| {
				let _ = sender.send(future_result);
				futures::finished(())
			});
		executor.spawn(f);
		match receiver.wait() {
			Ok(future_result) => future_result,
			Err(err) => panic!("cancelled: {}", err),
		}
	}

	fn generate_keypair_http(executor: &Executor, port: u16, document_id: &ServerKeyId, signature: &Signature, threshold: u32) -> Public {
		let response = hyper::Client::new()
			.request(Request::builder()
				.method("POST")
				.uri(format!("http://127.0.0.1:{}/shadow/{:x}/{}/{}", port, document_id, signature.to_vec().to_hex(), threshold))
				.body(Body::empty())
				.unwrap()
			);
		let response = run(executor, response).unwrap();
		let status = response.status();
		let bytes = response.into_body().collect().wait().unwrap();
		let bytes = bytes.into_iter().map(|chunk| chunk.into_iter()).flatten().collect();
		let str = String::from_utf8(bytes).unwrap();
		println!("generate_keypair returned: {}", str);
		assert!(status.is_success());
		str[3..str.len()-1].parse().unwrap()

	}

	fn generate_joint_signature_key(executor: &Executor, port: u16) {
		let response = hyper::Client::new()
			.request(Request::builder()
				.method("POST")
				.uri(format!("http://127.0.0.1:{}/joint_signature_key", port))
				.body(Body::empty())
				.unwrap()
			);
		let response = run(executor, response).unwrap();
		let status = response.status();
		let bytes = response.into_body().collect().wait().unwrap();
		let bytes = bytes.into_iter().map(|chunk| chunk.into_iter()).flatten().collect();
		println!("generate_joint_signature_key returned: {}", String::from_utf8(bytes).unwrap());
		assert!(status.is_success());
	}

	fn store_encrypted_document_key(executor: &Executor, port: u16, document_id: &ServerKeyId, signature: &Signature, common_point: &Public, encrypted_point: &Public) {
		let response = hyper::Client::new()
			.request(Request::builder()
				.method("POST")
				.uri(format!("http://127.0.0.1:{}/shadow/{:x}/{}/{:x}/{:x}", port, document_id, signature.to_vec().to_hex(), common_point, encrypted_point))
				.body(Body::empty())
				.unwrap()
			);
		let response = run(executor, response).unwrap();
		let status = response.status();
		let bytes = response.into_body().collect().wait().unwrap();
		let bytes = bytes.into_iter().map(|chunk| chunk.into_iter()).flatten().collect();
		let str = String::from_utf8(bytes).unwrap();
		println!("store_encrypted_document_key returned: {}", str);
		assert!(status.is_success());
	}

	fn restore_document_key_shadow_payload(executor: &Executor, port: u16, document_id: &ServerKeyId, signature: &Signature, payload: &Vec<U256>) {
		let json_body = serde_json::to_string(payload).unwrap();
		let response = hyper::Client::new()
			.request(Request::builder()
				.method("POST")
				.uri(format!("http://127.0.0.1:{}/shadow/{:x}/{}", port, document_id, signature.to_vec().to_hex()))
				.body(Body::from(json_body))
				.unwrap()
			);
		let response = run(executor, response).unwrap();
		let status = response.status();
		let bytes = response.into_body().collect().wait().unwrap();
		let bytes = bytes.into_iter().map(|chunk| chunk.into_iter()).flatten().collect();
		println!("restore_document_key_shadow_payload returned: {}", String::from_utf8(bytes).unwrap());
		assert!(status.is_success());
	}

	#[test]
	#[cfg_attr(feature = "ci", ignore = "CI cannot determine non-locking threadcount")]
	fn shadow_decryption_with_payload_works_for_3_nodes_over_http() {
		// let _ = ::env_logger::Builder::from_default_env()
		// 	.filter_level(log::LevelFilter::Debug)
		// 	.init();
		// let _ = ::env_logger::try_init();

		struct AclCallback {
			whitelist: BTreeSet<(Address,ServerKeyId, Vec<U256>)>
		}

		impl AclStorage for AclCallback {
			fn check(&self, _requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
				if document == &*JOINT_SIGNATURE_KEY_ID {
					Ok(true)
				}else{
					panic!("check should not be called");
				}
			}

			fn check_with_payload(&self, requester: Address, document: &ServerKeyId, authorization_payload: &Vec<U256>) -> Result<bool, Error> {
				let in_whitelist = self.whitelist.contains(&(requester, document.clone(), authorization_payload.clone()));
				Ok(in_whitelist)
			}
		}

		impl AclCallback {
			pub fn new() -> AclCallback {
				AclCallback {
					whitelist: BTreeSet::new()
				}
			}

			pub fn whitelist(&mut self, requester: Requester, document: ServerKeyId, payload: Vec<U256>) {
				self.whitelist.insert((requester.address(&document).unwrap(), document, payload));
			}
		}

		let callbacks: Vec<Arc<Mutex<AclCallback>>> = (0..3).map(|_| Arc::new(Mutex::new(AclCallback::new()))).collect();
		let acl_storages = callbacks.iter().map(|x| x.clone() as Arc<Mutex<dyn AclStorage>>).collect();
		let contract_address = ContractAddress::Address(H160([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]));
		let runtime = Runtime::with_default_thread_count();
		let executor = runtime.executor();
		let rpc_server = EthServerMock::start(&runtime, Arc::new(DummyEthClient::new()), 9015).unwrap();

		let _key_servers = start_key_servers(acl_storages, contract_address, &runtime, 9012, 9015, Some(9016));

		// generate a key first
		let document_id: ServerKeyId = "d587ff44457dcc1cb3cf4a77fcb95f979c8a0218fa79bdac5790c6dbab1f0b70".parse().unwrap();
		let alice = gen_key_pair();
		let bob = gen_key_pair();
		let signature = parity_crypto::publickey::sign(alice.secret(), &document_id).unwrap();
		let server_key_public = generate_keypair_http(&executor, 9016, &document_id, &signature, 2);
		let document_key = Random.generate().public().clone();
		let encrypted_document_key = math::encrypt_secret(&document_key, &server_key_public).unwrap();
		store_encrypted_document_key(&executor, 9016, &document_id, &signature, &encrypted_document_key.common_point, &encrypted_document_key.encrypted_point);

		// generate signing key
		generate_joint_signature_key(&executor, 9016);

		let whitelisted_payload = vec![U256([0,0,0,0]), U256([0,1,0,1])];
		let whitelisted_requester = Requester::Public(bob.public().clone());
		// whitelist at 3 servers
		{
			let mut guard = callbacks[0].lock().unwrap();
			guard.whitelist(whitelisted_requester.clone(), document_id.clone(), whitelisted_payload.clone());
		}
		{
			let mut guard = callbacks[1].lock().unwrap();
			guard.whitelist(whitelisted_requester.clone(), document_id.clone(), whitelisted_payload.clone());
		}
		{
			let mut guard = callbacks[2].lock().unwrap();
			guard.whitelist(whitelisted_requester.clone(), document_id.clone(), whitelisted_payload.clone());
		}

		let bob_signature = parity_crypto::publickey::sign(bob.secret(), &document_id).unwrap();
		restore_document_key_shadow_payload(&executor, 9016, &document_id, &bob_signature, &whitelisted_payload);

		rpc_server.shutdown();
	}

}
