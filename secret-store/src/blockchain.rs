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
use bytes::{Bytes, ToPretty};
use ethereum_types::{H256, Address, Public, U256};
use ethabi::RawLog;
use crypto::publickey::{Signature, Error as EthKeyError};
use std::{time, thread};
use std::time::Duration;
use ::{NodeAddress, Error};
use jsonrpc_core_client::{transports, TypedClient};
use futures::Future;
use futures::sync::oneshot;
use rustc_hex::{FromHex};
#[cfg(test)]
use {
	parking_lot::Mutex,
	std::collections::HashMap,
	rlp::Rlp,
	transaction_signature::RawTransaction
};
use parity_runtime::Executor;

/// Type for block number.
/// Duplicated from ethcore types
pub type BlockNumber = u64;

/// Uniquely identifies block.
/// Duplicated from ethcore types
#[derive(Debug, PartialEq, Copy, Clone, Hash, Eq)]
pub enum BlockId {
	/// Block's sha3.
	/// Querying by hash is always faster.
	Hash(H256),
	/// Block number within canon blockchain.
	Number(BlockNumber),
	/// Earliest block (genesis).
	Earliest,
	/// Latest mined block.
	Latest,
}

/// Contract address.
#[derive(Debug, Clone)]
pub enum ContractAddress {
	/// Address is read from registry.
	Registry,
	/// Address is specified.
	Address(ethereum_types::Address),
}

/// Key pair with signing ability.
pub trait SigningKeyPair: Send + Sync {
	/// Public portion of key.
	fn public(&self) -> &Public;
	/// Address of key owner.
	fn address(&self) -> Address;
	/// Sign data with the key.
	fn sign(&self, data: &H256) -> Result<Signature, EthKeyError>;
}

/// Wrapps client ChainNotify in order to send signal about new blocks
pub trait NewBlocksNotify: Send + Sync {
	/// Fires when chain has new blocks.
	/// Sends this signal only, if contracts' update required
	fn new_blocks(&self, _new_enacted_len: usize) {
		// does nothing by default
	}
}

/// Blockchain logs Filter.
#[derive(Debug, PartialEq)]
pub struct Filter {
	/// Blockchain will be searched from this block.
	pub from_block: BlockId,

	/// Search addresses.
	///
	/// If None, match all.
	/// If specified, log must be produced by one of these addresses.
	pub address: Option<Vec<Address>>,

	/// Search topics.
	///
	/// If None, match all.
	/// If specified, log must contain one of these topics.
	pub topics: Vec<Option<Vec<H256>>>,
}

/// Blockchain representation for Secret Store
pub trait SecretStoreChain: Send + Sync + 'static {
	/// Adds listener for chain's NewBlocks event
	fn add_listener(&self, target: Arc<dyn NewBlocksNotify>);

	/// Check if the underlying chain is in the trusted state
	fn is_trusted(&self) -> bool;

	/// Transact contract.
	fn transact_contract(&self, contract: Address, tx_data: Bytes) -> Result<(), EthKeyError>;

	/// Read contract address. If address source is registry, address only returned if current client state is
	/// trusted. Address from registry is read from registry from block latest block with
	/// REQUEST_CONFIRMATIONS_REQUIRED confirmations.
	fn read_contract_address(&self, registry_name: &str, address: &ContractAddress) -> Option<Address>;

	/// Call contract in the blockchain
	fn call_contract(&self, block_id: BlockId, contract_address: Address, data: Bytes) -> Result<Bytes, String>;

	/// Returns blockhash for block id
	fn block_hash(&self, id: BlockId) -> Option<H256>;

	/// Returns block number for block id
	fn block_number(&self, id: BlockId) -> Option<BlockNumber>;

	/// Retrieve last blockchain logs for the filter
	fn retrieve_last_logs(&self, filter: Filter) -> Option<Vec<RawLog>>;

	/// Get hash of the last block with predefined number of confirmations (depends on the chain).
	fn get_confirmed_block_hash(&self) -> Option<H256>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EstimateGasArgs {
	pub from: Address,
	pub to: Option<Address>,
	pub gas: Option<U256>,
	#[serde(rename="gasPrice")]
	pub gas_price: Option<U256>,
	pub value: Option<U256>,
	pub data: Option<Vec<u8>>,
}

pub trait EthClient: Send + Sync {
	fn get_nonce_for_address(&self, address: &Address) -> Result<U256, String>;

	fn get_gas_price(&self) -> Result<U256, String>;

	fn get_chain_id(&self) -> Result<Option<u64>, String>;

	/// this function blocks until the transaction specified by `hash` is confirmed.
	/// this function blocks for at most `timeout` time
	fn get_transaction_by_hash(&self, hash: &H256, timeout: time::Duration) -> Result<Vec<u8>, String>;

	/// submits encoded transaction `raw` and returns the transaction hash
	fn submit_transaction(&self, raw: Vec<u8>) -> Result<H256, String>;

	fn estimate_gas(&self, args: EstimateGasArgs) -> Result<U256, String>;
}

pub struct EthRpcClient {
	executor: Executor,
	address: String
}

impl EthRpcClient {

	pub fn new(executor: Executor, rpc_over_http_address: &NodeAddress) -> Result<Self, Error> {
		let rpc_client = EthRpcClient {
			executor: executor.clone(),
			address: format!("http://{}:{}", rpc_over_http_address.address, rpc_over_http_address.port)
		};
		let (sender, receiver) = oneshot::channel();
		executor.spawn(
				rpc_client.client()
					.then(|client| {
						let _ = sender.send(client.map(|_| () ));
						futures::finished(())
					})
		);
		let connected = match receiver.wait() {
			Ok(future_result) => future_result,
			Err(err) => Err(Error::Internal(err.to_string()))
		};
		connected.map(|_| rpc_client)
	}

	fn client(&self) -> impl Future<Item=TypedClient, Error=Error> {
		transports::http::connect(&self.address)
			.map_err(|rpc_error| Error::Io(format!("{}", rpc_error)))
	}

	fn run<F,R>(&self, f: F) -> Result<R,Error> where F: Future<Item=R, Error=Error> + Send + 'static, R: Send + 'static {
		let (sender, receiver) = oneshot::channel();
		let f = f
			.then(|future_result| {
				let _ = sender.send(future_result);
				futures::finished(())
			});
		self.executor.spawn(f);
		match receiver.wait() {
			Ok(future_result) => future_result,
			Err(err) => Err(Error::Internal(err.to_string()))
		}
	}
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
pub struct TransactionByHash {
	pub hash: H256,
	pub nonce: U256,
	pub block_hash: Option<H256>,
	pub block_number: Option<U256>,
	pub transaction_index: Option<U256>,
	pub from: Address,
	pub to: Option<Address>,
	pub value: U256,
	pub gas_price: U256,
	pub gas: U256,
	pub input: String,
	pub v: U256,
	pub standard_v: String,
	pub r: U256,
	pub raw: String,
	pub public_key: Public,
	pub chain_id: U256,
	pub creates: Option<H256>,
	pub condition: Option<U256>
}

impl TransactionByHash {
	pub fn is_mined(&self) -> bool {
		// documentation at https://openethereum.github.io/wiki/JSONRPC-eth-module#eth_gettransactionbyhash
		// certain fields are null if the transaction is pending
		self.block_hash.is_some() && self.block_number.is_some()
	}
}

impl EthClient for EthRpcClient {

	fn get_nonce_for_address(&self, address: &Address) -> Result<U256, String> {
		let address = address.clone();
		let call = self.client()
			.and_then(move |client| {
				client.call_method("eth_getTransactionCount", "U256", vec![address])
					.map_err(|rpc_err| Error::Io(format!("eth_getTransactionCount error: {}", rpc_err)))
			});
		self.run(call).map_err(|err| err.to_string())
	}

	fn get_gas_price(&self) -> Result<U256, String> {
		let call = self.client()
			.and_then(|client| {
				client.call_method("eth_gasPrice", "U256", ())
					.map_err(|rpc_err| Error::Io(format!("eth_gasPrice error: {}", rpc_err)))
			});
		self.run(call).map_err(|err| err.to_string())
	}

	fn get_chain_id(&self) -> Result<Option<u64>, String> {
		let call = self.client()
			.and_then(|client| {
				client.call_method("eth_chainId", "Option<String>", ())
					.map_err(|rpc_err| Error::Io(format!("eth_chainId error: {}", rpc_err)))
			});
		let u64_as_str: Option<String> = self.run(call).map_err(|err| err.to_string())?;
		match u64_as_str {
			Some(u64_as_str) => u64::from_str_radix(&u64_as_str[2..], 16)
				.map(|id| Some(id))
				.map_err(|err| err.to_string()),
			None => Ok(None)
		}
	}

	fn get_transaction_by_hash(&self, hash: &H256, timeout: Duration) -> Result<Vec<u8>, String> {
		let hash = hash.clone();
		let start = time::Instant::now();
		while start.elapsed() < timeout {
			let call = self.client()
				.and_then(move |client| {
					client.call_method("eth_getTransactionByHash", "Option<TransactionByHash>", vec![hash])
						.map_err(|rpc_err| Error::Io(format!("eth_getTransactionByHash error: {}", rpc_err)))
				})
				.and_then(|tx: Option<TransactionByHash>| {
					match tx {
						Some(tx) if tx.is_mined() => futures::finished(Some(tx)),
						_ => futures::finished(None),
					}
				});
			match self.run(call) {
				Ok(Some(tx)) => return tx.raw[2..].from_hex().map_err(|hex_err| hex_err.to_string()),
				Ok(None) => {
					// transaction not yet mined / or pending on current node
					thread::sleep(Duration::from_millis(100))
				},
				Err(error) => return Err(error.to_string())
			}
		}
		Err("transaction not found within timeout".into())
	}

	fn submit_transaction(&self, raw: Vec<u8>) -> Result<H256, String> {
		let call = self.client()
			.and_then(move |client| {
				let raw_hex = format!("0x{}", raw.to_hex());
				client.call_method("eth_sendRawTransaction", "H256", vec![raw_hex])
					.map_err(|rpc_err| Error::Io(format!("eth_sendRawTransaction error: {}", rpc_err)))
			});
		self.run(call).map_err(|err| err.to_string())
	}

	fn estimate_gas(&self, args: EstimateGasArgs) -> Result<U256, String> {
		#[derive(Serialize)]
		struct Args {
			from: Address,
			to: Option<Address>,
			gas: Option<U256>,
			#[serde(rename="gasPrice")]
			gas_price: Option<U256>,
			value: Option<U256>,
			data: Option<String>,
		}
		let tx_args = Args {
			from: args.from,
			to: args.to,
			gas: args.gas,
			gas_price: args.gas_price,
			value: args.value,
			data: args.data.map(|data| format!("0x{}", data.to_hex()))
		};
		let call = self.client()
			.and_then(move |client| {
				client.call_method("eth_estimateGas", "U256", vec![tx_args])
					.map_err(|rpc_err| Error::Io(format!("eth_estimateGas error: {}", rpc_err)))
			});
		self.run(call).map_err(|err| err.to_string())
	}
}

#[cfg(test)]
pub struct DummyEthClient {
	transactions: Mutex<HashMap<Address, Vec<(H256,Vec<u8>)>>>,
	gas_price: U256,
	chain_id: Option<u64>
}

#[cfg(test)]
impl DummyEthClient {
	pub fn new() -> Self {
		Self::new_with(U256::zero(), Some(1234))
	}

	pub fn new_with(gas_price: U256, chain_id: Option<u64>) -> Self {
		DummyEthClient {
			transactions: Mutex::new(HashMap::new()),
			gas_price,
			chain_id
		}
	}

	pub fn transactions(&self) -> HashMap<Address, Vec<(H256, Vec<u8>)>> {
		self.transactions.lock().clone()
	}
}

#[cfg(test)]
impl EthClient for DummyEthClient {
	fn get_nonce_for_address(&self, address: &Address) -> Result<U256, String> {
		let transactions = self.transactions.lock();
		Ok(transactions.get(address).map(|tx_by_address| U256([tx_by_address.len() as u64, 0,0,0])).unwrap_or(U256::zero()))
	}

	fn get_gas_price(&self) -> Result<U256, String> {
		Ok(self.gas_price.clone())
	}

	fn get_chain_id(&self) -> Result<Option<u64>, String> {
		Ok(self.chain_id.clone())
	}

	fn get_transaction_by_hash(&self, hash: &H256, timeout: Duration) -> Result<Vec<u8>, String> {
		let start = std::time::Instant::now();
		while start.elapsed() < timeout {
			let found_tx = {
				let transactions = self.transactions.lock();
				transactions.iter().map(|(_, tx_by_address)| tx_by_address.iter())
					.flatten()
					.find(|(tx_hash, _)| tx_hash == hash)
					.map(|(_, raw)| raw.clone())
				// unlock transactions
			};
			match found_tx {
				Some(tx) => return Ok(tx),
				None => std::thread::sleep(Duration::from_millis(100))
			}
		}
		Err(format!("dummy client: transaction {:x} not found within timeout", hash))
	}

	fn submit_transaction(&self, raw: Vec<u8>) -> Result<H256, String> {
		fn read_h256_without_leading_zeros(rlp: &Rlp, index: usize) -> H256 {
			let mut bytes: Vec<u8> = rlp.val_at(index).unwrap();
			let append_zeros = 32-bytes.len();
			for _ in 0..append_zeros {
				bytes.insert(0, 0u8);
			}
			assert_eq!(bytes.len(),32);
			H256::from_slice(&bytes)
		}
		// dummy doesn't validate anything but structure
		let rlp = Rlp::new(&raw);
		assert!(rlp.is_list());
		assert_eq!(rlp.item_count().unwrap(), 9);
		let nonce: U256 = rlp.val_at(0).unwrap();
		let gas_price: U256 = rlp.val_at(1).unwrap();
		let gas: U256 = rlp.val_at(2).unwrap();
		let to: Address = rlp.val_at(3).unwrap();
		let value: U256 = rlp.val_at(4).unwrap();
		let data: Vec<u8> = rlp.val_at(5).unwrap();
		let v: u64 = rlp.val_at::<u64>(6).unwrap() - self.chain_id.unwrap() * 2 - 35;
		let r: H256 = read_h256_without_leading_zeros(&rlp, 7);
		let s: H256 = read_h256_without_leading_zeros(&rlp, 8);

		let tx = RawTransaction {
			nonce,
			to: Some(to),
			value,
			gas_price,
			gas,
			data,
			chain_id: self.chain_id.unwrap()
		};

		let signature = Signature::from_rsv(&r, &s, v as u8);
		let sender = parity_crypto::publickey::recover(&signature, &tx.hash()).map_err(|_| "mock: cannot recover sender key".to_string())?;
		let sender_address = parity_crypto::publickey::public_to_address(&sender);

		let tx_hash = tx.hash_with_signature(&signature);

		let mut transactions = self.transactions.lock();
		let vec = match transactions.get_mut(&sender_address) {
			Some(vec) => vec,
			None => {
				transactions.insert(sender_address.clone(), Vec::new());
				transactions.get_mut(&sender_address).unwrap()
			}
		};
		vec.push((tx_hash.clone(), raw));
		Ok(tx_hash)
	}

	fn estimate_gas(&self, _args: EstimateGasArgs) -> Result<U256, String> {
		Ok(U256::zero())
	}
}

#[cfg(test)]
mod test {
	use crypto::publickey::{Random, Generator};
	use blockchain::{EthRpcClient, EthClient, DummyEthClient};
	use ethereum_types::{Address, U256, H256};
	use NodeAddress;
	use std::str::FromStr;
	use std::time::Duration;
	use rlp::RlpStream;
	use parity_runtime::Runtime;
	use rustc_hex::FromHex;

	#[test]
	fn test_tx_signature_encoding() {
		let tx: Vec<u8> = "f884808227108252f894000000000000000000000000000000000000000080a47f74657374320000000000000000000000000000000000000000000000000000006000572aa050060eae5858fd7662426c8f84fa939fd8e28b185317d4544d4aa2db293fae849f305c7d1ea4584cf0f5ea0c2abe9018061c56c4bb18dd198dfabaa36402f90a".from_hex().unwrap();
		let dummy = DummyEthClient::new_with(U256::from(10000), Some(3));
		dummy.submit_transaction(tx).unwrap();
	}

	#[test]
	#[cfg_attr(not(ext_eth_client), ignore = "requires external eth client running at port 8545")]
	fn returns_correct_nonce() {
		let runtime = Runtime::with_default_thread_count();
		let addr = NodeAddress {
			address: "127.0.0.1".into(),
			port: 8545,
		};
		let client = EthRpcClient::new(runtime.executor(), &addr).unwrap();
		let address = Address::from_str("1234567890123456789012345678901234567890").unwrap();
		let nonce = client.get_nonce_for_address(&address).unwrap();
		assert_eq!(nonce, U256::zero());

		drop(runtime);
	}

	#[test]
	#[cfg_attr(not(ext_eth_client), ignore = "requires external eth client running at port 8545")]
	fn returns_gas_price() {
		let runtime = Runtime::with_default_thread_count();
		let addr = NodeAddress {
			address: "127.0.0.1".into(),
			port: 8545,
		};
		let client = EthRpcClient::new(runtime.executor(), &addr).unwrap();
		client.get_gas_price().unwrap();

		drop(runtime);
	}

	#[test]
	#[cfg_attr(not(ext_eth_client), ignore = "requires external eth client running at port 8545")]
	fn returns_chain_id() {
		let runtime = Runtime::with_default_thread_count();
		let addr = NodeAddress {
			address: "127.0.0.1".into(),
			port: 8545,
		};
		let client = EthRpcClient::new(runtime.executor(), &addr).unwrap();
		client.get_chain_id().unwrap();
		drop(runtime);
	}

	#[test]
	#[cfg_attr(not(ext_eth_client), ignore = "requires external eth client running at port 8545")]
	fn timeouts_on_unknown_transaction() {
		let runtime = Runtime::with_default_thread_count();
		let addr = NodeAddress {
			address: "127.0.0.1".into(),
			port: 8545,
		};
		let client = EthRpcClient::new(runtime.executor(), &addr).unwrap();
		let hash = H256([0;32]);
		assert_eq!(client.get_transaction_by_hash(&hash, Duration::from_secs(1)), Err("transaction not found within timeout".into()));
		drop(runtime);
	}

	#[test]
	#[cfg_attr(not(ext_eth_client), ignore = "requires external eth client running at port 8545")]
	fn correctly_submits_transaction() {
		let runtime = Runtime::with_default_thread_count();
		let _ = ::env_logger::Builder::from_default_env()
			.filter_level(log::LevelFilter::Debug)
			.init();
		let addr = NodeAddress {
			address: "127.0.0.1".into(),
			port: 8545,
		};
		let client = EthRpcClient::new(runtime.executor(), &addr).unwrap();
		let gas_price = client.get_gas_price().unwrap();
		let chain_id = client.get_chain_id().unwrap();
		let address = Address::from_str("1234567890123456789012345678901234567890").unwrap();
		let data: Vec<u8> = vec![];
		// build transaction
		let mut rlp = RlpStream::new();
		rlp.begin_unbounded_list();
		rlp.append(&U256::zero()); //nonce
		rlp.append(&gas_price);
		rlp.append(&U256([21000, 0, 0, 0]));
		rlp.append(&address);
		rlp.append(&U256::zero()); // value
		rlp.append(&data);
		if let Some(chain_id) = chain_id {
			// append values for signature following EIP-155
			rlp.append(&chain_id);
			rlp.append(&U256::zero());
			rlp.append(&U256::zero());
		}
		rlp.finalize_unbounded_list();
		let encoded = rlp.out();
		let hash = H256(tiny_keccak::keccak256(&encoded));
		// sign it
		let keypair = Random.generate();
		let signature = parity_crypto::publickey::sign(keypair.secret(), &hash).unwrap();

		// assemble the signed transaction
		let mut rlp = RlpStream::new();
		rlp.begin_unbounded_list();
		rlp.append(&U256::zero()); //nonce
		rlp.append(&gas_price);
		rlp.append(&U256([21000, 0, 0, 0]));
		rlp.append(&address);
		rlp.append(&U256::zero()); // value
		rlp.append(&data);
		let r = signature.r();
		let s = signature.s();
		let v =
			if let Some(chain_id) = chain_id {
				let v = signature.v();
				// see beigepaper eq. (292)
				if v != 27 && v != 28 {
					v%2 + (2 * chain_id) as u8 + 35
				}else{
					v
				}
			}else {
				signature.v()
			};
		rlp.append(&v);
		rlp.append(&r);
		rlp.append(&s);
		rlp.finalize_unbounded_list();

		let signed_transaction = rlp.out();

		let tx_hash = client.submit_transaction(signed_transaction.clone()).unwrap();
		let mined_transaction = client.get_transaction_by_hash(&tx_hash, Duration::from_secs(30)).unwrap();
		assert_eq!(signed_transaction, mined_transaction);

		drop(runtime);
	}
}
