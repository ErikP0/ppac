use ethereum_types::{Address, U64, U256, H256};
use crate::error::Error;
use std::net::IpAddr;
use rustc_hex::ToHex;
use serde::{Serialize, Deserialize};
use serde;
#[cfg(test)]
use parity_crypto::publickey::Signature;
#[cfg(test)]
use rlp::{RlpStream, Rlp};
use web3::Web3;
use std::convert::TryInto;
use web3::types::{Bytes, TransactionId};
use log::debug;

#[derive(Clone)]
pub struct EstimateGasArgs {
    pub from: Address,
    pub to: Address,
    pub gas_price: U256,
    pub value: U256,
    pub data: Vec<u8>,
}

impl Into<web3::types::CallRequest> for EstimateGasArgs {
    fn into(self) -> web3::types::CallRequest {
        web3::types::CallRequest {
            from: Some(self.from),
            to: Some(self.to),
            gas: None,
            gas_price: Some(self.gas_price),
            value: Some(self.value),
            data: Some(web3::types::Bytes(self.data)),
        }
    }
}

#[derive(Clone)]
pub struct CallArgs {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub value: Option<U256>,
    pub data: Vec<u8>,
}

impl Into<web3::types::CallRequest> for CallArgs {
    fn into(self) -> web3::types::CallRequest {
        web3::types::CallRequest {
            from: self.from,
            to: self.to,
            gas: self.gas,
            gas_price: self.gas_price,
            value: self.value,
            data: Some(web3::types::Bytes(self.data)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    pub raw: String,
}

impl From<web3::types::Transaction> for TransactionByHash {
    fn from(t: web3::types::Transaction) -> Self {
        TransactionByHash {
            hash: t.hash,
            nonce: t.nonce,
            block_hash: t.block_hash,
            block_number: t.block_number.map(|block_number| block_number.as_u64().into()),
            transaction_index: t.transaction_index.map(|transaction_index| transaction_index.as_u64().into()),
            from: t.from,
            to: t.to,
            value: t.value,
            gas_price: t.gas_price,
            gas: t.gas,
            input: (t.input.0).to_hex(),
            raw: t.raw.map(|bytes| (bytes.0).to_hex()).unwrap_or("".to_string()),
        }
    }
}

impl TransactionByHash {
    pub fn is_mined(&self) -> bool {
        // documentation at https://openethereum.github.io/wiki/JSONRPC-eth-module#eth_gettransactionbyhash
        // certain fields are null if the transaction is pending
        self.block_hash.is_some() && self.block_number.is_some()
    }

    #[cfg(test)]
    pub fn from_raw_transaction(raw: &Vec<u8>, chain_id: &Option<u64>) -> Self {
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
        let rlp = Rlp::new(raw);
        assert!(rlp.is_list());
        assert_eq!(rlp.item_count().unwrap(), 9);
        let nonce: U256 = rlp.val_at(0).unwrap();
        let gas_price: U256 = rlp.val_at(1).unwrap();
        let gas: U256 = rlp.val_at(2).unwrap();
        let to: Address = rlp.val_at(3).unwrap();
        let value: U256 = rlp.val_at(4).unwrap();
        let data: Vec<u8> = rlp.val_at(5).unwrap();
        let v: u64 = rlp.val_at(6).unwrap();
        let v: u8 = match chain_id {
            Some(_) => if v % 2 == 0 {
                1
            } else {
                0
            },
            None => v as u8,
        };
        let r: H256 = read_h256_without_leading_zeros(&rlp, 7);
        let s: H256 = read_h256_without_leading_zeros(&rlp, 8);

        let tx_hash = {
            let mut rlp = RlpStream::new();
            rlp.begin_unbounded_list();
            rlp.append(&nonce);
            rlp.append(&gas_price);
            rlp.append(&gas);
            rlp.append(&to);
            rlp.append(&value);
            rlp.append(&data);
            if let Some(chain_id) = chain_id {
                rlp.append(chain_id);
                rlp.append(&U256::zero());
                rlp.append(&U256::zero());
            }
            rlp.finalize_unbounded_list();
            H256(tiny_keccak::keccak256(&rlp.out()))
        };

        let signature = Signature::from_rsv(&r, &s, v);
        let sender = parity_crypto::publickey::recover(&signature, &tx_hash).map_err(|_| "mock: cannot recover sender key".to_string()).unwrap();
        let sender_address = parity_crypto::publickey::public_to_address(&sender);

        TransactionByHash {
            hash: tx_hash,
            nonce,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: sender_address,
            to: Some(to),
            value,
            gas_price,
            gas,
            input: data.to_hex::<String>(),
            raw: raw.to_hex::<String>(),
        }
    }
}

#[async_trait]
pub trait EthClient {

    async fn get_transaction_count(&self, address: &Address) -> Result<U256, Error>;

    async fn chain_id(&self) -> Result<Option<u64>, Error>;

    async fn gas_price(&self) -> Result<U256, Error>;

    async fn estimate_gas(&self, args: &EstimateGasArgs) -> Result<U256, Error>;

    async fn send_raw_transaction(&self, raw_transaction: &Vec<u8>) -> Result<H256, Error>;

    async fn get_transaction_by_hash(&self, transaction_hash: &H256) -> Result<Option<TransactionByHash>, Error>;

    /// Executes a new message call immediately without creating a transaction on the block chain.
    async fn call(&self, args: &CallArgs) -> Result<Vec<u8>, Error>;

    async fn is_transaction_success(&self, transaction_hash: &H256) -> Result<bool, Error>;
}

pub struct RpcEthClient {
    web3: Web3<web3::transports::Http>
}

impl RpcEthClient {
    pub fn new(address: &IpAddr, port: u16) -> Self {
        debug!("Using web3 client to: {}:{}", address, port);
        RpcEthClient {
            web3: Web3::new(web3::transports::Http::new(&format!("http://{addr}:{port}", addr = address, port = port)).unwrap())
        }
    }
}

#[async_trait]
impl EthClient for RpcEthClient {
    async fn get_transaction_count(&self, address: &Address) -> Result<U256, Error> {
        self.web3.eth().transaction_count(address.clone(), None).await
            .map_err(|err| Error::Eth(format!("EthError when calling eth_getTransactionCount: {}", err)))
    }

    async fn chain_id(&self) -> Result<Option<u64>, Error> {
        let id = self.web3.eth().chain_id().await
            .map_err(|err| Error::Eth(format!("EthError when calling eth_chainId: {}", err)))?;
        match id.try_into() {
            Ok(id) => Ok(Some(id)),
            Err(err) => Err(Error::Eth(format!("Cannot decode chain id: {}", err)))
        }
    }

    async fn gas_price(&self) -> Result<U256, Error> {
        self.web3.eth().gas_price().await
            .map_err(|err| Error::Eth(format!("EthError when calling eth_gasPrice: {}", err)))
    }

    async fn estimate_gas(&self, args: &EstimateGasArgs) -> Result<U256, Error> {
        self.web3.eth().estimate_gas(args.clone().into(), None).await
            .map_err(|err| Error::Eth(format!("EthError when calling eth_estimateGas: {}", err)))
    }

    async fn send_raw_transaction(&self, raw_transaction: &Vec<u8>) -> Result<H256, Error> {
        self.web3.eth().send_raw_transaction(Bytes(raw_transaction.clone())).await
            .map_err(|err| Error::Eth(format!("EthError when calling eth_sendRawTransaction: {}", err)))
    }

    async fn get_transaction_by_hash(&self, transaction_hash: &H256) -> Result<Option<TransactionByHash>, Error> {
        self.web3.eth().transaction(TransactionId::Hash(transaction_hash.clone())).await
            .map(|tx| tx.map(|tx| TransactionByHash::from(tx)))
            .map_err(|err| Error::Eth(format!("EthError when calling eth_getTransactionByHash: {}", err)))
    }

    async fn call(&self, args: &CallArgs) -> Result<Vec<u8>, Error> {
        self.web3.eth().call(args.clone().into(), None).await
            .map(|bytes| bytes.0)
            .map_err(|err| Error::Eth(format!("EthError when calling eth_call: {}", err)))
    }

    async fn is_transaction_success(&self, transaction_hash: &H256) -> Result<bool, Error> {
        match self.web3.eth().transaction_receipt(transaction_hash.clone()).await {
            Ok(Some(receipt)) => Ok(receipt.status == Some(U64([0x1]))),
            Ok(None) => Err(Error::Eth("transaction has not been mined".to_string())),
            Err(err) => Err(Error::Eth(format!("EthError when calling transaction_receipt: {}", err)))
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::sync::Mutex;
    use std::collections::HashMap;
    use ethereum_types::{Address, H256, U256};
    use crate::eth_client::{EthClient, TransactionByHash, EstimateGasArgs, CallArgs};
    use crate::error::Error;

    pub struct DummyEthClient {
        transactions: Mutex<HashMap<Address, Vec<(H256, Vec<u8>)>>>,
        gas_price: U256,
        chain_id: Option<u64>,
        hist: H256,
    }

    impl DummyEthClient {
        pub fn new() -> Self {
            Self::new_with(U256::zero(), Some(1234), H256([0; 32]))
        }

        pub fn new_with(gas_price: U256, chain_id: Option<u64>, hist: H256) -> Self {
            DummyEthClient {
                transactions: Mutex::new(HashMap::new()),
                gas_price,
                chain_id,
                hist,
            }
        }
    }

    #[async_trait]
    impl EthClient for DummyEthClient {
        async fn get_transaction_count(&self, address: &Address) -> Result<U256, Error> {
            let transactions = self.transactions.lock().unwrap();
            Ok(transactions.get(address).map(|tx_by_address| U256([tx_by_address.len() as u64, 0, 0, 0])).unwrap_or(U256::zero()))
        }

        async fn chain_id(&self) -> Result<Option<u64>, Error> {
            Ok(self.chain_id.clone())
        }

        async fn gas_price(&self) -> Result<U256, Error> {
            Ok(self.gas_price.clone())
        }

        async fn estimate_gas(&self, _: &EstimateGasArgs) -> Result<U256, Error> {
            Ok(U256::zero())
        }

        async fn send_raw_transaction(&self, raw: &Vec<u8>) -> Result<H256, Error> {
            let tx_by_hash = TransactionByHash::from_raw_transaction(&raw, &self.chain_id);
            let tx_hash = tx_by_hash.hash.clone();
            let sender_address = tx_by_hash.from.clone();
            let mut transactions = self.transactions.lock().unwrap();
            let vec = match transactions.get_mut(&sender_address) {
                Some(vec) => vec,
                None => {
                    transactions.insert(sender_address.clone(), Vec::new());
                    transactions.get_mut(&sender_address).unwrap()
                }
            };
            vec.push((tx_hash.clone(), raw.clone()));
            Ok(tx_hash)
        }

        async fn get_transaction_by_hash(&self, hash: &H256) -> Result<Option<TransactionByHash>, Error> {
            let transactions = self.transactions.lock().unwrap();
            let entry = transactions.iter().map(|(_, tx_by_address)| tx_by_address.iter())
                .flatten()
                .find(|(tx_hash, _)| tx_hash == hash);
            match entry {
                Some((_, raw)) => {
                    let mut tx = TransactionByHash::from_raw_transaction(&raw, &self.chain_id);
                    tx.block_hash = Some(H256(tiny_keccak::keccak256(&hash.0)));
                    tx.block_number = Some(U256::zero());
                    Ok(Some(tx))
                }
                None => Ok(None)
            }
        }

        async fn call(&self, args: &CallArgs) -> Result<Vec<u8>, Error> {
            // only support calls to getHist()
            let get_hist_signature = tiny_keccak::keccak256(&"getHist()".to_string().into_bytes());
            assert_eq!(args.data[..4], get_hist_signature[..4]);
            assert_eq!(args.data.len(), 4); //no arguments
            Ok(ethabi::encode(&[ethabi::Token::FixedBytes(self.hist.0.to_vec())]))
        }

        async fn is_transaction_success(&self, transaction_hash: &H256) -> Result<bool, Error> {
            self.get_transaction_by_hash(transaction_hash).await
                .map(|opt| if opt.is_none() { panic!() } else { true })
        }
    }
}
