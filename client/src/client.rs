// #![feature(trace_macros)]
use crate::Configuration;
use hyper::{Request, Body, StatusCode, body::HttpBody};
use crate::document::{Document, PendingDocumentUploadReceipt, ProvingKey, DocumentUploadReceipt};
use crate::access_policy::{AccessPolicy, FilledInAccessPolicy, VerificationKey};
use futures::future;
use ethereum_types::{H256, Public, U256, Address};
use parity_crypto::publickey::{Signature, Random, Generator};
use parity_crypto::publickey;
use crate::error::Error;
use std::str::FromStr;
use rand::rngs::OsRng;
use rand::RngCore;
use rustc_hex::ToHex;
use serde::Deserialize;
use serde;
use ethereum_tx_sign::RawTransaction;
use std::{time, thread};
use std::sync::Arc;
use crate::eth_client::{EthClient, RpcEthClient, EstimateGasArgs, TransactionByHash, CallArgs};
use crate::secret_store_http_client::{SecretStoreHttpClient, SecretStoreHttpClientImpl};
#[cfg(test)]
use serde::Serialize;
use zokrates_core::proof_system::SetupKeypair;
use ethabi::{FunctionOutputDecoder, Token};
use log::debug;

use_contract!(acl_contract, "res/SecretStoreAcl.abi");

pub struct Client<S: SecretStoreHttpClient, E: EthClient> {
    http_client: Arc<S>,
    eth_client: Arc<E>,
    config: Configuration,
}

impl Client<SecretStoreHttpClientImpl, RpcEthClient> {
    pub fn new(configuration: Configuration) -> Self {
        Client {
            http_client: Arc::new(SecretStoreHttpClientImpl::new()),
            eth_client: Arc::new(RpcEthClient::new(&configuration.eth_client_address, configuration.eth_client_port)),
            config: configuration
        }
    }
}

impl<S: SecretStoreHttpClient, E: EthClient> Client<S,E> {

    fn document_id_signature(&self, document_id: &H256) -> Result<Signature, Error> {
        Ok(publickey::sign(&self.config.key_pair.secret(), document_id)?)
    }

    async fn zokrates_setup(policy: &AccessPolicy) -> Result<SetupKeypair<VerificationKey>, Error> {
        policy.setup()
    }

    async fn assemble_body(mut body: Body) -> Result<String, Error> {
        let mut response_data = Vec::new();
        while let Some(next) = body.data().await {
            let chunk = next?;
            response_data.extend_from_slice(&chunk);
        }
        String::from_utf8(response_data)
            .map_err(|e| Error::SecretStore(e.to_string()))
    }

    pub async fn upload(&self, document: Document, policy: &AccessPolicy) -> Result<PendingDocumentUploadReceipt, Error> {
        let document_hash = document.hash();
        // generate server key for document and setup in parallel
        let encrypted_document = self.generate_document_key_encrypt_and_store(&document, &document_hash, policy.threshold());
        let setup = Self::zokrates_setup(&policy);
        let (encrypted_document, keypair) = future::try_join(encrypted_document, setup).await?;
        // submit document to acl contract

        let submit_tx_hash = self.submit_document(&document_hash, keypair.vk, policy.public_inputs()).await?;
        Ok(PendingDocumentUploadReceipt::new(document_hash, encrypted_document, keypair.pk, submit_tx_hash))
    }

    async fn generate_document_key_encrypt_and_store(&self, document: &Document, server_key_id: &H256, threshold: u32) -> Result<Vec<u8>, Error> {
        let server_key = self.generate_server_key(server_key_id, threshold).await?;
        let (encrypted_document, encrypted_document_key) = self.encrypt_document(document, &server_key).await?;
        self.store_encrypted_document_key(encrypted_document_key, server_key_id).await?;
        Ok(encrypted_document)
    }

    async fn generate_server_key(&self, server_key_id: &H256, threshold: u32) -> Result<Public,Error> {
        let signature = self.document_id_signature(server_key_id)?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{address}:{port}/shadow/{id:x}/{signature}/{threshold}",
                         address=self.config.secret_store_node_address,
                         port=self.config.secret_store_node_port,
                         id= server_key_id,
                         signature=signature.to_vec().to_hex::<String>(),
                         threshold=threshold))
            .body(Body::empty())?;
        debug!("Calling: {:?}", request);
        let response = self.http_client.request(request).await?;
        if response.status() != StatusCode::OK {
            return Err(Error::SecretStore(format!("when generating server key received status {}", response.status())));
        }
        let as_str = Self::assemble_body(response.into_body()).await?;
        // the response is "0x..."
        Ok(Public::from_str(&as_str[3..as_str.len()-1]).map_err(|e| Error::SecretStore(format!("when reading response of generating server key: {}", e)))?)
    }

    async fn encrypt_document(&self, document: &Document, server_key: &Public) -> Result<(Vec<u8>, EncryptedDocumentKey), Error> {
        // chose a random key for symmetric document encryption
        let document_key = Random.generate();
        let symmetric_document_key = public_to_symmetric_key(document_key.public());
        let encrypted_document = encrypt_document(document.content(), &symmetric_document_key)?;

        // encrypt document key with server key
        let encrypted_document_key = encrypt_document_key(document_key.public(), server_key)?;
        Ok((encrypted_document, encrypted_document_key))
    }

    async fn store_encrypted_document_key(&self, encrypted_document_key: EncryptedDocumentKey, server_key_id: &H256) -> Result<(), Error> {
        let signature = self.document_id_signature(&server_key_id)?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{address}:{port}/shadow/{id:x}/{signature}/{common_point:x}/{encrypted_point:x}",
                         address=self.config.secret_store_node_address,
                         port=self.config.secret_store_node_port,
                         id=server_key_id,
                         signature=signature.to_vec().to_hex::<String>(),
                         common_point=encrypted_document_key.common_point,
                         encrypted_point=encrypted_document_key.encrypted_point))
            .body(Body::empty())?;
        let response = self.http_client.request(request).await?;
        if response.status() == StatusCode::OK {
            Ok(())
        }else{
            Err(Error::SecretStore(format!("when storing encrypted document key received status {}", response.status())))
        }
    }

    async fn get_and_compute_nonce(&self, document_id: &H256, identity: &Address) -> Result<H256, Error> {
        let (encoded, output_decoder) = acl_contract::functions::get_hist::call();
        let output = self.eth_client.call(&CallArgs {
            from: None,
            to: Some(self.config.acl_contract_address.clone()),
            gas: None,
            gas_price: None,
            value: None,
            data: encoded
        }).await?;
        // compute sha256(sha256(hist||document_id||identity)||document_id||identity)
        let hist: H256 = output_decoder.decode(&output)
            .map_err(|err| Error::Eth(format!("When decoding output of getHist(): {}", err)))?;
        let hash = compute_nonce(&compute_nonce(&hist, &document_id, &identity), &document_id, &identity);
        Ok(format!("{:x}", hash).parse().unwrap())
    }

    pub async fn access_document(&self, document_id: &H256, encrypted_document: &Vec<u8>, policy: FilledInAccessPolicy, proving_key: &ProvingKey) -> Result<Vec<u8>, Error> {
        let identity = Random.generate();
        let nonce = self.get_and_compute_nonce(document_id, &identity.address()).await?;
        let proof = policy.compute_zk_proof(proving_key, nonce)?;
        let encoded_proof = serde_json::to_string(&proof.encode_as_payload()).unwrap();

        let signature = parity_crypto::publickey::sign(identity.secret(), &document_id)?;
        let request = Request::builder()
            .method("POST")
            .header("content-type", "application/json")
            .uri(format!("http://{address}:{port}/shadow/{id:x}/{signature}",
                address=self.config.secret_store_node_address,
                port=self.config.secret_store_node_port,
                id=document_id,
                signature=signature.to_vec().to_hex::<String>()
            ))
            .body(Body::from(encoded_proof))?;
        debug!("Calling {:?}", request);
        let response = self.http_client.request(request).await?;
        match response.status() {
            StatusCode::OK => {
                let as_str = Self::assemble_body(response.into_body()).await?;
                let ciphertext: DocumentKeyCiphertext = serde_json::from_str(&as_str).map_err(|serde_err| Error::SecretStore(format!("Cannot parse answer when accessing document key: {}", serde_err)))?;
                let key = decrypt_document_key(identity.secret(), ciphertext)?;
                decrypt_document(&key, encrypted_document)
            },
            StatusCode::FORBIDDEN => Err(Error::AccessDenied(document_id.clone())),
            StatusCode::NOT_FOUND => Err(Error::DocumentNotFound(document_id.clone())),
            _ => Err(Error::SecretStore(format!("when accessing document key received status {}", response.status()))),
        }
    }

    async fn submit_document(&self, document_id: &H256, verifying_key: VerificationKey, public_inputs: Vec<U256>) -> Result<H256, Error> {
        let nonce: U256 = self.eth_client.get_transaction_count(&self.config.key_pair.address()).await?;
        let chain_id: u64 = self.eth_client.chain_id().await?
            .ok_or_else(|| Error::Eth(format!("eth_chainId returned none")))?;
        let gas_price: U256 = self.eth_client.gas_price().await?;
        let (a,b,gamma,delta,gamma_abc) = verifying_key.ethabi_compliant();
        let (encoded_call, _) = acl_contract::functions::put_document::call(document_id.clone(), a, b, gamma, delta, gamma_abc, public_inputs);
        // estimate gas cost of call
        let gas: U256 = self.eth_client.estimate_gas(&EstimateGasArgs {
            from: self.config.key_pair.address(),
            to: self.config.acl_contract_address.clone(),
            gas_price: gas_price.clone(),
            value: U256::zero(),
            data: encoded_call.clone()
        }).await?;

        let tx = RawTransaction {
            nonce,
            to: Some(self.config.acl_contract_address.clone()),
            value: U256::zero(),
            gas_price,
            gas,
            data: encoded_call
        };
        let signed_tx = tx.sign(self.config.key_pair.secret(), &chain_id);
        let tx_hash = self.eth_client.send_raw_transaction(&signed_tx).await?;
        Ok(tx_hash)
    }

    pub async fn block_until_confirmed_submission(&self, receipt: PendingDocumentUploadReceipt, timeout: time::Duration) -> Result<DocumentUploadReceipt, Error> {
        let tx = self.get_transaction_by_hash(&receipt.acl_submission_hash, timeout).await?;
        if !self.eth_client.is_transaction_success(&tx.hash).await? {
            return Err(Error::Eth("DocumentUpload transaction wasn't successful".to_string()))
        }
        Ok(receipt.confirm(tx.block_number.unwrap()))
    }

    async fn get_transaction_by_hash(&self, hash: &H256, timeout: time::Duration) -> Result<TransactionByHash, Error> {
        let start = time::Instant::now();
        while start.elapsed() < timeout {
            let tx_by_hash: Option<TransactionByHash> = self.eth_client.get_transaction_by_hash(hash).await?;
            match tx_by_hash {
                Some(tx) if tx.is_mined() => return Ok(tx),
                // transaction not yet mined / or pending on current node
                _ => thread::sleep(time::Duration::from_millis(100)),
            }
        };
        Err(Error::Eth("transaction not found within timeout".into()))
    }
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct DocumentKeyCiphertext {
    pub common_point: Public,
    pub encrypted_point: Public,
}

/// returns keccak256(`hist`||`document_id`||`identity`)
fn compute_nonce(hist: &H256, document_id: &H256, identity: &Address) -> H256 {
    let content = ethabi::encode(&vec![
            Token::FixedBytes(hist.0.to_vec()),
            Token::FixedBytes(document_id.0.to_vec()),
            Token::Address(identity.clone()),
    ]);
    // tiny_keccak::keccak256 corresponds to solidity's keccak256 built-in function
    H256(tiny_keccak::keccak256(&content))
}


fn decrypt_document_key(secret: &publickey::Secret, ciphertext: DocumentKeyCiphertext) -> Result<Public, Error> {
    let mut common_point = ciphertext.common_point;
    let mut decrypted_secret = ciphertext.encrypted_point;
    publickey::ec_math_utils::public_mul_secret(&mut common_point, &secret)?;
    publickey::ec_math_utils::public_sub(&mut decrypted_secret, &common_point)?;
    Ok(decrypted_secret)
}

fn decrypt_document(document_key: &Public, encrypted_document: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let symmetric_document_key = public_to_symmetric_key(&document_key);
    let (encrypted_data, iv) = if encrypted_document.len() >= 16 {
        encrypted_document.split_at(encrypted_document.len() - 16)
    } else {
        return Err(Error::Crypto("invalid encrypted document".to_string()))
    };
    debug_assert_eq!(iv.len(), 16);
    let mut decrypted_document = vec![0u8; encrypted_document.len() - 16];
    debug_assert_eq!(encrypted_data.len(), decrypted_document.len());
    parity_crypto::aes::decrypt_128_ctr(&symmetric_document_key, &iv, encrypted_data, &mut decrypted_document)?;
    Ok(decrypted_document)
}

/// transforms a secp256k1 public key to a AES-128 symmetric key
fn public_to_symmetric_key(public: &Public) -> [u8;16] {
    let mut key = [0u8;16];
    key.copy_from_slice(&public[..16]);
    key
}

/// encrypt `document` with symmetric aes-128-ctr using `key`. The IV is stored at the last 16 bytes.
fn encrypt_document(document: &Vec<u8>, key: &[u8;16]) -> Result<Vec<u8>, Error> {
    let iv = {
        let mut rand = OsRng::default();
        let mut iv = [0u8; 16];
        rand.fill_bytes(&mut iv);
        iv
    };
    let mut encrypted_document = vec![0u8; document.len() + iv.len()];
    {
        let (mut encryption_buffer, iv_buffer) = encrypted_document.split_at_mut(document.len());

        parity_crypto::aes::encrypt_128_ctr(key, &iv, &document, &mut encryption_buffer)?;
        iv_buffer.copy_from_slice(&iv);
    }
    Ok(encrypted_document)
}

/// A ElGamal ciphertext
struct EncryptedDocumentKey {
    pub common_point: Public,
    pub encrypted_point: Public,
}

/// Encrypt the message `document_key` using ElGamal encryption with key `server_key`
fn encrypt_document_key(document_key: &Public, server_key: &Public) -> Result<EncryptedDocumentKey, Error> {
    let k = Random.generate().secret().clone();
    let mut common_point = parity_crypto::publickey::ec_math_utils::generation_point();
    // common_point = k * G
    parity_crypto::publickey::ec_math_utils::public_mul_secret(&mut common_point, &k)?;
    let mut encrypted_point: Public = server_key.clone();
    // encrypted_point = document_key + k * server_key
    parity_crypto::publickey::ec_math_utils::public_mul_secret(&mut encrypted_point, &k)?;
    parity_crypto::publickey::ec_math_utils::public_add(&mut encrypted_point, document_key)?;
    Ok(EncryptedDocumentKey {
        common_point,
        encrypted_point
    })
}

#[cfg(test)]
mod test {
    use crate::tests::DummySecretStore;
    use ethereum_types::{H256, Address, U256, H160};
    use parity_crypto::publickey::{Random, Generator, ec_math_utils};
    use crate::client::{encrypt_document_key, decrypt_document_key, public_to_symmetric_key, encrypt_document, decrypt_document, Client, compute_nonce};
    use std::sync::Arc;
    use crate::Configuration;
    use crate::document::{Document, PendingDocumentUploadReceipt};
    use crate::access_policy::{AccessPolicy, VerificationKey, WitnessArgument, test::verify_g16_proof};
    use crate::secret_store_http_client::test::{DummySecretStoreHttpClient, UnimplementedSecretStoreHttpClient};
    use crate::eth_client::test::DummyEthClient;
    use crate::eth_client::{EthClient, TransactionByHash, EstimateGasArgs, CallArgs};
    use rustc_hex::FromHex;
    use ethabi::{Function, Contract};
    use std::fs::File;
    use itertools::Itertools;
    use std::time::{Duration, Instant};
    use crate::error::Error;

    fn put_document_function() -> Function {
        let file = File::open("res/SecretStoreAcl.abi").unwrap();
        let contract = Contract::load(file).unwrap();
        contract.function("putDocument").unwrap().clone()
    }

    fn abi_signature(f: &Function) -> [u8; 4] {
        let selector = format!("{name}({args})", name=f.name, args=f.inputs.iter().map(|param| param.kind.to_string()).join(","));
        let as_bytes = selector.into_bytes();
        let hash = tiny_keccak::keccak256(&as_bytes);

        let mut signature = [0; 4];
        signature.copy_from_slice(&hash[..4]);
        signature
    }

    fn parse_g16_verifying_key(tokens: &Vec<ethabi::Token>) -> (VerificationKey, Vec<U256>) {
        fn parse_4_u256(array: &ethabi::Token) -> [U256; 4] {
            let array = array.clone().to_fixed_array().unwrap();
            assert_eq!(array.len(), 4);
            [array[0].clone().to_uint().unwrap(), array[1].clone().to_uint().unwrap(), array[2].clone().to_uint().unwrap(), array[3].clone().to_uint().unwrap()]
        }
        assert_eq!(tokens.len(), 7);
        let a = tokens[1].clone().to_fixed_array().unwrap();
        let a = [a[0].clone().to_uint().unwrap(), a[1].clone().to_uint().unwrap()];
        let b = parse_4_u256(&tokens[2]);
        let gamma = parse_4_u256(&tokens[3]);
        let delta = parse_4_u256(&tokens[4]);
        let gamma_abc = tokens[5].clone().to_array().unwrap();
        let gamma_abc = gamma_abc.iter().map(|token| token.clone().to_uint().unwrap()).collect();
        let input = tokens[6].clone().to_array().unwrap();
        let input = input.iter().map(|token| token.clone().to_uint().unwrap()).collect();
        (VerificationKey::from_ethabi(a,b,gamma,delta,gamma_abc).unwrap(), input)
    }

    struct EthClientWaitingForTx {
        tx: H256,
        ready_after: Duration,
        started: Instant,
        /// if true, tx will be returned as pending before `ready_after`
        /// if false, tx will be returned as not-existing before `ready_after`
        return_as_pending: bool
    }

    impl EthClientWaitingForTx {
        pub fn new(tx: H256, ready_after: Duration, return_as_pending: bool) -> Self {
            EthClientWaitingForTx {
                tx,
                ready_after,
                started: Instant::now(),
                return_as_pending
            }
        }
    }

    #[async_trait]
    impl EthClient for EthClientWaitingForTx {
        async fn get_transaction_count(&self, _address: &Address) -> Result<U256, Error> {
            unimplemented!()
        }

        async fn chain_id(&self) -> Result<Option<u64>, Error> {
            unimplemented!()
        }

        async fn gas_price(&self) -> Result<U256, Error> {
            unimplemented!()
        }

        async fn estimate_gas(&self, _args: &EstimateGasArgs) -> Result<U256, Error> {
            unimplemented!()
        }

        async fn send_raw_transaction(&self, _raw_transaction: &Vec<u8>) -> Result<H256, Error> {
            unimplemented!()
        }

        async fn get_transaction_by_hash(&self, transaction_hash: &H256) -> Result<Option<TransactionByHash>, Error> {
            if &self.tx == transaction_hash {
                if self.started.elapsed() >= self.ready_after {
                    // tx is ready
                    Ok(Some(TransactionByHash {
                        hash: self.tx.clone(),
                        nonce: U256::zero(),
                        block_hash: Some(H256::default()),
                        block_number: Some(U256::zero()),
                        transaction_index: Some(U256::zero()),
                        from: H160::default(),
                        to: None,
                        value: U256::zero(),
                        gas_price: U256::zero(),
                        gas: U256::zero(),
                        input: "".to_string(),
                        raw: "".to_string(),
                    }))
                } else {
                    if self.return_as_pending {
                        // encode as pending
                        Ok(Some(TransactionByHash {
                            hash: self.tx.clone(),
                            nonce: U256::zero(),
                            block_hash: None,
                            block_number: None,
                            transaction_index: None,
                            from: H160::default(),
                            to: None,
                            value: U256::zero(),
                            gas_price: U256::zero(),
                            gas: U256::zero(),
                            input: "".to_string(),
                            raw: "".to_string(),
                        }))
                    } else {
                        // doesn't exist
                        Ok(None)
                    }
                }
            } else {
                panic!("unexpected transaction")
            }
        }

        async fn call(&self, _args: &CallArgs) -> Result<Vec<u8>, Error> {
            unimplemented!()
        }

        async fn is_transaction_success(&self, transaction_hash: &H256) -> Result<bool, Error> {
            if &self.tx == transaction_hash {
                if self.started.elapsed() >= self.ready_after {
                    Ok(true)
                }else{
                    panic!("should only be called after transaction was mined");
                }
            }else{
                panic!("unexpected transaction")
            }
        }
    }

    #[test]
    fn client_properly_uploads_document() {

        async fn do_upload() {
            let http_client = Arc::new(DummySecretStoreHttpClient::new(DummySecretStore::new()));
            let eth_client = Arc::new(DummyEthClient::new());
            let uploader = Random.generate();
            let acl_contract: Address = "731a10897d267e19b34503ad902d0a29173ba4b1".parse().unwrap();
            let client = Client {
                http_client,
                eth_client: eth_client.clone(),
                config: Configuration {
                    secret_store_node_address: "127.0.0.1".parse().unwrap(),
                    secret_store_node_port: 0,
                    key_pair: uploader.clone(),
                    eth_client_address: "127.0.0.1".parse().unwrap(),
                    eth_client_port: 0,
                    acl_contract_address: acl_contract
                }
            };

            let document = Document::from_bytes(vec![0,1,2,3,4,5,6,7,8,9]);
            let policy = AccessPolicy::knowledge_of_root(U256([64,0,0,0]), 2);
            let pending_receipt = client.upload(document.clone(), &policy).await.unwrap();

            // assert document id is the hash of the plaintext document
            assert_eq!(pending_receipt.document_id, document.hash());
            // assert that the encrypted document has the same length (plus IV of 16 byte)
            assert_eq!(pending_receipt.encrypted_document.len(), document.content().len()+16);
            assert!(pending_receipt.proving_key.len() > 0);
            // assert that submit-document call has been made
            let tx = eth_client.get_transaction_by_hash(&pending_receipt.acl_submission_hash).await.unwrap();
            assert!(tx.is_some());
            let tx = tx.unwrap();
            assert_eq!(tx.from, uploader.address());
            assert_eq!(tx.value, U256::zero());
            assert_eq!(tx.to, Some(acl_contract.clone()));

            let put_document_call: Vec<u8> = tx.input.from_hex().unwrap();
            let put_document_function = put_document_function();
            assert!(put_document_call.len() >= 4);
            assert_eq!(put_document_call[..4], abi_signature(&put_document_function));
            let tokens = put_document_function.decode_input(&put_document_call[4..]).unwrap();
            let (vk, inputs) = parse_g16_verifying_key(&tokens);
            assert_eq!(inputs, vec![U256([64,0,0,0])]);

            // to verify that vk is indeed a valid G16 verifying key, we use the proving key and compute a proof
            // and try to verify it afterwards
            let nonce: H256 = "c50e523be48f0548907eb426131352d787fac005ddffe676773b41b45314fc70".parse().unwrap();
            let filled_policy = policy.fill_in(vec![WitnessArgument::Number(vec![U256([8,0,0,0])]), WitnessArgument::Number(vec![U256([64,0,0,0])])]);
            let proof = filled_policy.compute_zk_proof(&pending_receipt.proving_key, nonce.clone()).unwrap();

            assert!(verify_g16_proof(proof, vk, &vec![WitnessArgument::Number(vec![U256([64,0,0,0])]), WitnessArgument::from_h256(nonce), WitnessArgument::one()]));

        }

        tokio_test::block_on(do_upload());
    }

    async fn do_block_until_confirmed_submission(pending: bool) {
        let tx_hash: H256 = "c50e523be48f0548907eb426131352d787fac005ddffe676773b41b45314fc70".parse().unwrap();
        let http_client = Arc::new(UnimplementedSecretStoreHttpClient {});
        let eth_client = Arc::new(EthClientWaitingForTx::new(tx_hash.clone(), Duration::from_millis(300), pending));
        let uploader = Random.generate();
        let acl_contract: Address = "731a10897d267e19b34503ad902d0a29173ba4b1".parse().unwrap();
        let client = Client {
            http_client,
            eth_client: eth_client.clone(),
            config: Configuration {
                secret_store_node_address: "127.0.0.1".parse().unwrap(),
                secret_store_node_port: 0,
                key_pair: uploader.clone(),
                eth_client_address: "127.0.0.1".parse().unwrap(),
                eth_client_port: 0,
                acl_contract_address: acl_contract
            }
        };



        let pending_receipt = PendingDocumentUploadReceipt {
            document_id: H256::default(),
            encrypted_document: vec![],
            proving_key: vec![],
            acl_submission_hash: tx_hash.clone(),
        };

        client.block_until_confirmed_submission(pending_receipt, Duration::from_secs(4)).await.unwrap();
    }

    #[test]
    fn client_block_until_confirmed_submission_works_for_pending_transactions() {
        tokio_test::block_on(do_block_until_confirmed_submission(true))
    }

    #[test]
    fn client_block_until_confirmed_submission_works_for_other_transactions() {
        tokio_test::block_on(do_block_until_confirmed_submission(false))
    }

    #[test]
    fn client_block_until_confirmed_submission_timeouts() {
        async fn do_block_until_confirmed_submission_timeouts() {
            let tx_hash: H256 = "c50e523be48f0548907eb426131352d787fac005ddffe676773b41b45314fc70".parse().unwrap();
            let http_client = Arc::new(UnimplementedSecretStoreHttpClient {});
            let eth_client = Arc::new(EthClientWaitingForTx::new(tx_hash.clone(), Duration::from_secs(4), false));
            let uploader = Random.generate();
            let acl_contract: Address = "731a10897d267e19b34503ad902d0a29173ba4b1".parse().unwrap();
            let client = Client {
                http_client,
                eth_client: eth_client.clone(),
                config: Configuration {
                    secret_store_node_address: "127.0.0.1".parse().unwrap(),
                    secret_store_node_port: 0,
                    key_pair: uploader.clone(),
                    eth_client_address: "127.0.0.1".parse().unwrap(),
                    eth_client_port: 0,
                    acl_contract_address: acl_contract
                }
            };



            let pending_receipt = PendingDocumentUploadReceipt {
                document_id: H256::default(),
                encrypted_document: vec![],
                proving_key: vec![],
                acl_submission_hash: tx_hash.clone(),
            };

            // tx is finished after 4s, but the timeout is set to 500ms -> expect timeout error
            match client.block_until_confirmed_submission(pending_receipt, Duration::from_millis(500)).await {
                Err(Error::Eth(msg)) => assert_eq!(&msg, "transaction not found within timeout"),
                _ => panic!("expected timeout error"),
            }
        }
        tokio_test::block_on(do_block_until_confirmed_submission_timeouts())
    }

    #[test]
    fn client_access_document_works() {
        async fn do_access_document() {
            let http_client = Arc::new(DummySecretStoreHttpClient::new(DummySecretStore::new()));
            let eth_client = Arc::new(DummyEthClient::new());
            let uploader = Random.generate();
            let acl_contract: Address = "731a10897d267e19b34503ad902d0a29173ba4b1".parse().unwrap();
            let client = Client {
                http_client: http_client.clone(),
                eth_client: eth_client.clone(),
                config: Configuration {
                    secret_store_node_address: "127.0.0.1".parse().unwrap(),
                    secret_store_node_port: 0,
                    key_pair: uploader.clone(),
                    eth_client_address: "127.0.0.1".parse().unwrap(),
                    eth_client_port: 0,
                    acl_contract_address: acl_contract
                }
            };

            let document = Document::from_bytes(vec![0,1,2,3,4,5,6,7,8,9]);
            let policy = AccessPolicy::knowledge_of_root(U256([64,0,0,0]), 2);
            let pending_receipt = client.upload(document.clone(), &policy).await.unwrap();
            let receipt = client.block_until_confirmed_submission(pending_receipt, Duration::from_millis(500)).await.unwrap();

            // fill in policy
            let filled = policy.fill_in(vec![WitnessArgument::Number(vec![U256([8,0,0,0])]), WitnessArgument::Number(vec![U256([64,0,0,0])])]);

            let decrypted_document = client.access_document(&receipt.original.document_id, &receipt.original.encrypted_document, filled, &receipt.original.proving_key).await.unwrap();

            assert_eq!(document.content(), &decrypted_document);

            // the client used a random id (different from `uploader`
            let log = http_client.get_access_log();
            assert_eq!(1, log.len());
            log.iter().for_each(|(document_id,requester)| {
                assert_eq!(document_id, &receipt.original.document_id);
                assert_ne!(requester, &uploader.address());
            });
        }

        tokio_test::block_on(do_access_document())
    }

    #[test]
    fn client_access_document_errors_if_document_not_found() {
        async fn do_access_nonexistent_document() {
            let http_client = Arc::new(DummySecretStoreHttpClient::new(DummySecretStore::new()));
            let eth_client = Arc::new(DummyEthClient::new());
            let uploader = Random.generate();
            let acl_contract: Address = "731a10897d267e19b34503ad902d0a29173ba4b1".parse().unwrap();
            let client = Client {
                http_client,
                eth_client: eth_client.clone(),
                config: Configuration {
                    secret_store_node_address: "127.0.0.1".parse().unwrap(),
                    secret_store_node_port: 0,
                    key_pair: uploader.clone(),
                    eth_client_address: "127.0.0.1".parse().unwrap(),
                    eth_client_port: 0,
                    acl_contract_address: acl_contract
                }
            };

            let policy = AccessPolicy::knowledge_of_root(U256([64,0,0,0]), 2);
            let zk_keypair = policy.setup().unwrap();
            let document_id: H256 = "7141cd2794bdc548998130abeb41c69d8066376a609da72a54b8b18473c6d836".parse().unwrap();

            // fill in policy
            let filled = policy.fill_in(vec![WitnessArgument::Number(vec![U256([8,0,0,0])]), WitnessArgument::Number(vec![U256([64,0,0,0])])]);
            match client.access_document(&document_id, &vec![], filled, &zk_keypair.pk).await {
                Err(Error::DocumentNotFound(id)) => assert_eq!(id, document_id),
                _ => panic!("unexpected:")
            }
        }

        tokio_test::block_on(do_access_nonexistent_document())
    }

    #[test]
    fn client_access_document_errors_if_access_denied() {
        async fn do_access_forbidden_document() {
            let http_client = Arc::new(DummySecretStoreHttpClient::new(DummySecretStore::new()));
            let eth_client = Arc::new(DummyEthClient::new());
            let uploader = Random.generate();
            let acl_contract: Address = "731a10897d267e19b34503ad902d0a29173ba4b1".parse().unwrap();
            let client = Client {
                http_client: http_client.clone(),
                eth_client: eth_client.clone(),
                config: Configuration {
                    secret_store_node_address: "127.0.0.1".parse().unwrap(),
                    secret_store_node_port: 0,
                    key_pair: uploader.clone(),
                    eth_client_address: "127.0.0.1".parse().unwrap(),
                    eth_client_port: 0,
                    acl_contract_address: acl_contract
                }
            };

            let document = Document::from_bytes(vec![0,1,2,3,4,5,6,7,8,9]);
            let policy = AccessPolicy::knowledge_of_root(U256([64,0,0,0]), 2);
            let pending_receipt = client.upload(document.clone(), &policy).await.unwrap();
            let receipt = client.block_until_confirmed_submission(pending_receipt, Duration::from_millis(500)).await.unwrap();

            // fill in policy
            let filled = policy.fill_in(vec![WitnessArgument::Number(vec![U256([8,0,0,0])]), WitnessArgument::Number(vec![U256([64,0,0,0])])]);

            //blacklist document
            http_client.blacklist(&receipt.original.document_id);

            match client.access_document(&receipt.original.document_id, &receipt.original.encrypted_document, filled, &receipt.original.proving_key).await {
                Err(Error::AccessDenied(id)) => assert_eq!(id, receipt.original.document_id),
                _ => panic!("unexpected"),
            }
        }

        tokio_test::block_on(do_access_forbidden_document())
    }

    #[test]
    fn document_key_encryption_works() {
        let server_key = Random.generate();

        let document_key = Random.generate().public().clone();
        let encrypted_document_key = encrypt_document_key(&document_key, server_key.public()).unwrap();

        // ElGamal decryption
        let mut common_point = encrypted_document_key.common_point.clone();
        ec_math_utils::public_mul_secret(&mut common_point, server_key.secret()).unwrap();
        let mut decrypted_document_key = encrypted_document_key.encrypted_point.clone();
        ec_math_utils::public_sub(&mut decrypted_document_key, &common_point).unwrap();
        assert_eq!(document_key, decrypted_document_key);
    }

    #[test]
    fn secret_store_decryption_works() {
        let mut secretstore = DummySecretStore::new();

        let document_id = H256::default();
        let threshold = 4;
        let server_public = secretstore.generate_key(document_id.clone(), threshold).unwrap();

        let document_key = Random.generate().public().clone();
        let encrypted_document_key = encrypt_document_key(&document_key, &server_public).unwrap();

        secretstore.store_points(&document_id, encrypted_document_key.common_point, encrypted_document_key.encrypted_point).unwrap();

        let requester = Random.generate();
        let decryption_shadows = secretstore.decrypt_shadow(&document_id, requester.public()).unwrap();
        let decrypted_document_key = decrypt_document_key(requester.secret(), decryption_shadows).unwrap();

        assert_eq!(document_key, decrypted_document_key);
        assert_eq!(public_to_symmetric_key(&document_key), public_to_symmetric_key(&decrypted_document_key));
    }

    #[test]
    fn document_encryption_works() {
        let document = "A document to encrypt!";
        let document = document.to_string().into_bytes();

        let document_key = Random.generate().public().clone();

        let encrypted = encrypt_document(&document, &public_to_symmetric_key(&document_key)).unwrap();
        let decrypted = decrypt_document(&document_key, &encrypted).unwrap();
        assert_eq!(document, decrypted);
    }

    #[test]
    fn nonce_computation_works() {
        let h: H256 = "f73ab96ded664c70019727ec968567483242ac2f95d78790bcb2704fdbe0ce60".parse().unwrap();
        let document_id: H256 = "7fdfdba09411e4754f02e57b9c19ad7a3b556d4182147b271e62e635b1acee84".parse().unwrap();
        let user: Address = "aB21eA2b7a0aB6Df9850B0899D7886E1a69F86A6".parse().unwrap();

        let expected: H256 = "dc8e22cf90ff145e1a175cbef24b04f56a6d0b53d205a3545b4b369d8a4e3c76".parse().unwrap();
        assert_eq!(expected, compute_nonce(&h, &document_id, &user));
    }
}
