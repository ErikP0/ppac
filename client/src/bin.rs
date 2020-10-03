use structopt::StructOpt;
use std::path::{PathBuf, Path};
use libclient::Configuration;
use parity_crypto::publickey::{Random, Generator, KeyPair};
use ethereum_types::{Address, H256, Secret};
use libclient::error::Error;
use std::fs::File;
use libclient::document::Document;
use libclient::access_policy::{AccessPolicy, WitnessArgument};
use itertools::Itertools;
use libclient::client::Client;
use std::time::Duration;
use std::net::SocketAddr;
use std::str::FromStr;
use serde::Deserialize;
use std::ffi::OsString;
use std::io::Write;
#[cfg(test)]
extern crate simple_logger;

#[derive(StructOpt)]
struct CliCommand {
    #[structopt(short="c", long="config", parse(from_os_str), help = "Path to configuration file. If not given, a default configuration will be used.")]
    config: Option<PathBuf>,
    #[structopt(subcommand)]
    action: Action
}

#[derive(StructOpt)]
enum Action {
    #[structopt(name = "create-policy", about="Create an access policy based on a zokrates program")]
    CreatePolicy {
        #[structopt(long="circuit", parse(from_os_str), help="Path to the Zokrates circuit file")]
        circuit: PathBuf,
        #[structopt(long="zok-stdlib", parse(from_os_str), help="Path to the Zokrates stdlib")]
        zok_stdlib: PathBuf,
        #[structopt(short="t", long="threshold", help="The threshold t. At least t+1 shares are needed to reconstruct the secret that protects the document.")]
        threshold: u32,
        #[structopt(short="o", long="output", parse(from_os_str), default_value = "policy.json", help="Path to store the policy file.")]
        output: PathBuf,
        #[structopt(help="Public inputs")]
        arguments: Vec<String>
    },
    #[structopt(about="Upload a document associated with an access policy and receive the encrypted document.")]
    Upload {
        #[structopt(long="document", parse(from_os_str), help="Path to the document to upload.")]
        document: PathBuf,
        #[structopt(long="policy", parse(from_os_str), default_value = "policy.json", help="Path to the policy file to use.")]
        policy: PathBuf,
        #[structopt(long="encrypted-document", parse(from_os_str), default_value = "encrypted", help="Path to store the encrypted document after upload.")]
        encrypted_document: PathBuf,
        #[structopt(long="proving-key", parse(from_os_str), default_value = "proving.key", help="Path to store the proving key after upload.")]
        proving_key: PathBuf
    },
    #[structopt(about="Prove access authorization using zero-knowledge and decrypt the document")]
    Access {
        #[structopt(long="document-id", help="The id of the document to access")]
        document_id: String,
        #[structopt(long="policy", parse(from_os_str), help="Path to the policy file to use.")]
        policy: PathBuf,
        #[structopt(long="encrypted-document", parse(from_os_str), default_value = "encrypted", help="Path to read the encrypted document from.")]
        encrypted_document: PathBuf,
        #[structopt(long="proving-key", parse(from_os_str), default_value = "proving.key", help="Path to read the proving key from.")]
        proving_key: PathBuf,
        #[structopt(long="decrypted-document", parse(from_os_str), default_value = "document", help="Path to store the decrypted document.")]
        document: PathBuf,
        #[structopt(help="witness inputs")]
        arguments: Vec<String>
    }
}

fn default_configuration() -> Configuration {
    let file = ConfigurationFile {
        secret_store: None,
        eth_client: None,
        acl_contract: format!("{:x}", Address::default()),
        author_keypair: None
    };
    return file.parse().unwrap();
}

#[derive(Deserialize)]
struct ConfigurationFile {
    /// default "127.0.0.1:8010"
    pub secret_store: Option<String>,
    /// default "127.0.0.1:8545"
    pub eth_client: Option<String>,
    pub acl_contract: String,
    pub author_keypair: Option<String>
}

impl ConfigurationFile {
    pub fn parse(self) -> Result<Configuration, Error> {
        let secret_store_addr = SocketAddr::from_str(&self.secret_store.unwrap_or_else(|| "127.0.0.1:8010".to_string()))
            .map_err(|err| Error::Io(format!("Cannot parse secret store address: {}", err)))?;
        let eth_client = SocketAddr::from_str(&self.eth_client.unwrap_or_else(|| "127.0.0.1:8545".to_string()))
            .map_err(|err| Error::Io(format!("Cannot parse secret store address: {}", err)))?;
        let keypair = match self.author_keypair{
            Some(secret) => {
                let secret: Secret = secret.parse().map_err(|err| Error::Io(format!("Cannot parse keypair secret: {}", err)))?;
                let secret = parity_crypto::publickey::Secret::copy_from_slice(&secret.0).unwrap();
                KeyPair::from_secret(secret).map_err(|err| Error::Io(format!("Invalid secret key: {}", err)))?
            },
            None => Random.generate()
        };
        let acl_contract_address: Address = self.acl_contract.parse().map_err(|err| Error::Io(format!("Cannot parse acl contract address: {}", err)))?;
        Ok(Configuration {
            secret_store_node_address: secret_store_addr.ip(),
            secret_store_node_port: secret_store_addr.port(),
            key_pair: keypair,
            eth_client_address: eth_client.ip(),
            eth_client_port: eth_client.port(),
            acl_contract_address
        })
    }
}

fn parse_config_file(path: &Path) -> Result<Configuration, Error> {
    let json = std::fs::read_to_string(path)?;
    let config_file = serde_json::from_str::<ConfigurationFile>(&json)
        .map_err(|err| Error::Io(format!("Invalid config file: {}", err)))?;
    config_file.parse()
}

async fn client_main<I: IntoIterator>(args: I) -> Result<(), Error> where I::Item : Into<OsString> + Clone {
    let options: CliCommand = StructOpt::from_iter(args);
    let config = match options.config {
        Some(path) => parse_config_file(&path)?,
        None => default_configuration()
    };
    match options.action {
        Action::CreatePolicy {circuit, zok_stdlib, threshold, output, arguments} => cli_create_policy(&circuit, &zok_stdlib, threshold, &output, &arguments),
        Action::Upload {document, policy, encrypted_document, proving_key} => {
            let document = {
                let mut document_file = File::open(&document)?;
                Document::from_reader(&mut document_file)?
            };
            let policy = read_policy(&policy)?;
            let client = Client::new(config);
            let pending_receipt = client.upload(document, &policy).await?;
            println!("Successfully uploaded document {:x}", pending_receipt.document_id);
            print!("Waiting for transaction {:x} ...", pending_receipt.acl_submission_hash);
            std::io::stdout().flush().unwrap();
            let receipt = client.block_until_confirmed_submission(pending_receipt, Duration::from_secs(30)).await?;
            println!("Done (mined in block {:x})", receipt.acl_submission_block_num);
            // write encrypted document
            std::fs::write(&encrypted_document, &receipt.original.encrypted_document)?;
            std::fs::write(&proving_key, &receipt.original.proving_key)?;
            Ok(())
        },
        Action::Access { document_id, policy, document, encrypted_document, proving_key, arguments} => {
            let document_id: H256 = document_id.parse().map_err(|err| Error::Io(format!("Invalid document_id: {}", err)))?;
            let policy = read_policy(&policy)?;
            let arguments = read_witness_argument(&arguments)?;
            let client = Client::new(config);
            let encrypted_document = std::fs::read(&encrypted_document)?;
            let proving_key = std::fs::read(&proving_key)?;
            let decrypted_document = client.access_document(&document_id, &encrypted_document, policy.fill_in(arguments), &proving_key)
                .await?;
            std::fs::write(&document, &decrypted_document)?;
            Ok(())
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Error> {
    client_main(std::env::args()).await
}

fn read_policy(policy: &Path) -> Result<AccessPolicy, Error> {
    let json = std::fs::read_to_string(&policy)?;
    serde_json::from_str::<AccessPolicy>(&json)
        .map_err(|err| Error::Io(format!("Cannot read policy file: {}", err)))
}

fn read_witness_argument(arguments: &Vec<String>) -> Result<Vec<WitnessArgument>, Error> {
    arguments.iter().map(|arg| WitnessArgument::from_dec_string(&arg))
        .try_collect()
}

fn cli_create_policy(circuit: &Path, zok_stdlib: &Path, threshold: u32, output: &Path, arguments: &Vec<String>) -> Result<(), Error> {
    // parse arguments
    let arguments = read_witness_argument(arguments)?;
    // compile
    let policy = AccessPolicy::new(circuit, threshold, arguments, zok_stdlib)?;
    let json = serde_json::to_string(&policy).unwrap();
    std::fs::write(output, &json).map_err(Into::into)
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;
    use std::path::Path;
    use ethereum_types::H256;
    use log::info;
    use crate::{parse_config_file, read_policy};
    use std::net::IpAddr;
    use rustc_hex::FromHex;
    use libclient::error::Error;

    mod setup {
        use std::path::{Path, PathBuf};
        use std::process::{Command, Stdio, Child};
        use itertools::Itertools;
        use std::collections::HashMap;
        use tempdir::TempDir;
        use futures::future::join3;
        use hyper::{Request, Body, body::HttpBody, StatusCode};
        use hyper::client::Client as HttpClient;
        use ethereum_types::{H256, Address, H512, U256};
        use std::str::FromStr;
        use std::time::Duration;
        use std::future::Future;
        use ethabi::Token;
        use futures::{StreamExt};
        use tokio::io::{BufReader, AsyncBufReadExt};
        use log::info;

        struct Config {
            base_path: PathBuf,
            rpc_port: u16,
            network_port: u16,
            enode_addresses: Vec<(String,u16)>,
            self_secret: String,
            acl_contract: String,
            secret_store_http_port: u16,
            secret_store_port: u16,
            publickeys: Vec<(String, u16)>,
            password: PathBuf,
        }

        impl Config {
            pub fn export(self, log_file: &Path) -> PathBuf {
                let raw = std::fs::read_to_string(Path::new("test_res/config/secretstore-config.toml.format"))
                    .unwrap();
                let mut args = HashMap::new();
                args.insert("base_path".to_string(), self.base_path.to_str().unwrap().to_string());
                args.insert("rpc_port".to_string(), format!("{}", self.rpc_port));
                args.insert("network_port".to_string(), format!("{}", self.network_port));
                args.insert("network_bootnodes".to_string(), self.enode_addresses.iter()
                    .map(|(enode,port)| format!("\"enode://{}@127.0.0.1:{}\"", enode, port))
                    .join(",\n")
                );
                args.insert("self_secret".to_string(), self.self_secret);
                args.insert("secret_store_http_port".to_string(), format!("{}", self.secret_store_http_port));
                args.insert("acl_contract".to_string(), self.acl_contract);
                args.insert("secret_store_port".to_string(), format!("{}", self.secret_store_port));
                args.insert("secret_store_nodes".to_string(), self.publickeys.iter()
                    .map(|(pk, port)| format!("\"{}@127.0.0.1:{}\"", pk, port))
                    .join(",\n")
                );
                args.insert("password".to_string(), self.password.to_str().unwrap().to_string());
                args.insert("log_file".to_string(), log_file.to_str().unwrap().to_string());

                let filled_config = strfmt::strfmt(&raw, &args).unwrap();
                let config_path = self.base_path.join(Path::new("config.toml"));
                std::fs::write(&config_path, &filled_config).unwrap();
                return config_path;
            }
        }

        async fn start_secret_store(config: Config, account: &Path, log_file: PathBuf) -> Child {
            // first import account
            let config = config.export(&log_file);
            //openethereum --config <config> account import <account>
            Command::new("test_res/openethereum_with_secretstore")
                .arg("--config")
                .arg(config.to_str().unwrap())
                .arg("account")
                .arg("import")
                .arg(account.to_str().unwrap())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();

            info!("Imported account {}", account.display());
            std::thread::sleep(Duration::from_secs(1));

            // then start
            //openethereum --config <config>
            Command::new("test_res/openethereum_with_secretstore")
                .arg("--config")
                .arg(config.to_str().unwrap())
                .arg("--logging=info")
                .spawn()
                .unwrap()
        }

        pub struct SecretStoresHandle {
            pub contract: Address,
            handles: Vec<Child>,
            // when dropped, deletes directories
            _dirs: Vec<TempDir>
        }

        impl Drop for SecretStoresHandle {
            fn drop(&mut self) {
                for child in &mut self.handles {
                    // ignore any errors
                    let _ = child.kill();
                }
            }
        }

        async fn wait_until_ready(log_file: &Path) {
            let file = tokio::fs::File::open(log_file).await.unwrap();
            let mut lines = BufReader::new(file).lines();
            loop {
                match lines.next().await {
                    Some(Ok(line)) => if line.contains("Public node URL") {
                        return
                    }else{
                        ()
                    },
                    Some(Err(err)) => panic!("Error: {}", err),
                    None => (), // we wait until more log output is available
                }
            }
        }

        pub async fn start_secret_stores(working_dir: &Path) -> SecretStoresHandle {
            fn start_s1(base_path: &Path, contract: Option<String>, log_file: PathBuf) -> impl Future<Output=Child> {
                let c1 = Config {
                    base_path: base_path.to_path_buf(),
                    rpc_port: 8545,
                    network_port: 30303,
                    enode_addresses: vec![
                        ("aa8f59250f9007b4da4f5b2943da247ecc6fece0ed699ace4e0807f49a74acfe0c3b98bef2adaf64547c5cb88db3c0d2d6651cd16b88fbd4fb00cc648640e07a".to_string(), 30303)
                    ],
                    self_secret: "f2662c594e0301b07009102cf5e7f4fc0b14ef51".to_string(),
                    acl_contract: contract.unwrap_or("none".to_string()),
                    secret_store_http_port: 8010,
                    secret_store_port: 8040,
                    publickeys: vec![
                        ("bc34947b355b213094e4f1b027ced9eeabd3c11921b34f88d51173c6e6cade1af78ad4efd6202b17f5ccea01188fc2646ffc8b45da0d88ff832dcf6fd704ee82".to_string(), 8040),
                        ("ddebae99f13a619b6408f363663bb0349aa98a80714dfd126b781cd5a311b384453f3d4ba276eab60835c6653642e24fa9941b77582aea3997399472f827722e".to_string(), 8041),
                        ("2ae507188ea88bef9ce95cd6d8c64cc632ffe73a2b0094841f444c493122a1fae75667324cf531a7c95f962abbc83c58ec498053bfb90bd2705f80453e12e094".to_string(), 8042),
                    ],
                    password: PathBuf::from("test_res/config/s1.pwd")
                };
                start_secret_store(
                    c1,
                    Path::new("test_res/config/s1-account.json"),
                    log_file
                )
            }

            fn start_s2(base_path: &Path, contract: Option<String>, log_file: PathBuf) -> impl Future<Output=Child> {
                let c2 = Config {
                    base_path: base_path.to_path_buf(),
                    rpc_port: 8546,
                    network_port: 30304,
                    enode_addresses: vec![
                        ("aa8f59250f9007b4da4f5b2943da247ecc6fece0ed699ace4e0807f49a74acfe0c3b98bef2adaf64547c5cb88db3c0d2d6651cd16b88fbd4fb00cc648640e07a".to_string(), 30303)
                    ],
                    self_secret: "e99f1743bacb18389f7626e058b5d4ebaa3002de".to_string(),
                    acl_contract: contract.unwrap_or("none".to_string()),
                    secret_store_http_port: 8011,
                    secret_store_port: 8041,
                    publickeys: vec![
                        ("bc34947b355b213094e4f1b027ced9eeabd3c11921b34f88d51173c6e6cade1af78ad4efd6202b17f5ccea01188fc2646ffc8b45da0d88ff832dcf6fd704ee82".to_string(), 8040),
                        ("ddebae99f13a619b6408f363663bb0349aa98a80714dfd126b781cd5a311b384453f3d4ba276eab60835c6653642e24fa9941b77582aea3997399472f827722e".to_string(), 8041),
                        ("2ae507188ea88bef9ce95cd6d8c64cc632ffe73a2b0094841f444c493122a1fae75667324cf531a7c95f962abbc83c58ec498053bfb90bd2705f80453e12e094".to_string(), 8042),
                    ],
                    password: PathBuf::from("test_res/config/s2.pwd")
                };
                start_secret_store(
                    c2,
                    Path::new("test_res/config/s2-account.json"),
                    log_file
                )
            }

            fn start_s3(base_path: &Path, contract: Option<String>, log_file: PathBuf) -> impl Future<Output=Child> {
                let c3 = Config {
                    base_path: base_path.to_path_buf(),
                    rpc_port: 8547,
                    network_port: 30305,
                    enode_addresses: vec![
                        ("aa8f59250f9007b4da4f5b2943da247ecc6fece0ed699ace4e0807f49a74acfe0c3b98bef2adaf64547c5cb88db3c0d2d6651cd16b88fbd4fb00cc648640e07a".to_string(), 30303)
                    ],
                    self_secret: "9fb7c4be5ab2bd2819bc0575ea14d1670804307b".to_string(),
                    acl_contract: contract.unwrap_or("none".to_string()),
                    secret_store_http_port: 8012,
                    secret_store_port: 8042,
                    publickeys: vec![
                        ("bc34947b355b213094e4f1b027ced9eeabd3c11921b34f88d51173c6e6cade1af78ad4efd6202b17f5ccea01188fc2646ffc8b45da0d88ff832dcf6fd704ee82".to_string(), 8040),
                        ("ddebae99f13a619b6408f363663bb0349aa98a80714dfd126b781cd5a311b384453f3d4ba276eab60835c6653642e24fa9941b77582aea3997399472f827722e".to_string(), 8041),
                        ("2ae507188ea88bef9ce95cd6d8c64cc632ffe73a2b0094841f444c493122a1fae75667324cf531a7c95f962abbc83c58ec498053bfb90bd2705f80453e12e094".to_string(), 8042),
                    ],
                    password: PathBuf::from("test_res/config/s3.pwd")
                };
                start_secret_store(
                    c3,
                    Path::new("test_res/config/s3-account.json"),
                    log_file
                )
            }

            let log_s1 = working_dir.join("s1.log");
            let log_s2 = working_dir.join("s2.log");
            let log_s3 = working_dir.join("s3.log");

            let tmp1 = TempDir::new("s1").unwrap();
            let tmp2 = TempDir::new("s2").unwrap();
            let tmp3 = TempDir::new("s3").unwrap();
            let ss1 = start_s1(tmp1.path(), None, log_s1.clone());
            let ss2 = start_s2(tmp2.path(), None, log_s2.clone());
            let ss3 = start_s3(tmp3.path(), None, log_s3.clone());

            let (mut child1, mut child2, mut child3) = join3(ss1, ss2, ss3).await;
            info!("All handles created");
            // wait until ready
            join3(
                wait_until_ready(&log_s1),
                wait_until_ready(&log_s2),
                wait_until_ready(&log_s3),
            ).await;
            info!("Secret stores ready");

            // generate joint signature key
            let (joint_signature_public, joint_signature_id) = {
                let client = HttpClient::new();
                let request = Request::builder()
                    .method("POST")
                    .uri("http://127.0.0.1:8010/joint_signature_key")
                    .body(Body::empty())
                    .unwrap();
                let response = client.request(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let mut body = response.into_body();
                let mut response_data= Vec::new();
                while let Some(next) = body.data().await {
                    response_data.extend_from_slice(&next.unwrap());
                }
                let response_data = String::from_utf8(response_data).unwrap();
                let joint_signature_public = H512::from_str(&response_data[3..response_data.len()-1]).unwrap();
                (joint_signature_public, H256([0xffu8; 32]))
            };
            let joint_signature_address = parity_crypto::publickey::public_to_address(&joint_signature_public);
            info!("Generated joint signature key {} with id {}", joint_signature_public, joint_signature_id);

            // generate contract
            let contract_address = {
                let transport = web3::transports::http::Http::new("http://127.0.0.1:8545").unwrap();
                let web3 = web3::Web3::new(transport);
                let abi = std::fs::read("test_res/contracts/SecretStore.abi").unwrap();
                let bytecode = std::fs::read_to_string("test_res/contracts/SecretStore.bin").unwrap();
                let password = std::fs::read_to_string("test_res/config/s1.pwd").unwrap();
                let password = password.trim_end().to_string();
                info!("Uploading SecretStore Contract");
                let contract = web3::contract::Contract::deploy(web3.eth(), &abi).unwrap()
                    .confirmations(0)
                    .poll_interval(Duration::from_secs(1))
                    .options(web3::contract::Options {
                        gas: Some(U256([0x26fb33,0,0,0])),
                        gas_price: None,
                        value: None,
                        nonce: None,
                        condition: None
                    })
                    .sign_and_execute(bytecode, (Token::Address(joint_signature_address), Token::FixedBytes(joint_signature_id.0.to_vec())), "f2662c594e0301b07009102cf5e7f4fc0b14ef51".parse().unwrap(), &password)
                    .unwrap()
                    .await
                    .unwrap();
                contract.address()
            };
            info!("Uploaded acl contract at {:x}", contract_address);

            // restart secret stores with contract address reference
            let _ = child1.kill();
            let _ = child2.kill();
            let _ = child3.kill();
            // remove old log files
            std::fs::remove_file(&log_s1).unwrap();
            std::fs::remove_file(&log_s2).unwrap();
            std::fs::remove_file(&log_s3).unwrap();
            std::thread::sleep(Duration::from_secs(2));


            let address = format!("{:x}", contract_address);
            let ss1 = start_s1(tmp1.path(), Some(address.clone()), log_s1.clone());
            let ss2 = start_s2(tmp2.path(), Some(address.clone()), log_s2.clone());
            let ss3 = start_s3(tmp3.path(), Some(address.clone()), log_s3.clone());

            let (child1, child2, child3) = join3(ss1, ss2, ss3).await;
            join3(
                wait_until_ready(&log_s1),
                wait_until_ready(&log_s2),
                wait_until_ready(&log_s3),
            ).await;

            SecretStoresHandle {
                contract: contract_address,
                handles: vec![child1, child2, child3],
                _dirs: vec![tmp1, tmp2, tmp3]
            }
        }
    }

    async fn client(args: Vec<String>) {
        let program_name = "client".to_string();
        super::client_main(vec![program_name].into_iter().chain(args.into_iter())).await
            .unwrap()
    }

    async fn client_with_res(args: Vec<String>) -> Result<(), Error> {
        let program_name = "client".to_string();
        super::client_main(vec![program_name].into_iter().chain(args.into_iter())).await
    }

    async fn do_client_access_document() {
        let tmpdir = TempDir::new("").unwrap();
        info!("Starting 3 secret store nodes");
        let secret_stores = setup::start_secret_stores(tmpdir.path()).await;
        info!("Started");

        // create the config file
        let config = tmpdir.path().join(Path::new("config.json"));
        std::fs::write(&config, format!(r#"{{"secret_store": "127.0.0.1:8010", "eth_client": "127.0.0.1:8545", "acl_contract": "{:x}"}}"#, secret_stores.contract)).unwrap();

        info!("Creating policy");
        // create a policy
        let policy = tmpdir.path().join(Path::new("policy.json"));
        client(vec![
            "create-policy".to_string(),
            "--circuit".to_string(),
            "test_res/circuit_root.zok".to_string(), // circuit
            "--zok-stdlib".to_string(),
            "test_res/stdlib/".to_string(), // zok-stdlib
            "--threshold".to_string(),
            "2".to_string(), // threshold
            "--output".to_string(),
            policy.to_str().unwrap().to_string(), // policy output
            "64".to_string() // public input, here: square
        ]).await;

        // there is now a policy file
        assert!(policy.is_file());

        let document = "This is a very top secret document";
        let id: H256 = "14f715d0d66977c8a4706d07e8e658e4980adde11e32235ec43e647043c5be3d".parse().unwrap();

        let document_path = tmpdir.path().join(Path::new("document"));
        std::fs::write(&document_path, document).unwrap();

        let encrypted_doc = tmpdir.path().join(Path::new("encrypted"));
        let provingkey = tmpdir.path().join(Path::new("proving.key"));
        info!("Uploading document");
        client(vec![
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "upload".to_string(),
            "--document".to_string(),
            document_path.to_str().unwrap().to_string(), // document
            "--policy".to_string(),
            policy.to_str().unwrap().to_string(), // policy file
            "--encrypted-document".to_string(),
            encrypted_doc.to_str().unwrap().to_string(), // encrypted document
            "--proving-key".to_string(),
            provingkey.to_str().unwrap().to_string(), // proving key
        ]).await;

        // there now is a encrypted document & proving key
        assert!(encrypted_doc.is_file());
        assert!(provingkey.is_file());

        info!("Accessing document");
        let decrypted_document = tmpdir.path().join(Path::new("decrypted"));
        client(vec![
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "access".to_string(),
            "--document-id".to_string(),
            format!("{:x}", id), // document id
            "--policy".to_string(),
            policy.to_str().unwrap().to_string(), // policy file
            "--encrypted-document".to_string(),
            encrypted_doc.to_str().unwrap().to_string(), // encrypted document
            "--proving-key".to_string(),
            provingkey.to_str().unwrap().to_string(), // proving key
            "--decrypted-document".to_string(),
            decrypted_document.to_str().unwrap().to_string(), // decrypted document
            "8".to_string(), // witness arg
            "64".to_string() // witness arg
        ]).await;

        // there is a decrypted document
        assert!(decrypted_document.is_file());
        // with the same content
        assert_eq!(&std::fs::read_to_string(&decrypted_document).unwrap(), document);


        info!("Shutdown");
        drop(secret_stores);
        info!("Killed secret store nodes");
    }

    async fn do_client_accesses_unknown_document() {
        let tmpdir = TempDir::new("").unwrap();
        info!("Starting 3 secret store nodes");
        let secret_stores = setup::start_secret_stores(tmpdir.path()).await;
        info!("Started");

        // create the config file
        let config = tmpdir.path().join(Path::new("config.json"));
        std::fs::write(&config, format!(r#"{{"secret_store": "127.0.0.1:8010", "eth_client": "127.0.0.1:8545", "acl_contract": "{:x}"}}"#, secret_stores.contract)).unwrap();

        // create a policy (using test_res/root_policy.json)
        let policy = tmpdir.path().join(Path::new("policy.json"));
        std::fs::write(&policy, std::fs::read("test_res/root_policy.json").unwrap()).unwrap();

        let setup_keypair = read_policy(&policy).unwrap()
            .setup().unwrap();
        let provingkey = tmpdir.path().join("proving.key");
        std::fs::write(&provingkey, &setup_keypair.pk).unwrap();

        // create a fake encrypted document
        let encrypted: Vec<u8> = "fd92e25ab3b215ed8d67c670e0ce44e1b2cb73d9437b73b21871dcf80cd5e4ee05d59241395fb1b588132869ea88a642a33f0ff62db5492112313af0".from_hex()
            .unwrap();
        let encrypted_path = tmpdir.path().join("encrypted");
        std::fs::write(&encrypted_path, &encrypted).unwrap();

        info!("Accessing document");
        let decrypted_document = tmpdir.path().join(Path::new("decrypted"));
        let res = client_with_res(vec![
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "access".to_string(),
            "--document-id".to_string(),
            "14f715d0d66977c8a4706d07e8e658e4980adde11e32235ec43e647043c5be3d".to_string(), // document id
            "--policy".to_string(),
            policy.to_str().unwrap().to_string(), // policy file
            "--encrypted-document".to_string(),
            encrypted_path.to_str().unwrap().to_string(), // encrypted document
            "--proving-key".to_string(),
            provingkey.to_str().unwrap().to_string(), // proving key
            "--decrypted-document".to_string(),
            decrypted_document.to_str().unwrap().to_string(), // decrypted document
            "8".to_string(), // witness arg
            "64".to_string() // witness arg
        ]).await;
        match res {
            Err(Error::DocumentNotFound(id)) => assert_eq!(id, "14f715d0d66977c8a4706d07e8e658e4980adde11e32235ec43e647043c5be3d".parse().unwrap()), //ok
            _ => panic!("Expected document not found error, got {:?}", res)
        };
        drop(secret_stores);
    }

    async fn do_client_accesses_document_with_invalid_proof() {
        let tmpdir = TempDir::new("").unwrap();
        info!("Starting 3 secret store nodes");
        let secret_stores = setup::start_secret_stores(tmpdir.path()).await;
        info!("Started");

        // create the config file
        let config = tmpdir.path().join(Path::new("config.json"));
        std::fs::write(&config, format!(r#"{{"secret_store": "127.0.0.1:8010", "eth_client": "127.0.0.1:8545", "acl_contract": "{:x}"}}"#, secret_stores.contract)).unwrap();

        let document = "This is a very top secret document";
        let id: H256 = "14f715d0d66977c8a4706d07e8e658e4980adde11e32235ec43e647043c5be3d".parse().unwrap();

        let document_path = tmpdir.path().join(Path::new("document"));
        std::fs::write(&document_path, document).unwrap();
        let encrypted_doc = tmpdir.path().join(Path::new("encrypted"));
        let provingkey = tmpdir.path().join(Path::new("proving.key"));
        {
            info!("Creating policy");
            // create a policy
            let policy = tmpdir.path().join(Path::new("policy.json"));
            client(vec![
                "create-policy".to_string(),
                "--circuit".to_string(),
                "test_res/circuit_root.zok".to_string(), // circuit
                "--zok-stdlib".to_string(),
                "test_res/stdlib/".to_string(), // zok-stdlib
                "--threshold".to_string(),
                "2".to_string(), // threshold
                "--output".to_string(),
                policy.to_str().unwrap().to_string(), // policy output
                "64".to_string() // public input, here: square
            ]).await;

            // there is now a policy file
            assert!(policy.is_file());

            info!("Uploading document");
            client(vec![
                "--config".to_string(),
                config.to_str().unwrap().to_string(),
                "upload".to_string(),
                "--document".to_string(),
                document_path.to_str().unwrap().to_string(), // document
                "--policy".to_string(),
                policy.to_str().unwrap().to_string(), // policy file
                "--encrypted-document".to_string(),
                encrypted_doc.to_str().unwrap().to_string(), // encrypted document
                "--proving-key".to_string(),
                provingkey.to_str().unwrap().to_string(), // proving key
            ]).await;
        }

        // there now is a encrypted document & proving key
        assert!(encrypted_doc.is_file());
        assert!(provingkey.is_file());

        // create a policy of the same type but with different public inputs
        let policy2 = tmpdir.path().join(Path::new("policy2.json"));
        client(vec![
            "create-policy".to_string(),
            "--circuit".to_string(),
            "test_res/circuit_root.zok".to_string(), // circuit
            "--zok-stdlib".to_string(),
            "test_res/stdlib/".to_string(), // zok-stdlib
            "--threshold".to_string(),
            "2".to_string(), // threshold
            "--output".to_string(),
            policy2.to_str().unwrap().to_string(), // policy output
            "30846916".to_string() // public input, here: square
        ]).await;

        info!("Accessing document");
        let decrypted_document = tmpdir.path().join(Path::new("decrypted"));
        let res = client_with_res(vec![
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "access".to_string(),
            "--document-id".to_string(),
            format!("{:x}", id), // document id
            "--policy".to_string(),
            policy2.to_str().unwrap().to_string(), // policy file
            "--encrypted-document".to_string(),
            encrypted_doc.to_str().unwrap().to_string(), // encrypted document
            "--proving-key".to_string(),
            provingkey.to_str().unwrap().to_string(), // proving key
            "--decrypted-document".to_string(),
            decrypted_document.to_str().unwrap().to_string(), // decrypted document
            "5554".to_string(), // witness arg
            "30846916".to_string() // witness arg
        ]).await;

        match res {
            Err(Error::AccessDenied(document_id)) => assert_eq!(document_id, id),
            _ => panic!("Expected access denied error, got: {:?}", res)
        };

        drop(secret_stores);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore = "CI cannot use pre-built openethereum binary")]
    fn client_access() {

        simple_logger::init_with_level(log::Level::Info).unwrap();

        info!("client_access_document");
        tokio_test::block_on(do_client_access_document());
        // give teardown enough time
        std::thread::sleep(std::time::Duration::from_secs(1));

        info!("client_accesses_unknown_document");
        tokio_test::block_on(do_client_accesses_unknown_document());
        // give teardown enough time
        std::thread::sleep(std::time::Duration::from_secs(1));

        info!("client_accesses_document_with_invalid_proof");
        tokio_test::block_on(do_client_accesses_document_with_invalid_proof());
    }

    #[test]
    fn parses_config_file_correctly() {
        let config = parse_config_file(Path::new("test_res/config/client-config.json"))
            .unwrap();
        assert_eq!(config.acl_contract_address, "83e9de79853ec65e4e221646d8253f18de38fa71".parse().unwrap());
        assert_eq!(config.eth_client_address, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.eth_client_port, 8545);
        assert_eq!(config.secret_store_node_address, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.secret_store_node_port, 8010);
    }
}
