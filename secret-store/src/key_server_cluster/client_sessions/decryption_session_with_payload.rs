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

use crypto::publickey::{Secret, Signature};
use ethereum_types::{Address, H256, U256, Public};
use futures::Oneshot;
use key_server_cluster::cluster::Cluster;
use key_server_cluster::cluster_sessions::{
    ClusterSession, CompletionSignal, SessionIdWithSubSession,
};
use key_server_cluster::jobs::consensus_session::{
    ConsensusSession, ConsensusSessionParams, ConsensusSessionState,
};
use key_server_cluster::jobs::job_session::JobTransport;
use key_server_cluster::jobs::key_access_payload_job::{
    KeyAccessWithPayloadJob, KeyAccessWithPayloadPartialJobRequest,
};
use key_server_cluster::client_sessions::signing_session_ecdsa::{SessionImpl as SigningSession, SessionParams as SigningSessionParams};
use key_server_cluster::message::{ConfirmConsensusInitialization, ConsensusMessageWithPayload, DecryptionSessionError, InitializeConsensusSessionWithPayload, Message, DecryptionWithPayloadMessage, EcdsaSigningMessage, KeyVersionNegotiationMessage, ConsensusMessage, EcdsaSigningConsensusMessage, EcdsaPartialSignature, EcdsaSigningSessionCompleted, DecryptionWithPayloadKeyVersionNegotiation, EcdsaSigningConsensusWithPayloadMessage, InitializeConsensusSession, EcdsaSigningWithPayloadMessage, DecryptionConsensusMessage, DecryptionSessionCompleted, EcdsaRequestPartialSignature, RequestProxyDecryption, ProxyDecryption};
use key_server_cluster::{
    AclStorage, DocumentKeyShare, Error, NodeId, Requester, SessionId,
    SessionMeta,
};
use key_server_cluster::admin_sessions::key_version_negotiation_session::{
    SessionImpl as KeyVersionNegotiationSession,
    SessionParams as KeyVersionNegotiationSessionParams,
    FastestResultComputer
};
use key_server_cluster::admin_sessions::{key_version_negotiation_session, ShareChangeSessionMeta};
use traits::JOINT_SIGNATURE_KEY_ID;
use parking_lot::{Mutex, MutexGuard};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::ops::{DerefMut, Deref};
use serialization::{SerializableU256, SerializableH256};
use std::{fmt, time};
use blockchain::{EthClient, EstimateGasArgs};
use transaction_signature::RawTransaction;
use key_server_cluster::jobs::proxy_decryption_job::{ProxyDecryptionJob, ProxyDecryptionJobRequest};
use key_server_cluster::math::PartialDecryptionShare;

/// Distributed decryption session (accepts a payload that is forwarded to the ACL-contract)
/// Based on "ECDKG: A Distributed Key Generation Protocol Based on Elliptic Curve Discrete Logarithm" paper:
/// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.124.4128&rep=rep1&type=pdf
/// Brief overview:
/// 1) initialization: master node (which has received request for decrypting the secret) requests all other nodes to decrypt the secret
/// 2) ACL check: all nodes which have received the request are querying ACL-contract to check if requestor has access to the document
/// 3) partial decryption: every node which has successfully checked access for the requester do a partial decryption
/// 4) decryption: master node receives all partial decryptions of the secret and restores the secret
pub struct SessionImpl {
    /// Session core.
    core: SessionCore,
    /// Session data.
    data: Mutex<SessionState>,
}

pub struct SessionCreationData {
    pub requester: Requester,
    pub payload: Vec<U256>,
}

/// Immutable session data.
struct SessionCore {
    /// Session metadata.
    pub meta: SessionMeta,
    /// Decryption session access key.
    pub access_key: Secret,
    /// Key share.
    pub decryption_key_share: DocumentKeyShare,
    // Signing key share
    pub signing_key_share: DocumentKeyShare,
    /// Cluster which allows this node to send messages to other nodes in the cluster.
    pub cluster: Arc<dyn Cluster>,

    acl_storage: Arc<dyn AclStorage>,
    /// Session-level nonce.
    pub nonce: u64,
    /// Session completion signal.
    pub completed: CompletionSignal<ProxyEncryptedDocumentKey>,

    pub log_contract_address: Address,

    eth_client: Arc<dyn EthClient>
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProxyEncryptedDocumentKey {
    pub common_point: Public,
    pub encrypted_point: Public
}

/// Decryption consensus session type.
type ProxyDecryptionConsensusSession = ConsensusSession<
    KeyAccessWithPayloadJob,
    DecryptionConsensusTransport,
    ProxyDecryptionJob,
    ProxyDecryptionJobTransport,
>;
// /// Broadcast decryption job session type.
// type BroadcastDecryptionJobSession = JobSession<DecryptionJob, DecryptionJobTransport>;

// /// Mutable session data.
// struct SessionData {
//     state: SessionState
// }

trait SessionStateErrorHandler {
    /// Passes `error` from `node` to sub sessions in the current state
    /// returns a new error that is used instead for `SessionState::Failed`, if any
    fn on_session_error(&mut self, core: &SessionCore, node: &NodeId, error: Error) -> Option<Error>;
    /// Informs sub sessions of the current state that the session stalled
    /// returns a new error that is used instead for `SessionState::Failed`, if any
    fn on_session_timeout(&mut self, core: &SessionCore) -> Option<Error>;
}

enum SessionState {
    Master(MasterState),
    Slave(SlaveState),
    Failed(Error)
}

enum MasterState {
    Created(SessionMasterStateCreated),
    KeyVersionNegotiation(SessionMasterStateKeyVersionNegotiation),
    JointSignature(SessionMasterStateJointSignature),
    DecryptionConsensus(SessionMasterStateDecryptionConsensus),
    Decryption(SessionMasterStateDecryption),
    Completed(ProxyEncryptedDocumentKey)
}

enum SlaveState {
    Created(SessionSlaveStateCreated),
    KeyVersionNegotiation(SessionSlaveStateKeyVersionNegotiation),
    JointSignature(SessionSlaveStateJointSignature),
    DecryptionConsensus(SessionSlaveStateDecryptionConsensus),
    Decryption(SessionSlaveStateDecryption),
    WaitingForCompletion(SessionSlaveStateWaitingForCompletion),
    Completed
}

struct SessionMasterStateCreated { requester: Public, authorization_payload: Vec<U256> }
struct SessionMasterStateKeyVersionNegotiation { requester: Public, authorization_payload: Vec<U256>, signing_key_negotiation_session: KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, decryption_key_negotiation_session: KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, transport_buf: Arc<Mutex<KeyVersionNegotiationBuffer>>}
struct SessionMasterStateJointSignature {requester: Public, authorization_payload: Vec<U256>, decryption_key_version: H256, signature_session: SigningSession, transaction: H256 }
struct SessionMasterStateDecryptionConsensus{requester: Public, key_access_session: ProxyDecryptionConsensusSession, decryption_key_version: H256 }
struct SessionMasterStateDecryption{requester: Public, key_access_session: ProxyDecryptionConsensusSession }

struct SessionSlaveStateCreated {}
struct SessionSlaveStateKeyVersionNegotiation { signing_key_negotiation_session: KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, decryption_key_negotiation_session: KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, transport_buf: Arc<Mutex<KeyVersionNegotiationBuffer>>}
struct SessionSlaveStateJointSignature {requester: Public, authorization_payload: Vec<U256>, signature_session: SigningSession, transaction: RawTransaction }
struct SessionSlaveStateDecryptionConsensus{requester: Public, authorization_payload: Vec<U256>, key_access_session: ProxyDecryptionConsensusSession, transaction: H256}
struct SessionSlaveStateDecryption{requester: Public, key_access_session: ProxyDecryptionConsensusSession, decryption_key_version: H256 }
struct SessionSlaveStateWaitingForCompletion {}

enum SessionStateResult {
    State(SessionState),
    RecoverableError(SessionState, Error),
    Error(Error),
}

impl SessionState {
    pub fn requester(&self) -> Option<Requester> {
        let public = match self {
            SessionState::Master(MasterState::Created(SessionMasterStateCreated{requester, ..}))
            | SessionState::Master(MasterState::KeyVersionNegotiation(SessionMasterStateKeyVersionNegotiation{requester, ..}))
            | SessionState::Master(MasterState::JointSignature(SessionMasterStateJointSignature{requester, ..}))
            | SessionState::Master(MasterState::DecryptionConsensus(SessionMasterStateDecryptionConsensus{requester, ..}))
            | SessionState::Master(MasterState::Decryption(SessionMasterStateDecryption {requester, ..}))
            | SessionState::Slave(SlaveState::JointSignature(SessionSlaveStateJointSignature{requester, ..}))
            | SessionState::Slave(SlaveState::DecryptionConsensus(SessionSlaveStateDecryptionConsensus{requester, ..}))
            | SessionState::Slave(SlaveState::Decryption(SessionSlaveStateDecryption{requester, ..})) =>
                requester,
            _ => return None
        };
        Some(Requester::Public(public.clone()))
    }

    fn change_state<F>(state: &mut MutexGuard<SessionState>, change_state_fun: F) -> Result<(), Error>
        where F: FnOnce(SessionState) -> SessionStateResult {
        // temporarily replace state with a dummy, here SessionState::Failed
        let old_state = std::mem::replace(state.deref_mut(), SessionState::Failed(Error::Internal("Session state changing was interrupted".into())));
        let old_state_str = format!("{:?}", &old_state);
        let (new_state, error) = match change_state_fun(old_state) {
            SessionStateResult::State(state) => (state, None),
            SessionStateResult::RecoverableError(state, error) => (state, Some(error)),
            SessionStateResult::Error(error) => (SessionState::Failed(error.clone()), Some(error)),
        };
        debug!("Changing state from {} to {:?}", old_state_str, &new_state);
        std::mem::replace(state.deref_mut(), new_state);
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl SessionStateErrorHandler for SessionState {
    fn on_session_error(&mut self, core: &SessionCore, node: &NodeId, error: Error) -> Option<Error> {
        match self {
            SessionState::Master(master_state) => master_state.on_session_error(core, node, error),
            SessionState::Slave(slave_state) => slave_state.on_session_error(core, node, error),
            SessionState::Failed(_) => None,
        }
    }

    fn on_session_timeout(&mut self, core: &SessionCore) -> Option<Error> {
        match self {
            SessionState::Master(master_state) => master_state.on_session_timeout(core),
            SessionState::Slave(slave_state) => slave_state.on_session_timeout(core),
            SessionState::Failed(_) => None,
        }
    }
}

fn on_session_error(
    transport_buf: &Arc<Mutex<KeyVersionNegotiationBuffer>>,
    core: &SessionCore,
    signing_key_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>,
    decryption_key_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>,
    node: &NodeId, error: Error
) -> Option<Error> {
    signing_key_negotiation.on_session_error(node, error.clone());
    decryption_key_negotiation.on_session_error(node, error.clone());
    // send buffered errors
    let _ = transport_buf.lock().send_to_cluster(core.cluster.as_ref());
    signing_key_negotiation.result().or(decryption_key_negotiation.result())
        .map(|res| res.err()).flatten()
}

fn on_session_timeout(
    transport_buf: &Arc<Mutex<KeyVersionNegotiationBuffer>>,
    core: &SessionCore,
    signing_key_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>,
    decryption_key_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>
) -> Option<Error> {
    signing_key_negotiation.on_session_timeout();
    decryption_key_negotiation.on_session_timeout();
    // send buffered errors
    let _ = transport_buf.lock().send_to_cluster(core.cluster.as_ref());
    signing_key_negotiation.result().or(decryption_key_negotiation.result())
        .map(|res| res.err()).flatten()
}

fn process_error(state: SessionState, error: Error) -> SessionStateResult {
    match error {
        Error::TooEarlyForRequest => SessionStateResult::RecoverableError(state, error),
        _ => SessionStateResult::Error(error),
    }
}

impl SessionStateErrorHandler for MasterState {
    fn on_session_error(&mut self, core: &SessionCore, node: &NodeId, error: Error) -> Option<Error> {
        match self {
            MasterState::KeyVersionNegotiation(key_negotiation) =>
                on_session_error(&key_negotiation.transport_buf, core, &key_negotiation.signing_key_negotiation_session, &key_negotiation.decryption_key_negotiation_session, node, error),
            MasterState::JointSignature(joint_signature) => {
                joint_signature.signature_session.on_session_error(node, error);
                joint_signature.signature_session.result().map(|res| res.err()).flatten()
            },
            MasterState::Decryption(SessionMasterStateDecryption {ref mut key_access_session, ..})
            | MasterState::DecryptionConsensus(SessionMasterStateDecryptionConsensus {ref mut key_access_session, ..}) =>
                key_access_session.on_node_error(node, error).err(),
            MasterState::Created(_) | MasterState::Completed(_) => None,
        }
    }

    fn on_session_timeout(&mut self, core: &SessionCore) -> Option<Error> {
        match self {
            MasterState::KeyVersionNegotiation(key_negotiation) =>
                on_session_timeout(&key_negotiation.transport_buf, core, &key_negotiation.signing_key_negotiation_session, &key_negotiation.decryption_key_negotiation_session),
            MasterState::JointSignature(joint_signature) => {
                joint_signature.signature_session.on_session_timeout();
                joint_signature.signature_session.result().map(|res| res.err()).flatten()
            },
            MasterState::Decryption(SessionMasterStateDecryption {ref mut key_access_session, ..})
            | MasterState::DecryptionConsensus(SessionMasterStateDecryptionConsensus {ref mut key_access_session, ..}) =>
                key_access_session.on_session_timeout().err(),
            MasterState::Created(_) | MasterState::Completed(_) => None,
        }
    }
}

impl SessionStateErrorHandler for SlaveState {
    fn on_session_error(&mut self, core: &SessionCore, node: &NodeId, error: Error) -> Option<Error> {
        match self {
            SlaveState::KeyVersionNegotiation(key_negotiation) =>
                on_session_error(&key_negotiation.transport_buf, core, &key_negotiation.signing_key_negotiation_session, &key_negotiation.decryption_key_negotiation_session, node, error),
            SlaveState::JointSignature(joint_signature) => {
                joint_signature.signature_session.on_session_error(node, error);
                joint_signature.signature_session.result().map(|res| res.err()).flatten()
            },
            SlaveState::Decryption(SessionSlaveStateDecryption {ref mut key_access_session, ..})
            | SlaveState::DecryptionConsensus(SessionSlaveStateDecryptionConsensus {ref mut key_access_session, ..}) =>
                key_access_session.on_node_error(node, error).err(),
            SlaveState::Created(_) | SlaveState::WaitingForCompletion(_) | SlaveState::Completed => None,
        }
    }

    fn on_session_timeout(&mut self, core: &SessionCore) -> Option<Error> {
        match self {
            SlaveState::KeyVersionNegotiation(key_negotiation) =>
                on_session_timeout(&key_negotiation.transport_buf, core, &key_negotiation.signing_key_negotiation_session, &key_negotiation.decryption_key_negotiation_session),
            SlaveState::JointSignature(joint_signature) => {
                joint_signature.signature_session.on_session_timeout();
                joint_signature.signature_session.result().map(|res| res.err()).flatten()
            },
            SlaveState::Decryption(SessionSlaveStateDecryption {ref mut key_access_session, ..})
            | SlaveState::DecryptionConsensus(SessionSlaveStateDecryptionConsensus {ref mut key_access_session, ..}) =>
                key_access_session.on_session_timeout().err(),
            SlaveState::Created(_) | SlaveState::WaitingForCompletion(_) | SlaveState::Completed => None,
        }
    }
}

fn flatten<T,E>(result: Result<Result<T,E>,E>) -> Result<T,E> {
    match result {
        Ok(inner) => inner,
        Err(e) => Err(e)
    }
}

fn new_key_version_negotiation_session(core: &SessionCore, transport_buf: Arc<Mutex<KeyVersionNegotiationBuffer>>, is_signing: bool, key_share: DocumentKeyShare) -> KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport> {
    KeyVersionNegotiationSession::new(KeyVersionNegotiationSessionParams {
        meta: ShareChangeSessionMeta {
            id: if is_signing {
                *JOINT_SIGNATURE_KEY_ID
            } else {
                core.meta.id.clone()
            },
            master_node_id: core.meta.master_node_id,
            self_node_id: core.meta.self_node_id,
            configured_nodes_count: core.meta.configured_nodes_count,
            connected_nodes_count: core.meta.connected_nodes_count,
        },
        sub_session: core.access_key.clone(),
        key_share: Some(key_share.clone()),
        result_computer: Arc::new(FastestResultComputer::new(core.meta.self_node_id, Some(&key_share), core.meta.configured_nodes_count, core.meta.connected_nodes_count)),
        transport: KeyVersionNegotiationSessionTransport {
            buffer: transport_buf,
            is_signing
        },
        nonce: core.nonce
    }).0
}

impl SessionMasterStateCreated {

    fn initialize_sessions(core: &SessionCore, signing_key_version_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, decryption_key_version_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, buf: &Arc<Mutex<KeyVersionNegotiationBuffer>>) -> Result<(),Error> {
        signing_key_version_negotiation.initialize(core.cluster.nodes().clone())?;
        decryption_key_version_negotiation.initialize(core.cluster.nodes().clone())?;
        buf.lock().send_to_cluster(core.cluster.as_ref())
    }
    
    pub fn initialize(self, core: &SessionCore) -> SessionStateResult {
        debug_assert_eq!(core.meta.self_node_id, core.meta.master_node_id);
        let transport_buf = Arc::new(Mutex::new(KeyVersionNegotiationBuffer::new()));
        let signing_key_version_negotiation = new_key_version_negotiation_session(core, transport_buf.clone(), true, core.signing_key_share.clone());
        let decryption_key_version_negotiation = new_key_version_negotiation_session(core, transport_buf.clone(), false, core.decryption_key_share.clone());
        // we are on master => initialize key version negotiation
        let initialization_result = Self::initialize_sessions(core, &signing_key_version_negotiation, &decryption_key_version_negotiation, &transport_buf);
        match initialization_result {
            Ok(_) => {
                if signing_key_version_negotiation.is_finished() && decryption_key_version_negotiation.is_finished() {
                    match SessionMasterStateKeyVersionNegotiation::get_key_versions(&signing_key_version_negotiation, &decryption_key_version_negotiation) {
                        Ok((signing_key_version, decryption_key_version)) => {
                            let key_version_negotiation_state = SessionMasterStateKeyVersionNegotiation {
                                requester: self.requester.clone(),
                                authorization_payload: self.authorization_payload.clone(),
                                decryption_key_negotiation_session: decryption_key_version_negotiation,
                                signing_key_negotiation_session: signing_key_version_negotiation,
                                transport_buf
                            };
                            key_version_negotiation_state.start_signing_session_from_master(core, signing_key_version, decryption_key_version)
                        },
                        Err(e) => process_error(SessionState::Master(MasterState::Created(self)), e),
                    }
                }else{
                    SessionStateResult::State(
                        SessionState::Master(MasterState::KeyVersionNegotiation(SessionMasterStateKeyVersionNegotiation {
                            requester: self.requester.clone(),
                            authorization_payload: self.authorization_payload.clone(),
                            decryption_key_negotiation_session: decryption_key_version_negotiation,
                            signing_key_negotiation_session: signing_key_version_negotiation,
                            transport_buf
                        }))
                    )
                }
            },
            Err(error) => process_error(SessionState::Master(MasterState::Created(self)), error),
        }
    }
}

impl SessionSlaveStateCreated {

    fn process_key_version_negotiation_message(
        transport_buf: &Arc<Mutex<KeyVersionNegotiationBuffer>>,
        signing_key_version_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>,
        decryption_key_version_negotiation: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>,
        sender: &NodeId,
        message: &DecryptionWithPayloadKeyVersionNegotiation,
        cluster: &dyn Cluster
    ) -> Result<(), Error> {
        signing_key_version_negotiation.process_message(sender, &message.signing_key)?;
        decryption_key_version_negotiation.process_message(sender, &message.decryption_key)?;
        transport_buf.lock().send_to_cluster(cluster)
    }

    pub fn initialize(self, core: &SessionCore, sender: &NodeId, message: &DecryptionWithPayloadKeyVersionNegotiation) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        let transport_buf = Arc::new(Mutex::new(KeyVersionNegotiationBuffer::new()));
        let signing_key_version_negotiation = new_key_version_negotiation_session(core, transport_buf.clone(), true, core.signing_key_share.clone());
        let decryption_key_version_negotiation = new_key_version_negotiation_session(core, transport_buf.clone(), false, core.decryption_key_share.clone());
        let process_message_result = Self::process_key_version_negotiation_message(&transport_buf, &signing_key_version_negotiation, &decryption_key_version_negotiation, sender, message, core.cluster.as_ref());
        match process_message_result {
            Ok(_) => {
                SessionStateResult::State(
                    SessionState::Slave(SlaveState::KeyVersionNegotiation(SessionSlaveStateKeyVersionNegotiation {
                        decryption_key_negotiation_session: decryption_key_version_negotiation,
                        signing_key_negotiation_session: signing_key_version_negotiation,
                        transport_buf
                    }))
                )
            },
            Err(error) => process_error(SessionState::Slave(SlaveState::Created(self)), error),
        }
    }
}

fn new_signing_session(core: &SessionCore, requester_public: Public, authorization_payload: Vec<U256>) -> Result<SigningSession, Error> {
    SigningSession::new(
        SigningSessionParams {
            meta: SessionMeta {
                id: *JOINT_SIGNATURE_KEY_ID,
                master_node_id: core.meta.master_node_id,
                self_node_id: core.meta.self_node_id,
                threshold: core.signing_key_share.threshold,
                configured_nodes_count: core.meta.configured_nodes_count,
                connected_nodes_count: core.meta.connected_nodes_count,
            },
            access_key: core.access_key.clone(),
            key_share: Some(core.signing_key_share.clone()),
            acl_storage: core.acl_storage.clone(),
            cluster: Arc::new(TransactionSigningTransport {
                session_id: core.meta.id.clone(),
                cluster: core.cluster.clone(),
                authorization_payload
            }),
            nonce: core.nonce,
            broadcast_signature: true // slaves receive the signature to compute the transaction hash
        },
        if core.meta.self_node_id == core.meta.master_node_id {
            Some(Requester::Public(requester_public))
        }else{
            None
        }
    )
        .map(|(session, _)| session)
}

#[derive(Clone)]
struct EncodedTransaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub address: Address,
    pub value: U256,
    pub data: Vec<u8>,
    pub chain_id: u64,
    pub encoded: Vec<u8>,
    pub signature: Option<Signature>
}


fn new_raw_transaction(core: &SessionCore, requester: Address, document_id: SessionId, authorization_payload: Vec<U256>) -> Result<RawTransaction, Error> {
    use_contract!(acl_log, "res/acl_log.json");

    let chain_id = core.eth_client.get_chain_id().map_err(|err_msg| Error::Internal(err_msg))?;
    let chain_id = chain_id.ok_or_else(|| Error::Internal(format!("EthClient returned empy chain_id")))?;
    let (encoded_function_call, _): (ethabi::Bytes, _) = acl_log::functions::log_access::call(requester, document_id, authorization_payload);
    let contract_address = &core.log_contract_address;
    let signing_address = parity_crypto::publickey::public_to_address(&core.signing_key_share.public);
    let nonce: U256 = core.eth_client.get_nonce_for_address(&signing_address).map_err(|err_msg| Error::Internal(err_msg))?;
    let gas_price: U256 = core.eth_client.get_gas_price().map_err(|err_msg| Error::Internal(err_msg))?;
    let value = U256::zero();
    let gas_limit: U256 = core.eth_client.estimate_gas(EstimateGasArgs {
        from: signing_address.clone(),
        to: Some(contract_address.clone()),
        gas: None,
        gas_price: Some(gas_price.clone()),
        value: Some(value.clone()),
        data: Some(encoded_function_call.clone()),
    }).map_err(|err_msg| Error::Internal(err_msg))?;

    Ok(RawTransaction {
        nonce,
        to: Some(contract_address.clone()),
        value,
        gas_price,
        gas: gas_limit,
        data: encoded_function_call,
        chain_id
    })
}

impl SessionMasterStateKeyVersionNegotiation {

    pub fn try_start_signing_session_from_master(self, core: &SessionCore, sender: &NodeId, message: &DecryptionWithPayloadKeyVersionNegotiation) -> SessionStateResult {
        debug_assert_eq!(core.meta.self_node_id, core.meta.master_node_id);
        let signing_key_result = self.signing_key_negotiation_session.process_message(sender, &message.signing_key);
        let decryption_key_result = self.decryption_key_negotiation_session.process_message(sender, &message.decryption_key);
        // send responses (if any)
        let send_result = self.transport_buf.lock().send_to_cluster(core.cluster.as_ref());
        let combined = signing_key_result.map(|_| decryption_key_result.map(|_| send_result));
        let combined = flatten(flatten(combined));
        match combined {
            Ok(()) => {
                if self.signing_key_negotiation_session.is_finished() && self.decryption_key_negotiation_session.is_finished() {
                    match Self::get_key_versions(&self.signing_key_negotiation_session, &self.decryption_key_negotiation_session) {
                        Ok((signing_key_version, decryption_key_version)) => self.start_signing_session_from_master(core, signing_key_version, decryption_key_version),
                        Err(e) => process_error(SessionState::Master(MasterState::KeyVersionNegotiation(self)), e),
                    }
                } else {
                    // waiting for responses, remain in this state
                    SessionStateResult::State(SessionState::Master(MasterState::KeyVersionNegotiation(self)))
                }
            },
            Err(error) => process_error(SessionState::Master(MasterState::KeyVersionNegotiation(self)), error),
        }
    }

    fn get_key_versions(signing_key_negotiation_session: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>, decryption_key_negotiation_session: &KeyVersionNegotiationSession<KeyVersionNegotiationSessionTransport>) -> Result<(H256,H256), Error> {
        match (signing_key_negotiation_session.result(), decryption_key_negotiation_session.result()) {
            (Some(Ok(Some((signing_version, _)))), Some(Ok(Some((decryption_version, _))))) => Ok((signing_version, decryption_version)),
            (Some(Ok(None)), _ ) | (None, _) => Err(Error::Internal("signing key negotiation is finished but has no result".into())),
            (_, Some(Ok(None))) | (_, None) => Err(Error::Internal("decryption key negotiation is finished but has no result".into())),
            (Some(Err(e)), _) | (_, Some(Err(e))) => {
                Err(e)
            },
        }
    }

    fn start_signing_session_from_master(self, core: &SessionCore, signing_key_version: H256, decryption_key_version: H256) -> SessionStateResult {
        fn new_joint_signature_state(state: SessionMasterStateKeyVersionNegotiation, decryption_key_version: H256, session: SigningSession, tx: H256) -> SessionMasterStateJointSignature {
            SessionMasterStateJointSignature {
                requester: state.requester,
                authorization_payload: state.authorization_payload,
                decryption_key_version: decryption_key_version,
                signature_session: session,
                transaction: tx
            }
        }

        let signing_session = new_signing_session(core, self.requester.clone(), self.authorization_payload.clone());
        match signing_session {
            Ok(session) => {
                // we are on master -> initialize
                let address = crypto::publickey::public_to_address(&self.requester);
                let tx_hash = match new_raw_transaction(core, address, core.meta.id, self.authorization_payload.clone()) {
                    Ok(tx) => tx.hash(),
                    Err(error) => return process_error(SessionState::Master(MasterState::KeyVersionNegotiation(self)), error),
                };
                match session.initialize(signing_key_version, tx_hash) {
                    Ok(()) => {
                        match session.result() {
                            Some(Ok(signature)) => new_joint_signature_state(self, decryption_key_version, session, tx_hash.clone()).complete_signing_session_and_start_decryption_consensus(core, signature),
                            Some(Err(e)) => process_error(SessionState::Master(MasterState::KeyVersionNegotiation(self)), e),
                            None => SessionStateResult::State(
                                SessionState::Master(MasterState::JointSignature(new_joint_signature_state(self, decryption_key_version, session, tx_hash.clone())))
                            )
                        }
                    },
                    Err(error) => process_error(SessionState::Master(MasterState::KeyVersionNegotiation(self)), error),
                }
            },
            Err(error) => process_error(SessionState::Master(MasterState::KeyVersionNegotiation(self)), error),
        }
    }
}

impl SessionSlaveStateKeyVersionNegotiation {

    pub fn start_signing_session_from_slave(self, core: &SessionCore, sender: &NodeId, message: &EcdsaSigningConsensusWithPayloadMessage) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(sender, &core.meta.master_node_id);
        if !self.decryption_key_negotiation_session.is_finished() || !self.signing_key_negotiation_session.is_finished() {
            return SessionStateResult::Error(Error::InvalidStateForRequest);
        }
        // let decryption_key_version = match self.decryption_key_negotiation_session.result() {
        //     Some(Ok(Some((version, _)))) => version,
        //     Some(Err(error)) => return SessionState::Failed(error),
        //     Some(Ok(None)) | None => return SessionState::Failed(Error::Internal("decryption key negotiation is finished but has no result".into()))
        // };
        match &message.message {
            ConsensusMessageWithPayload::InitializeConsensusSession(init_consensus) => {
                let requester = match Requester::from(init_consensus.requester.clone()).public(&*JOINT_SIGNATURE_KEY_ID) {
                    Ok(requester) => requester,
                    Err(err) => return SessionStateResult::Error(Error::InsufficientRequesterData(err.to_string()))
                };
                let authorization_payload: Vec<U256> = init_consensus.payload.iter().map(|x| x.0.clone()).collect();
                let signing_session = new_signing_session(core, requester.clone(), authorization_payload.clone());
                let address = crypto::publickey::public_to_address(&requester);
                let tx = match new_raw_transaction(core, address, core.meta.id, authorization_payload.clone()) {
                    Ok(tx) => tx,
                    Err(error) => return process_error(SessionState::Slave(SlaveState::KeyVersionNegotiation(self)), error)
                };
                match signing_session {
                    Ok(signing_session) => {
                        let joint_signature_state = SessionSlaveStateJointSignature {
                            requester: requester,
                            authorization_payload: authorization_payload,
                            signature_session: signing_session,
                            transaction: tx
                        };
                        joint_signature_state.process_message(sender, &EcdsaSigningWithPayloadMessage::EcdsaSigningConsensusMessage(message.clone()))
                    },
                    Err(error) => process_error(SessionState::Slave(SlaveState::KeyVersionNegotiation(self)), error),
                }

            },
            _ => SessionStateResult::Error(Error::InvalidStateForRequest)
        }
    }
}
/// `version` is Some if new_key_access_session is called by master, otherwise None
fn new_key_access_session(core: &SessionCore, key_access_job: KeyAccessWithPayloadJob, version: Option<H256>) -> Result<ProxyDecryptionConsensusSession, Error> {
    // self_node_id == master_node_id => version.is_some
    debug_assert!(core.meta.self_node_id != core.meta.master_node_id || version.is_some());
    // self_node_id != master_node_id => version.is_none
    debug_assert!(core.meta.self_node_id == core.meta.master_node_id || version.is_none());
    ConsensusSession::new(ConsensusSessionParams {
        meta: core.meta.clone(),
        consensus_executor: key_access_job,
        consensus_transport: DecryptionConsensusTransport {
            id: core.meta.id.clone(),
            access_key: core.access_key.clone(),
            nonce: core.nonce,
            origin: None,
            version: version,
            cluster: core.cluster.clone(),
        }
    })
}

trait SessionStateJointSignature where Self: std::marker::Sized {
    fn signature_session(&self) -> &SigningSession;

    fn transaction(&self) -> H256;

    fn into_session_state(self) -> SessionState;

    fn process_message(self, sender: &NodeId, message: &EcdsaSigningWithPayloadMessage) -> SessionStateResult {
        // translate back and replace session id
        let session_id: SerializableH256 = (*JOINT_SIGNATURE_KEY_ID).into();
        let message = match message.clone() {
            EcdsaSigningWithPayloadMessage::EcdsaSigningConsensusMessage(consensus_msg) => {
                let sub_message = match consensus_msg.message {
                    ConsensusMessageWithPayload::InitializeConsensusSession(init) => {
                        ConsensusMessage::InitializeConsensusSession(InitializeConsensusSession {
                            requester: init.requester,
                            version: init.version
                        })
                    },
                    ConsensusMessageWithPayload::ConfirmConsensusInitialization(confirm) => ConsensusMessage::ConfirmConsensusInitialization(confirm)
                };
                EcdsaSigningMessage::EcdsaSigningConsensusMessage(EcdsaSigningConsensusMessage {
                    session: session_id,
                    sub_session: consensus_msg.sub_session,
                    session_nonce: consensus_msg.session_nonce,
                    message: sub_message
                })
            },
            EcdsaSigningWithPayloadMessage::EcdsaSignatureNonceGenerationMessage(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaSignatureNonceGenerationMessage(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaInversionNonceGenerationMessage(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaInversionNonceGenerationMessage(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaInversionZeroGenerationMessage(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaInversionZeroGenerationMessage(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaSigningInversedNonceCoeffShare(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaSigningInversedNonceCoeffShare(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaRequestPartialSignature(m) => {
                debug_assert_eq!(&m.message_hash.0, &self.transaction());
                EcdsaSigningMessage::EcdsaRequestPartialSignature(EcdsaRequestPartialSignature {
                    session: session_id,
                    sub_session: m.sub_session,
                    session_nonce: m.session_nonce,
                    request_id: m.request_id,
                    inversed_nonce_coeff: m.inversed_nonce_coeff,
                    message_hash: self.transaction().into()// place the slave's version of the transaction hash (prevents master from signing arbitrary tx)
                })
            },
            EcdsaSigningWithPayloadMessage::EcdsaPartialSignature(_) => {
                unreachable!("this type of message is handled in SessionMasterStateJointSignature::try_complete_signing_session_and_start_decryption_consensus")
            },
            EcdsaSigningWithPayloadMessage::EcdsaSigningSessionError(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaSigningSessionError(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaSigningSessionCompleted(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaSigningSessionCompleted(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaSigningSessionDelegation(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaSigningSessionDelegation(m)
            },
            EcdsaSigningWithPayloadMessage::EcdsaSigningSessionDelegationCompleted(mut m) => {
                m.session = session_id;
                EcdsaSigningMessage::EcdsaSigningSessionDelegationCompleted(m)
            },
        };
        debug_assert_eq!(&*JOINT_SIGNATURE_KEY_ID, message.session_id());
        match self.signature_session().process_message(sender, &message) {
            Ok(()) => SessionStateResult::State(self.into_session_state()),
            Err(error) => process_error(self.into_session_state(), error),
        }
    }
}

impl SessionStateJointSignature for SessionMasterStateJointSignature {
    fn signature_session(&self) -> &SigningSession {
        &self.signature_session
    }

    fn transaction(&self) -> H256 {
        self.transaction.clone()
    }

    fn into_session_state(self) -> SessionState {
        SessionState::Master(MasterState::JointSignature(self))
    }
}

impl SessionStateJointSignature for SessionSlaveStateJointSignature {
    fn signature_session(&self) -> &SigningSession {
        &self.signature_session
    }

    fn transaction(&self) -> H256 {
        self.transaction.hash()
    }


    fn into_session_state(self) -> SessionState {
        SessionState::Slave(SlaveState::JointSignature(self))
    }
}

impl SessionMasterStateJointSignature {
    pub fn try_complete_signing_session_and_start_decryption_consensus(self, core: &SessionCore, sender: &NodeId, message: &EcdsaPartialSignature) -> SessionStateResult {
        debug_assert_eq!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(core.meta.id, *message.session);
        // replace session id
        let message = EcdsaPartialSignature {
            session: (*JOINT_SIGNATURE_KEY_ID).into(),
            sub_session: message.sub_session.clone(),
            session_nonce: message.session_nonce.clone(),
            request_id: message.request_id.clone(),
            partial_signature_s: message.partial_signature_s.clone()
        };
        match self.signature_session.process_message(sender, &EcdsaSigningMessage::EcdsaPartialSignature(message)) {
            Ok(()) => {
                if self.signature_session.is_finished() {
                    match self.signature_session.result() {
                        Some(Ok(signature)) => self.complete_signing_session_and_start_decryption_consensus(core, signature),
                        Some(Err(error)) => process_error(SessionState::Master(MasterState::JointSignature(self)), error),
                        None => SessionStateResult::Error(Error::Internal("signing session finished but has no result".into())),
                    }
                }else{
                    // waiting for more partial signatures
                    SessionStateResult::State(self.into_session_state())
                }
            },
            Err(error) => process_error(SessionState::Master(MasterState::JointSignature(self)), error),
        }
    }

    fn complete_signing_session_and_start_decryption_consensus(self, core: &SessionCore, signature: Signature) -> SessionStateResult {
        debug_assert!(parity_crypto::publickey::verify_public(&core.signing_key_share.public, &signature, &self.transaction).unwrap());
        let address = crypto::publickey::public_to_address(&self.requester);
        let tx = match new_raw_transaction(core, address, core.meta.id.clone(), self.authorization_payload.clone()) {
            Ok(tx) => tx,
            Err(e) => return process_error(SessionState::Master(MasterState::JointSignature(self)), e)
        };
        let tx_hash = match core.eth_client.submit_transaction(tx.signed(&signature)) {
            Ok(tx_hash) => tx_hash,
            Err(e) => return process_error(SessionState::Master(MasterState::JointSignature(self)), Error::Internal(e))
        };
        debug!("Master waiting for tx {:x}", tx_hash);
        // wait until transaction is mined before continue
        let call_log_fun = core.eth_client.get_transaction_by_hash(&tx_hash, time::Duration::from_secs(30))
            .map_err(|err_msg| Error::Internal(err_msg))
            .map(|_| ()); // ignore result
        let key_access_job = call_log_fun.map(|_| KeyAccessWithPayloadJob::new_on_master(core.meta.id.clone(), core.acl_storage.clone(), Requester::Public(self.requester.clone()), self.authorization_payload.clone()));
        let key_access_session = key_access_job.map(|key_access_job| new_key_access_session(core, key_access_job, Some(self.decryption_key_version)));
        let key_access_session = flatten(key_access_session);
        match key_access_session {
            Ok(mut key_access_session) => {
                // on master -> initialize session
                match key_access_session.initialize(core.cluster.nodes()) {
                    Ok(_) => {
                        let state = key_access_session.state();
                        let decryption_consensus_state = SessionMasterStateDecryptionConsensus {
                            requester: self.requester,
                            key_access_session,
                            decryption_key_version: self.decryption_key_version
                        };
                        match state {
                            ConsensusSessionState::ConsensusEstablished => decryption_consensus_state.complete_consensus_session_from_master(core),
                            _ => SessionStateResult::State(SessionState::Master(MasterState::DecryptionConsensus(decryption_consensus_state))),
                        }
                    },
                    Err(error) => process_error(SessionState::Master(MasterState::JointSignature(self)), error),
                }
            },
            Err(error) => process_error(SessionState::Master(MasterState::JointSignature(self)), error),
        }
    }
}

impl SessionSlaveStateJointSignature {
    pub fn complete_signing_session_on_slave(self, core: &SessionCore, sender: &NodeId, message: &EcdsaSigningSessionCompleted) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(sender, &core.meta.master_node_id);
        let signature = match &message.signature {
            Some(signature) => &signature.0,
            None => return process_error(SessionState::Slave(SlaveState::JointSignature(self)), Error::Internal("Master didn't send the jointly generated signature".to_string())),
        };
        debug_assert!(parity_crypto::publickey::verify_public(&core.signing_key_share.public, signature, &self.transaction())
            .expect("Master sent invalid signature"));
        let key_access_session = new_key_access_session(core, KeyAccessWithPayloadJob::new_on_slave(core.meta.id.clone(), core.acl_storage.clone()), None);
        match key_access_session {
            Ok(key_access_session) => {
                SessionStateResult::State(
                    SessionState::Slave(SlaveState::DecryptionConsensus(SessionSlaveStateDecryptionConsensus {
                        requester: self.requester,
                        authorization_payload: self.authorization_payload,
                        key_access_session,
                        transaction: self.transaction.hash_with_signature(&signature),
                    }))
                )
            },
            Err(error) => process_error(SessionState::Slave(SlaveState::JointSignature(self)), error),
        }
    }
}

impl SessionMasterStateDecryptionConsensus {

    pub fn try_complete_consensus_session_from_master(mut self, core: &SessionCore, sender: &NodeId, message: &DecryptionConsensusMessage) -> SessionStateResult {
        debug_assert_eq!(core.meta.self_node_id, core.meta.master_node_id);
        let message = match &message.message {
            ConsensusMessage::ConfirmConsensusInitialization(confirm) => confirm,
            _ => panic!("Expected confirm message for master") // TODO replace by static check
        };
        let result = self.key_access_session.on_consensus_partial_response(sender, message.is_confirmed);
        let state = result.map(|_| self.key_access_session.state());
        match state {
            Ok(ConsensusSessionState::EstablishingConsensus) => {
                // waiting for more responses
                SessionStateResult::State(
                    SessionState::Master(MasterState::DecryptionConsensus(self))
                )
            },
            Ok(ConsensusSessionState::ConsensusEstablished) => {
                self.complete_consensus_session_from_master(core)
            },
            Ok(ConsensusSessionState::Failed) => {
                // broadcast failure to end the session for every node
                let error = self.key_access_session.result().err().unwrap_or(Error::ConsensusUnreachable);
                //ignore the error
                let _ = core.cluster.broadcast(Message::DecryptionWithPayload(DecryptionWithPayloadMessage::DecryptionSessionError(DecryptionSessionError {
                    session: core.meta.id.clone().into(),
                    sub_session: core.access_key.clone().into(),
                    session_nonce: core.nonce,
                    error: error.clone(),
                })));
                SessionStateResult::Error(error)
            },
            Ok(_) => SessionStateResult::Error(Error::InvalidMessage),
            Err(error) => process_error(SessionState::Master(MasterState::DecryptionConsensus(self)), error),
        }
    }

    fn complete_consensus_session_from_master(mut self, core: &SessionCore) -> SessionStateResult {
        let decryption_job = ProxyDecryptionJob::new(core.meta.self_node_id.clone(), self.requester.clone(), core.decryption_key_share.clone(), self.decryption_key_version.clone(), core.access_key.clone());
        let decryption_job = match decryption_job {
            Ok(decryption_job) => decryption_job,
            Err(error) => return process_error(SessionState::Master(MasterState::DecryptionConsensus(self)), error),
        };
        let decryption_transport = ProxyDecryptionJobTransport {
            id: core.meta.id.clone(),
            access_key: core.access_key.clone(),
            nonce: core.nonce,
            master_node_id: core.meta.master_node_id,
            cluster: core.cluster.clone(),
        };
        let init_result = self.key_access_session.disseminate_jobs(decryption_job, decryption_transport, false);
        match init_result {
            Ok(_) => {
                let state = self.key_access_session.state();
                match state {
                    ConsensusSessionState::Finished => {
                        let result = self.key_access_session.result().unwrap();
                        SessionStateResult::State(
                            SessionState::Master(MasterState::Completed(ProxyEncryptedDocumentKey {
                                common_point: result.common_point,
                                encrypted_point: result.encrypted_point,
                            }))
                        )
                    },
                    ConsensusSessionState::Failed => {
                        let error = self.key_access_session.result().err().expect("failed consensus state");
                        process_error(SessionState::Master(MasterState::DecryptionConsensus(self)), error)
                    },
                    _ => SessionStateResult::State(
                        SessionState::Master(MasterState::Decryption(SessionMasterStateDecryption {
                            requester: self.requester,
                            key_access_session: self.key_access_session,
                        }))
                    )
                }
            },
            Err(error) => process_error(SessionState::Master(MasterState::DecryptionConsensus(self)), error),
        }
    }
}

impl SessionSlaveStateDecryptionConsensus {
    pub fn complete_consensus_session_from_slave(mut self, core: &SessionCore, sender: &NodeId, message: &DecryptionConsensusMessage) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(sender, &core.meta.master_node_id);
        let message = match &message.message {
            ConsensusMessage::InitializeConsensusSession(init) => init,
            _ => panic!("expected init message for slave") //TOOD replace by static check
        };
        // wait until transaction is mined
        debug!("Slave waiting for tx {:x}", self.transaction);
        match core.eth_client.get_transaction_by_hash(&self.transaction, time::Duration::from_secs(30)) {
            Ok(_) => (),
            Err(err) => return process_error(SessionState::Slave(SlaveState::DecryptionConsensus(self)), Error::Internal(err))
        }
        match self.key_access_session.on_consensus_partial_request(sender, KeyAccessWithPayloadPartialJobRequest {
            requester: message.requester.clone().into(),
            payload: self.authorization_payload.clone()
        }) {
            Ok(()) => {
                SessionStateResult::State(
                    SessionState::Slave(SlaveState::Decryption(SessionSlaveStateDecryption {
                        requester: self.requester,
                        key_access_session: self.key_access_session,
                        decryption_key_version: message.version.0.clone() // <-- this is the decryption key version selected by master
                    }))
                )
            },
            Err(error) => process_error(SessionState::Slave(SlaveState::DecryptionConsensus(self)), error),
        }
    }
}

impl SessionMasterStateDecryption {

    pub fn process_response(mut self, core: &SessionCore, sender: &NodeId, response: &ProxyDecryption) -> SessionStateResult {
        debug_assert_eq!(core.meta.self_node_id, core.meta.master_node_id);
        let job_response = PartialDecryptionShare {
            common_point: response.common_point.clone().into(),
            encrypted_point: response.encrypted_point.clone().into(),
            k_commitment: response.k_commitment.clone().into(),
            share_commitment: response.share_commitment.clone().into(),
            encrypted_point_commitment: response.encrypted_point_commitment.clone().into(),
            k_response: response.k_response.clone().into(),
            share_response: response.share_response.clone().into(),
        };
        let result_state = self.key_access_session.on_job_response(sender, job_response)
            .map(|_| self.key_access_session.state());
        match result_state {
            Ok(ConsensusSessionState::WaitingForPartialResults) => {
                // waiting for more responses, remain in this state
                SessionStateResult::State(
                    SessionState::Master(MasterState::Decryption(self))
                )
            },
            Ok(ConsensusSessionState::Finished) => {
                //broadcast the completion message
                let broadcast_result = core.cluster.broadcast(Message::DecryptionWithPayload(DecryptionWithPayloadMessage::DecryptionWithPayloadCompleted(DecryptionSessionCompleted {
                    session: core.meta.id.into(),
                    sub_session: core.access_key.clone().into(),
                    session_nonce: core.nonce
                })));

                match broadcast_result {
                    Ok(()) => {
                        let result = self.key_access_session.result().expect("session is in finished state");
                        let proxy_encrypted_document_key = ProxyEncryptedDocumentKey {
                            common_point: result.common_point,
                            encrypted_point: result.encrypted_point,
                        };
                        core.completed.send(Ok(proxy_encrypted_document_key.clone()));
                        SessionStateResult::State(
                            SessionState::Master(MasterState::Completed(proxy_encrypted_document_key))
                        )
                    },
                    Err(error) => SessionStateResult::Error(error),
                }


            },
            Ok(_) => process_error(SessionState::Master(MasterState::Decryption(self)), Error::InvalidStateForRequest),
            Err(error) => process_error(SessionState::Master(MasterState::Decryption(self)), error),
        }
    }
}

impl SessionSlaveStateDecryption {
    pub fn process_request(mut self, core: &SessionCore, sender: &NodeId, _request: &RequestProxyDecryption) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(sender, &core.meta.master_node_id);
        let decryption_job = ProxyDecryptionJob::new(core.meta.self_node_id,self.requester.clone(), core.decryption_key_share.clone(), self.decryption_key_version.clone(), core.access_key.clone());
        let decryption_job = match decryption_job {
            Ok(decryption_job) => decryption_job,
            Err(error) => return process_error(SessionState::Slave(SlaveState::Decryption(self)), error),
        };
        let decryption_transport = ProxyDecryptionJobTransport {
            id: core.meta.id.clone(),
            access_key: core.access_key.clone(),
            nonce: core.nonce,
            master_node_id: core.meta.master_node_id,
            cluster: core.cluster.clone(),
        };
        let job_request = ();
        match self.key_access_session.on_job_request(sender, job_request, decryption_job, decryption_transport) {
            Ok(_) => SessionStateResult::State(SessionState::Slave(SlaveState::WaitingForCompletion(SessionSlaveStateWaitingForCompletion {}))),
            Err(error) => process_error(SessionState::Slave(SlaveState::Decryption(self)), error),
        }
    }

    pub fn complete(self, core: &SessionCore, sender: &NodeId, _message: &DecryptionSessionCompleted) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(sender, &core.meta.master_node_id);
        SessionStateResult::State(SessionState::Slave(SlaveState::Completed))
    }
}

impl SessionSlaveStateWaitingForCompletion {
    pub fn complete(self, core: &SessionCore, sender: &NodeId, _message: &DecryptionSessionCompleted) -> SessionStateResult {
        debug_assert_ne!(core.meta.self_node_id, core.meta.master_node_id);
        debug_assert_eq!(sender, &core.meta.master_node_id);
        SessionStateResult::State(SessionState::Slave(SlaveState::Completed))
    }
}

/// SessionImpl creation parameters
pub struct SessionParams {
    /// Session metadata.
    pub meta: SessionMeta,
    /// Session access key.
    pub access_key: Secret,
    /// Key share.
    pub decryption_key_share: DocumentKeyShare,
    // Signing key share
    pub signing_key_share: DocumentKeyShare,
    /// ACL storage.
    pub acl_storage: Arc<dyn AclStorage>,
    /// Cluster.
    pub cluster: Arc<dyn Cluster>,
    /// Session nonce.
    pub nonce: u64,
    pub self_public: Public,

    pub log_contract_address: Option<Address>,

    pub eth_client: Arc<dyn EthClient>
}

struct KeyVersionNegotiationBuffer {
    decryption_broadcast: Option<KeyVersionNegotiationMessage>,
    signing_broadcast: Option<KeyVersionNegotiationMessage>,
    decryption_sends: HashMap<NodeId, KeyVersionNegotiationMessage>,
    signing_sends: HashMap<NodeId, KeyVersionNegotiationMessage>,
}

impl KeyVersionNegotiationBuffer {
    pub fn new() -> Self {
        KeyVersionNegotiationBuffer {
            decryption_broadcast: None,
            signing_broadcast: None,
            decryption_sends: HashMap::new(),
            signing_sends: HashMap::new()
        }
    }

    pub fn buffer_send_decryption(&mut self, to: &NodeId, message: KeyVersionNegotiationMessage) -> Result<(), Error> {
        let previous = self.decryption_sends.insert(to.clone(), message);
        debug_assert!(previous.is_none());
        Ok(())
    }

    pub fn buffer_send_signing(&mut self, to: &NodeId, message: KeyVersionNegotiationMessage) -> Result<(), Error> {
        let previous = self.signing_sends.insert(to.clone(), message);
        debug_assert!(previous.is_none());
        Ok(())
    }

    pub fn buffer_broadcast_decryption(&mut self, message: KeyVersionNegotiationMessage) -> Result<(), Error> {
        debug_assert!(self.decryption_broadcast.is_none());
        self.decryption_broadcast = Some(message);
        Ok(())
    }

    pub fn buffer_broadcast_signing(&mut self, message: KeyVersionNegotiationMessage) -> Result<(), Error> {
        debug_assert!(self.signing_broadcast.is_none());
        self.signing_broadcast = Some(message);
        Ok(())
    }

    pub fn send_to_cluster(&mut self, cluster: &dyn Cluster) -> Result<(), Error> {
        // first send individual messages, then broadcasts
        debug_assert_eq!(self.decryption_sends.len(), self.signing_sends.len());
        let mut sorted_decryptions: Vec<(NodeId, KeyVersionNegotiationMessage)> = self.decryption_sends.drain().collect();
        sorted_decryptions.sort_by(|(a,_), (b,_)| a.cmp(b));
        let mut sorted_signings: Vec<(NodeId, KeyVersionNegotiationMessage)> = self.signing_sends.drain().collect();
        sorted_signings.sort_by(|(a,_), (b,_)| a.cmp(b));

        sorted_decryptions.drain(..).zip(sorted_signings.drain(..))
            .try_for_each(|((decryption_to, decryption), (signing_to, signing))| {
                debug_assert_eq!(decryption_to, signing_to);
                cluster.send(&decryption_to, Message::DecryptionWithPayload(DecryptionWithPayloadMessage::KeyVersionNegotiation(DecryptionWithPayloadKeyVersionNegotiation {
                    signing_key: signing,
                    decryption_key: decryption
                })))
        })?;
        match (self.decryption_broadcast.take(), self.signing_broadcast.take()) {
            (Some(decryption_broadcast), Some(signing_broadcast)) => {
                cluster.broadcast(Message::DecryptionWithPayload(DecryptionWithPayloadMessage::KeyVersionNegotiation(DecryptionWithPayloadKeyVersionNegotiation {
                    decryption_key: decryption_broadcast,
                    signing_key: signing_broadcast
                })))
            },
            (None,None) => Ok(()), // ok, no broadcast this time
            _ => panic!("Inconsistent broadcasts of signing and decryption key version negotiation")
        }
    }
}

struct KeyVersionNegotiationSessionTransport {
    buffer: Arc<Mutex<KeyVersionNegotiationBuffer>>,
    is_signing: bool
}

impl key_version_negotiation_session::SessionTransport for KeyVersionNegotiationSessionTransport {
    fn broadcast(&self, message: KeyVersionNegotiationMessage) -> Result<(), Error> {
        if self.is_signing {
            self.buffer.lock().buffer_broadcast_signing(message)
        }else{
            self.buffer.lock().buffer_broadcast_decryption(message)
        }
    }

    fn send(&self, node: &NodeId, message: KeyVersionNegotiationMessage) -> Result<(), Error> {
        if self.is_signing {
            self.buffer.lock().buffer_send_signing(node, message)
        } else {
            self.buffer.lock().buffer_send_decryption(node, message)
        }
    }
}

/// Decryption consensus transport.
struct DecryptionConsensusTransport {
    /// Session id.
    id: SessionId,
    /// Session access key.
    access_key: Secret,
    /// Session-level nonce.
    nonce: u64,
    /// Session origin (if any).
    origin: Option<Address>,
    /// Selected key version (on master node).
    version: Option<H256>,
    /// Cluster.
    cluster: Arc<dyn Cluster>,
}

/// Decryption job transport
struct ProxyDecryptionJobTransport {
    /// Session id.
    id: SessionId,
    //// Session access key.
    access_key: Secret,
    /// Session-level nonce.
    nonce: u64,
    /// Master node id.
    master_node_id: NodeId,
    /// Cluster.
    cluster: Arc<dyn Cluster>,
}

/// Acts as `Cluster` and wraps every `Message::EcdsaSigning` in a `Message::DecryptionWithPayload(DecryptionWithPayloadMessage::SignLogTransaction)`
/// forwarding the wrapped message to the underlying `cluster`
struct TransactionSigningTransport {
    session_id: SessionId,
    cluster: Arc<dyn Cluster>,
    authorization_payload: Vec<U256>,
}

impl TransactionSigningTransport {
    fn map_message(&self, message: Message) -> Result<Message, Error> {
        // replace session_id
        match message {
            Message::EcdsaSigning(m) => Ok(Message::DecryptionWithPayload(DecryptionWithPayloadMessage::SignLogTransaction(match m {
                EcdsaSigningMessage::EcdsaSigningConsensusMessage(consensus_msg) => {
                    let sub_message = match consensus_msg.message {
                        ConsensusMessage::InitializeConsensusSession(init) => ConsensusMessageWithPayload::InitializeConsensusSession(InitializeConsensusSessionWithPayload {
                            requester: init.requester,
                            version: init.version,
                            payload: self.authorization_payload.iter().map(|x| SerializableU256::from(x.clone())).collect(),
                        }),
                        ConsensusMessage::ConfirmConsensusInitialization(confirm) => ConsensusMessageWithPayload::ConfirmConsensusInitialization(confirm),
                    };
                    EcdsaSigningWithPayloadMessage::EcdsaSigningConsensusMessage(EcdsaSigningConsensusWithPayloadMessage {
                        session: self.session_id.clone().into(),
                        sub_session: consensus_msg.sub_session,
                        session_nonce: consensus_msg.session_nonce,
                        message: sub_message
                    })
                },
                EcdsaSigningMessage::EcdsaSignatureNonceGenerationMessage(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaSignatureNonceGenerationMessage(m)
                },
                EcdsaSigningMessage::EcdsaInversionNonceGenerationMessage(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaInversionNonceGenerationMessage(m)
                },
                EcdsaSigningMessage::EcdsaInversionZeroGenerationMessage(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaInversionZeroGenerationMessage(m)
                },
                EcdsaSigningMessage::EcdsaSigningInversedNonceCoeffShare(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaSigningInversedNonceCoeffShare(m)
                },
                EcdsaSigningMessage::EcdsaRequestPartialSignature(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaRequestPartialSignature(m)
                },
                EcdsaSigningMessage::EcdsaPartialSignature(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaPartialSignature(m)
                },
                EcdsaSigningMessage::EcdsaSigningSessionError(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaSigningSessionError(m)
                },
                EcdsaSigningMessage::EcdsaSigningSessionCompleted(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaSigningSessionCompleted(m)
                },
                EcdsaSigningMessage::EcdsaSigningSessionDelegation(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaSigningSessionDelegation(m)
                },
                EcdsaSigningMessage::EcdsaSigningSessionDelegationCompleted(mut m) => {
                    m.session = self.session_id.clone().into();
                    EcdsaSigningWithPayloadMessage::EcdsaSigningSessionDelegationCompleted(m)
                },
            }))),
            _ => Err(Error::InvalidMessage)
        }
    }
}

impl Cluster for TransactionSigningTransport {
    fn broadcast(&self, message: Message) -> Result<(), Error> {
        let mapped_message = self.map_message(message)?;
        self.cluster.broadcast(mapped_message)
    }

    fn send(&self, to: &NodeId, message: Message) -> Result<(), Error> {
        let mapped_message = self.map_message(message)?;
        self.cluster.send(to, mapped_message)
    }

    fn is_connected(&self, node: &NodeId) -> bool {
        self.cluster.is_connected(node)
    }

    fn nodes(&self) -> BTreeSet<NodeId> {
        self.cluster.nodes()
    }

    fn configured_nodes_count(&self) -> usize {
        self.cluster.configured_nodes_count()
    }

    fn connected_nodes_count(&self) -> usize {
        self.cluster.connected_nodes_count()
    }
}
// /// Session delegation status.
// enum DelegationStatus {
//     /// Delegated to other node.
//     DelegatedTo(NodeId),
//     /// Delegated from other node.
//     DelegatedFrom(NodeId, u64),
// }

impl SessionImpl {
    /// Create new decryption session.
    pub fn new_from_master(params: SessionParams, requester: Requester, authorization_payload: Vec<U256>)
    -> Result<(Self, Oneshot<Result<ProxyEncryptedDocumentKey, Error>>), Error> {
        debug_assert_eq!(params.meta.threshold, params.decryption_key_share.threshold);
        // debug_assert!(2*params.signing_key_share.threshold < params.cluster.connected_nodes_count());

        // check that common_point and encrypted_point are already set
        if params.decryption_key_share.common_point.is_none() || params.decryption_key_share.encrypted_point.is_none() {
            return Err(Error::DocumentKeyIsNotFound);
        }

        let (completed, oneshot) = CompletionSignal::new();
        let server_key_id = params.meta.id.clone();
        let requester_public = requester.public(&server_key_id).map_err(|msg| Error::InsufficientRequesterData(msg))?;
        Ok((
            SessionImpl {
                core: SessionCore {
                    meta: params.meta,
                    access_key: params.access_key,
                    decryption_key_share: params.decryption_key_share,
                    signing_key_share: params.signing_key_share,
                    cluster: params.cluster,
                    nonce: params.nonce,
                    completed,
                    acl_storage: params.acl_storage,
                    log_contract_address: params.log_contract_address.ok_or_else(|| Error::Internal("Cannot perform decryption sessions as log contract address is not set".to_string()))?,
                    eth_client: params.eth_client,
                },
                data: Mutex::new(SessionState::Master(MasterState::Created(SessionMasterStateCreated {
                    requester: requester_public,
                    authorization_payload,
                })))
            },
            oneshot,
        ))
    }

    /// Create new decryption session.
    pub fn new_from_slave(params: SessionParams) -> Result<(Self, Oneshot<Result<ProxyEncryptedDocumentKey, Error>>), Error> {
        debug_assert_eq!(params.meta.threshold, params.decryption_key_share.threshold);
        debug_assert!(2*params.signing_key_share.threshold < params.cluster.connected_nodes_count());

        // check that common_point and encrypted_point are already set
        if params.decryption_key_share.common_point.is_none() || params.decryption_key_share.encrypted_point.is_none() {
            return Err(Error::DocumentKeyIsNotFound);
        }

        let (completed, oneshot) = CompletionSignal::new();
        Ok((
            SessionImpl {
                core: SessionCore {
                    meta: params.meta,
                    access_key: params.access_key,
                    decryption_key_share: params.decryption_key_share,
                    signing_key_share: params.signing_key_share,
                    cluster: params.cluster,
                    nonce: params.nonce,
                    completed,
                    acl_storage: params.acl_storage,
                    log_contract_address: params.log_contract_address.ok_or_else(|| Error::Internal("Cannot perform decryption sessions as log contract address is not set".to_string()))?,
                    eth_client: params.eth_client
                },
                data: Mutex::new(SessionState::Slave(SlaveState::Created(SessionSlaveStateCreated {})))
            },
            oneshot,
        ))
    }

    /// Get this node id.
    #[cfg(test)]
    pub fn node(&self) -> &NodeId {
        &self.core.meta.self_node_id
    }

    /// Get this session access key.
    #[cfg(test)]
    pub fn access_key(&self) -> &Secret {
        &self.core.access_key
    }

    /// Get session state (tests only).
    #[cfg(test)]
    fn state(&self) -> &Mutex<SessionState> {
        &self.data
    }

    /// Get decrypted secret
    #[cfg(test)]
    pub fn decrypted_secret(&self) -> Option<Result<ProxyEncryptedDocumentKey, Error>> {
        let data = self.data.lock();
        match data.deref() {
            SessionState::Master(MasterState::Completed(shadow)) => Some(Ok(shadow.clone())),
            SessionState::Failed(e) => Some(Err(e.clone())),
            _ => None,
        }
    }

    /// Get key requester.
    pub fn requester(&self) -> Option<Requester> {
        self.data.lock().requester()
    }

    // /// Get session origin.
    // #[cfg(test)]
    // pub fn origin(&self) -> Option<Address> {
    //     self.data.lock().origin.clone()
    // }

    /// Initialize decryption session on master node.
    pub fn initialize(&self) -> Result<(), Error> {
        debug_assert_eq!(self.core.meta.self_node_id, self.core.meta.master_node_id);

        // check if version exists and thresholds can be fulfilled
        if self.core.decryption_key_share.threshold >= self.core.meta.connected_nodes_count ||
            2*self.core.signing_key_share.threshold >= self.core.meta.connected_nodes_count {
            return Err(Error::ConsensusUnreachable);
        }

        let mut data = self.data.lock();
        SessionState::change_state(&mut data, |old_state| match old_state {
            SessionState::Master(MasterState::Created(session_created)) => session_created.initialize(&self.core),
            _ => SessionStateResult::Error(Error::InvalidStateForRequest)
        })?;

        self.error_if_failed(&data)
    }

    fn error_if_failed(&self, state: &SessionState) -> Result<(), Error> {
        match state {
            &SessionState::Failed(ref error) => {
                // send error to completion future as this session stops now
                self.core.completed.send(Err(error.clone()));
                Err(error.clone())
            },
            _ => Ok(())
        }
    }

    /// Process decryption message.
    pub fn process_message(
        &self,
        sender: &NodeId,
        message: &DecryptionWithPayloadMessage,
    ) -> Result<(), Error> {
        debug!("Node {} received {} from {}", self.core.meta.self_node_id, message, sender);
        if self.core.nonce != message.session_nonce() {
            return Err(Error::ReplayProtection);
        }

        let mut data = self.data.lock();
        SessionState::change_state(&mut data, |old_state| match (message.clone(), old_state) {
            // Message (2)
            (DecryptionWithPayloadMessage::KeyVersionNegotiation(message), SessionState::Slave(SlaveState::Created(session_created))) =>
                session_created.initialize(&self.core, sender, &message),
            // Message (3)
            (DecryptionWithPayloadMessage::KeyVersionNegotiation(message), SessionState::Master(MasterState::KeyVersionNegotiation(key_version_negotiation))) =>
                key_version_negotiation.try_start_signing_session_from_master(&self.core, sender, &message),
            // Message (4)
            (DecryptionWithPayloadMessage::SignLogTransaction(EcdsaSigningWithPayloadMessage::EcdsaSigningConsensusMessage(message)), SessionState::Slave(SlaveState::KeyVersionNegotiation(key_version_negotiation))) =>
                key_version_negotiation.start_signing_session_from_slave(&self.core, sender, &message),
            // Message (6)
            (DecryptionWithPayloadMessage::SignLogTransaction(EcdsaSigningWithPayloadMessage::EcdsaPartialSignature(message)), SessionState::Master(MasterState::JointSignature(joint_signature))) =>
                joint_signature.try_complete_signing_session_and_start_decryption_consensus(&self.core, sender, &message),
            // Message (7)
            (DecryptionWithPayloadMessage::SignLogTransaction(EcdsaSigningWithPayloadMessage::EcdsaSigningSessionCompleted(message)), SessionState::Slave(SlaveState::JointSignature(joint_signature))) =>
                joint_signature.complete_signing_session_on_slave(&self.core, sender, &message),
            // Messages (5) to master
            (DecryptionWithPayloadMessage::SignLogTransaction(message), SessionState::Master(MasterState::JointSignature(joint_signature))) =>
                joint_signature.process_message(sender, &message),
            // Messages (5) to slave
            (DecryptionWithPayloadMessage::SignLogTransaction(message), SessionState::Slave(SlaveState::JointSignature(joint_signature))) =>
                joint_signature.process_message(sender, &message),
            // Message (8)
            (DecryptionWithPayloadMessage::DecryptionConsensusMessage(message), SessionState::Slave(SlaveState::DecryptionConsensus(decryption_consensus))) =>
                decryption_consensus.complete_consensus_session_from_slave(&self.core, sender, &message),
            // Message (9)
            (DecryptionWithPayloadMessage::DecryptionConsensusMessage(message), SessionState::Master(MasterState::DecryptionConsensus(decryption_consensus))) =>
                decryption_consensus.try_complete_consensus_session_from_master(&self.core, sender, &message),
            // Message (10)
            (DecryptionWithPayloadMessage::RequestPartialDecryption(message), SessionState::Slave(SlaveState::Decryption(decryption))) =>
                decryption.process_request(&self.core, sender, &message),
            // Message (11)
            (DecryptionWithPayloadMessage::PartialDecryption(message), SessionState::Master(MasterState::Decryption(decryption))) =>
                decryption.process_response(&self.core, sender, &message),
            // Message (12) (also accepted in SlaveState::Decryption as the master node continues as soon as enough decryption shares are sent)
            (DecryptionWithPayloadMessage::DecryptionWithPayloadCompleted(message), SessionState::Slave(SlaveState::Decryption(decryption))) =>
                decryption.complete(&self.core, sender, &message),
            (DecryptionWithPayloadMessage::DecryptionWithPayloadCompleted(message), SessionState::Slave(SlaveState::WaitingForCompletion(waiting_for_completion))) =>
                waiting_for_completion.complete(&self.core, sender, &message),

            // Error Message
            (DecryptionWithPayloadMessage::DecryptionSessionError(message), _) =>
                SessionStateResult::Error(message.error),

            // Invalid message for state
            (msg, state) => {
                warn!(target: "decryption_session_with_payload", "Received unexpected message {:?} for state {:?}", msg, state);
                SessionStateResult::State(state)
            }
        })?;

        self.error_if_failed(&data)
    }

    /// Process error from the other node.
    fn process_node_error(&self, node: Option<&NodeId>, error: Error) -> Result<(), Error> {
        let mut data = self.data.lock();
        let is_self_node_error = node
            .map(|n| n == &self.core.meta.self_node_id)
            .unwrap_or(false);
        // error is always fatal if coming from this node
        if is_self_node_error {
            *data = SessionState::Failed(error.clone());
        }

        let error_for_state = match node {
            Some(node) => data.on_session_error(&self.core, node, error.clone()),
            None => data.on_session_timeout(&self.core),
        };

        match error_for_state {
            Some(err) => *data = SessionState::Failed(err),
            None => *data = SessionState::Failed(error.clone()),
        }
        return Err(error);
    }
}

impl ClusterSession for SessionImpl {
    type Id = SessionIdWithSubSession;
    type CreationData = SessionCreationData;
    type SuccessfulResult = ProxyEncryptedDocumentKey;

    fn type_name() -> &'static str {
        "decryption_with_payload"
    }

    fn id(&self) -> SessionIdWithSubSession {
        SessionIdWithSubSession::new(self.core.meta.id.clone(), self.core.access_key.clone())
    }

    fn is_finished(&self) -> bool {
        let data = self.data.lock();
        match data.deref() {
            SessionState::Master(MasterState::Created(_))
            | SessionState::Slave(SlaveState::Created(_)) => false,
            SessionState::Master(MasterState::KeyVersionNegotiation(SessionMasterStateKeyVersionNegotiation {decryption_key_negotiation_session, signing_key_negotiation_session, .. }))
            | SessionState::Slave(SlaveState::KeyVersionNegotiation(SessionSlaveStateKeyVersionNegotiation { decryption_key_negotiation_session, signing_key_negotiation_session, .. })) => {
                match (decryption_key_negotiation_session.result(), signing_key_negotiation_session.result()) {
                    (Some(Err(_)), _) | (_, Some(Err(_))) => true,
                    _ => false
                }
            },
            SessionState::Master(MasterState::JointSignature(SessionMasterStateJointSignature { signature_session, .. }))
            | SessionState::Slave(SlaveState::JointSignature(SessionSlaveStateJointSignature { signature_session, .. })) => {
                match signature_session.result() {
                    Some(Err(_)) => true,
                    _ => false,
                }
            },
            SessionState::Master(MasterState::DecryptionConsensus(SessionMasterStateDecryptionConsensus {key_access_session, ..}))
            | SessionState::Slave(SlaveState::DecryptionConsensus(SessionSlaveStateDecryptionConsensus {key_access_session, ..}))
            | SessionState::Master(MasterState::Decryption(SessionMasterStateDecryption {key_access_session, ..}))
            | SessionState::Slave(SlaveState::Decryption(SessionSlaveStateDecryption {key_access_session, ..})) => {
                key_access_session.state() == ConsensusSessionState::Failed
            },
            SessionState::Slave(SlaveState::WaitingForCompletion(_)) => false,
            SessionState::Master(MasterState::Completed(_))
            | SessionState::Slave(SlaveState::Completed)
            | SessionState::Failed(_) => true,
        }
    }

    fn on_node_timeout(&self, node: &NodeId) {
        // ignore error, only state matters
        let _ = self.process_node_error(Some(node), Error::NodeDisconnected);
    }

    fn on_session_timeout(&self) {
        // ignore error, only state matters
        let _ = self.process_node_error(None, Error::NodeDisconnected);
    }

    fn on_session_error(&self, node: &NodeId, error: Error) {
        let is_fatal = self.process_node_error(Some(node), error.clone()).is_err();
        let is_this_node_error = *node == self.core.meta.self_node_id;
        if is_fatal || is_this_node_error {
            // error in signing session is non-fatal, if occurs on slave node
            // => either respond with error
            // => or broadcast error
            let message = Message::DecryptionWithPayload(DecryptionWithPayloadMessage::DecryptionSessionError(
                DecryptionSessionError {
                    session: self.core.meta.id.clone().into(),
                    sub_session: self.core.access_key.clone().into(),
                    session_nonce: self.core.nonce,
                    error: error.clone().into(),
                },
            ));

            // do not bother processing send error, as we already processing error
            let _ = if self.core.meta.master_node_id == self.core.meta.self_node_id {
                self.core.cluster.broadcast(message)
            } else {
                self.core
                    .cluster
                    .send(&self.core.meta.master_node_id, message)
            };

            self.core.completed.send(Err(error));
        }
    }

    fn on_message(&self, sender: &NodeId, message: &Message) -> Result<(), Error> {
        match *message {
            Message::DecryptionWithPayload(ref message) => self.process_message(sender, message),
            _ => unreachable!("cluster checks message to be correct before passing; qed"),
        }
    }
}

impl JobTransport for DecryptionConsensusTransport {
    type PartialJobRequest = KeyAccessWithPayloadPartialJobRequest;
    type PartialJobResponse = bool;

    fn send_partial_request(
        &self,
        node: &NodeId,
        request: KeyAccessWithPayloadPartialJobRequest,
    ) -> Result<(), Error> {
        let version = self.version.as_ref()
			.expect("send_partial_request is called on initialized master node only; version is filled in before initialization starts on master node; qed");
        self.cluster.send(
            node,
            Message::DecryptionWithPayload(DecryptionWithPayloadMessage::DecryptionConsensusMessage(
                DecryptionConsensusMessage {
                    session: self.id.clone().into(),
                    sub_session: self.access_key.clone().into(),
                    session_nonce: self.nonce,
                    origin: self.origin.clone().map(Into::into),
                    message: ConsensusMessage::InitializeConsensusSession(
                        InitializeConsensusSession {
                            requester: request.requester.into(),
                            version: version.clone().into(),
                        },
                    ),
                },
            )),
        )
    }

    fn send_partial_response(&self, node: &NodeId, response: bool) -> Result<(), Error> {
        self.cluster.send(
            node,
            Message::DecryptionWithPayload(DecryptionWithPayloadMessage::DecryptionConsensusMessage(
                DecryptionConsensusMessage {
                    session: self.id.clone().into(),
                    sub_session: self.access_key.clone().into(),
                    session_nonce: self.nonce,
                    origin: None,
                    message: ConsensusMessage::ConfirmConsensusInitialization(
                        ConfirmConsensusInitialization {
                            is_confirmed: response,
                        },
                    ),
                },
            )),
        )
    }
}

impl JobTransport for ProxyDecryptionJobTransport {
    type PartialJobRequest = ProxyDecryptionJobRequest;
    type PartialJobResponse = PartialDecryptionShare;

    fn send_partial_request(
        &self,
        node: &NodeId,
        _request: ProxyDecryptionJobRequest,
    ) -> Result<(), Error> {
        self.cluster.send(
            node,
            Message::DecryptionWithPayload(DecryptionWithPayloadMessage::RequestPartialDecryption(
                RequestProxyDecryption {
                    session: self.id.clone().into(),
                    sub_session: self.access_key.clone().into(),
                    session_nonce: self.nonce,
                },
            )),
        )?;

        Ok(())
    }

    fn send_partial_response(
        &self,
        node: &NodeId,
        response: PartialDecryptionShare,
    ) -> Result<(), Error> {
        if *node == self.master_node_id {
            self.cluster.send(
                node,
                Message::DecryptionWithPayload(DecryptionWithPayloadMessage::PartialDecryption(ProxyDecryption {
                    session: self.id.clone().into(),
                    sub_session: self.access_key.clone().into(),
                    session_nonce: self.nonce,
                    common_point: response.common_point.into(),
                    encrypted_point: response.encrypted_point.into(),
                    k_commitment: response.k_commitment.into(),
                    share_commitment: response.share_commitment.into(),
                    encrypted_point_commitment: response.encrypted_point_commitment.into(),
                    k_response: response.k_response.into(),
                    share_response: response.share_response.into(),
                })),
            )?;
        }

        Ok(())
    }
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SessionState::Master(master_state) => {
                write!(f, "SessionState::Master::{}", match master_state {
                    MasterState::Created(_) => "Created".to_string(),
                    MasterState::KeyVersionNegotiation(_) => "KeyVersionNegotiation".to_string(),
                    MasterState::JointSignature(js) => format!("JointSignature::{}", js.signature_session.state_str()),
                    MasterState::DecryptionConsensus(_) => "DecryptionConsensus".to_string(),
                    MasterState::Decryption(_) => "Decryption".to_string(),
                    MasterState::Completed(_) => "Completed".to_string(),
                })
            },
            SessionState::Slave(slave_state) => write!(f, "SessionState::Slave::{}", match slave_state {
                SlaveState::Created(_) => "Created".to_string(),
                SlaveState::KeyVersionNegotiation(_) => "KeyVersionNegotiation".to_string(),
                SlaveState::JointSignature(js) => format!("JointSignature::{}", js.signature_session.state_str()),
                SlaveState::DecryptionConsensus(_) => "DecryptionConsensus".to_string(),
                SlaveState::Decryption(_) => "Decryption".to_string(),
                SlaveState::WaitingForCompletion(_) => "WaitingForCompletion".to_string(),
                SlaveState::Completed => "Completed".to_string(),
            }),
            SessionState::Failed(error) => write!(f, "SessionState::Error({})", error.to_string()),
        }
    }
}

// #[cfg(test)]
// pub fn create_default_decryption_session() -> Arc<SessionImpl> {
//     use acl_storage::DummyAclStorage;
//     use ethereum_types::H512;
//     use key_server_cluster::cluster::tests::DummyCluster;
//
//     Arc::new(
//         SessionImpl::new(
//             SessionParams {
//                 meta: SessionMeta {
//                     id: Default::default(),
//                     self_node_id: Default::default(),
//                     master_node_id: Default::default(),
//                     threshold: 0,
//                     configured_nodes_count: 0,
//                     connected_nodes_count: 0,
//                 },
//                 access_key: Secret::zero(),
//                 key_share: Default::default(),
//                 acl_storage: Arc::new(DummyAclStorage::default()),
//                 cluster: Arc::new(DummyCluster::new(Default::default())),
//                 nonce: 0,
//             },
//             Some(Requester::Public(H512::from_low_u64_be(2))),
//         )
//         .unwrap()
//         .0,
//     )
// }
//
#[cfg(test)]
mod tests {
    use acl_storage::{DummyAclStorage, AclStorage};
    use crypto::publickey::{public_to_address, Generator, KeyPair, Public, Random, Secret, ec_math_utils, Signature, verify_public};
    use ethereum_types::{Address, H512, U256, H256};
    use serialization::{SerializableH256};
    use key_server_cluster::cluster::tests::DummyCluster;
    use key_server_cluster::cluster_sessions::ClusterSession;
    use key_server_cluster::decryption_session_with_payload::{SessionImpl, SessionParams};
    use key_server_cluster::jobs::consensus_session::ConsensusSessionState;
    use key_server_cluster::message::{self, Message, DecryptionWithPayloadMessage, KeyVersionNegotiationMessage, RequestKeyVersions, DecryptionWithPayloadKeyVersionNegotiation};
    use key_server_cluster::{
        DocumentKeyShare, DocumentKeyShareVersion, Error, NodeId,
        Requester, SessionId, SessionMeta,
    };
    use std::collections::{BTreeMap, VecDeque, BTreeSet, HashMap};
    use std::str::FromStr;
    use std::sync::Arc;
    use ::{ServerKeyId, SecretStoreChain};
    use key_server_cluster::client_sessions::decryption_session_with_payload::{SessionState, KeyVersionNegotiationBuffer, MasterState, SlaveState, SessionMasterStateDecryptionConsensus, SessionSlaveStateDecryptionConsensus, SessionMasterStateDecryption, SessionSlaveStateDecryption, ProxyEncryptedDocumentKey};
    use ethabi::{RawLog, Bytes};
    use ::{Filter, BlockId};
    use ::{ContractAddress, NewBlocksNotify};
    use std::ops::Deref;
    use key_server_cluster::cluster::Cluster;
    use parking_lot::Mutex;
    use traits::JOINT_SIGNATURE_KEY_ID;
    use rustc_hex::{FromHex, ToHex};
    use rlp::{RlpStream, Rlp};
    use blockchain::{DummyEthClient, EthClient};
    use transaction_signature::RawTransaction;

    const SECRET_PLAIN: &'static str = "d2b57ae7619e070af0af6bc8c703c0cd27814c54d5d6a999cacac0da34ede279ca0d9216e85991029e54e2f0c92ee0bd30237725fa765cbdbfc4529489864c5f";
    const SIGNING_SECRET_PLAIN: &'static str = "889e32162578670415b98122b566b07f09728f5daeaa10051b35f7df96951a16";
    const DUMMY_SESSION_ID: [u8; 32] = [1u8; 32];
    lazy_static! {
        static ref DUMMY_PAYLOAD: Vec<U256> = vec![U256([1,2,3,4])];
    }
    lazy_static! {
        static ref DUMMY_CONTRACT_ADDRESS: Address = Address::default();
    }

    fn default_acl_storage(_: i32) -> DummyAclStorage {
        DummyAclStorage::default()
    }

    fn single_dummy_eth_client(client: DummyEthClient) -> impl FnOnce(usize) -> Vec<Arc<DummyEthClient>> {
        let client = Arc::new(client);
        return move |n| {
            (0..n).map(|_| client.clone()).collect()
        };
    }

    /// if `chain_id` is Some, the transaction will be encoded for signing
    fn append_transaction(rlp: &mut RlpStream, nonce: &U256, gas_price: &U256, gas_limit: &U256, address: &Address, value: &U256, data: &Vec<u8>) {
        rlp.append(nonce);
        rlp.append(gas_price);
        rlp.append(gas_limit);
        rlp.append(address);
        rlp.append(value);
        rlp.append(data);
    }

    fn hash_transaction(tx: &[u8]) -> H256 {
        let mut hasher = tiny_keccak::Keccak::new_keccak256();
        hasher.update(&tx);
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        return H256(result);
        // H256::from(tiny_keccak::sha3_256(tx))
    }

    fn prepare_decryption_sessions() -> (
        KeyPair,
        Vec<Arc<DummyCluster>>,
        Vec<Arc<DummyAclStorage>>,
        Vec<SessionImpl>
    ) {
        let (keypair, clusters, acl_storages, sessions, _) = prepare_decryption_sessions_helper(Random.generate(), DUMMY_PAYLOAD.clone(), default_acl_storage, single_dummy_eth_client(DummyEthClient::new()), None);
        return (keypair, clusters, acl_storages, sessions);
    }

    fn prepare_decryption_sessions_given_eth_client<E: 'static + EthClient,F>(requester: KeyPair, payload: Vec<U256>, eth_client_create: F, contract_address: Option<Address>) -> (
        KeyPair,
        Vec<Arc<DummyCluster>>,
        Vec<Arc<DummyAclStorage>>,
        Vec<SessionImpl>,
        Vec<Arc<E>>
    ) where F: FnOnce(usize)->Vec<Arc<E>> {
        prepare_decryption_sessions_helper(requester, payload, default_acl_storage, eth_client_create, contract_address)
    }

    fn prepare_decryption_sessions_given_acl<T: 'static + AclStorage, F>(requester: KeyPair, payload: Vec<U256>, acl_create: F) -> (
        KeyPair,
        Vec<Arc<DummyCluster>>,
        Vec<Arc<T>>,
        Vec<SessionImpl>,
    ) where F: Fn(i32)->T {
        let (keypair, cluster, acl_storages, sessions, _) = prepare_decryption_sessions_helper(requester, payload, acl_create, single_dummy_eth_client(DummyEthClient::new()), None);
        return (keypair, cluster, acl_storages, sessions);
    }

    fn prepare_decryption_sessions_helper<T: 'static + AclStorage,F, E: 'static + EthClient, G>(requester: KeyPair, payload: Vec<U256>, acl_create: F, eth_client_create: G, contract_address: Option<Address>) -> (
        KeyPair,
        Vec<Arc<DummyCluster>>,
        Vec<Arc<T>>,
        Vec<SessionImpl>,
        Vec<Arc<E>>
    ) where F: Fn(i32)->T, G: FnOnce(usize)->Vec<Arc<E>> {
        // prepare encrypted data + cluster configuration for scheme 4-of-5
        let session_id = SessionId::from(DUMMY_SESSION_ID);
        let access_key = Random.generate().secret().clone();
        let secret_shares: Vec<Secret> = vec![
            "4e0a3398f3be44751ea0beb219c2e30eab63059a8699e02cd749656f412cd00f"
                .parse()
                .unwrap(),
            "0810b5a871fb0374a5c61cce28ae423049fe6acd629825d5fc52ab2b2e1c9f11"
                .parse()
                .unwrap(),
            "146beda7c5e8e14304f2dac9518ded07a56d2e6baf35dcd2e67eb007fc83ee8f"
                .parse()
                .unwrap(),
            "4f479833b381db08104aeaa56af69d4669d1b5ee4154cc90d10a894e17ea3499"
                .parse()
                .unwrap(),
            "c264282fc753abb5dc18591317c643e701866473c80f172f7199aa5bfbfd1248"
                .parse()
                .unwrap(),
        ];
        let signing_shares: Vec<Secret> = vec![
            "629e1028a192f13a18ec8e0dc02bc7ab3e7c146023fdca28cce6f983190ab9f1".parse().unwrap(),
            "9d2e14281123add1512e60057f9175098ff20ca6c2861cc178200be4bd69c36d".parse().unwrap(),
            "a3686a42232140d778de14861b84e10c1c54243972b093793e77bacfefa1c746".parse().unwrap(),
            "bb4b15f38fd58d8521b3d0e9ec9191b4bd4487ececef024b84c9f41884c55c6e".parse().unwrap(),
            "c60f50e5b1c0b1447333f7fa9356449972427f3e6c9f4a4ac27e16291b639254".parse().unwrap(),
        ];
        let signing_public = H512::from_str("d8d2e815d080ceed1527bfb01af2f8ac908fa94e70c19440c4e245b80c254a05b078a4cd0fa6755e496b16d0fa2cc756cf7bf1dbc4a63988868a971a2a020d6e").unwrap();
        let id_numbers: Vec<(NodeId, Secret)> = vec![
            (H512::from_str("b486d3840218837b035c66196ecb15e6b067ca20101e11bd5e626288ab6806ecc70b8307012626bd512bad1559112d11d21025cef48cc7a1d2f3976da08f36c8").unwrap(),
             "281b6bf43cb86d0dc7b98e1b7def4a80f3ce16d28d2308f934f116767306f06c".parse().unwrap()),
            (H512::from_str("1395568277679f7f583ab7c0992da35f26cde57149ee70e524e49bdae62db3e18eb96122501e7cbb798b784395d7bb5a499edead0706638ad056d886e56cf8fb").unwrap(),
             "00125d85a05e5e63e214cb60fe63f132eec8a103aa29266b7e6e6c5b7597230b".parse().unwrap()),
            (H512::from_str("99e82b163b062d55a64085bacfd407bb55f194ba5fb7a1af9c34b84435455520f1372e0e650a4f91aed0058cb823f62146ccb5599c8d13372c300dea866b69fc").unwrap(),
             "f43ac0fba42a5b6ed95707d2244659e89ba877b1c9b82c0d0a9dcf834e80fc62".parse().unwrap()),
            (H512::from_str("7e05df9dd077ec21ed4bc45c9fe9e0a43d65fa4be540630de615ced5e95cf5c3003035eb713317237d7667feeeb64335525158f5f7411f67aca9645169ea554c").unwrap(),
             "5a324938dfb2516800487d25ab7289ba8ec38811f77c3df602e4e65e3c9acd9f".parse().unwrap()),
            (H512::from_str("321977760d1d8e15b047a309e4c7fe6f355c10bb5a06c68472b676926427f69f229024fa2692c10da167d14cdc77eb95d0fce68af0a0f704f0d3db36baa83bb2").unwrap(),
             "12cf422d50002d04e52bd4906fd7f5f235f051ca36abfe37e061f8da248008d8".parse().unwrap()),
        ];
        let publics: Vec<Public> = id_numbers.iter().map(|(_,secret)| {
            let mut public = ec_math_utils::generation_point();
            ec_math_utils::public_mul_secret(&mut public, secret).unwrap();
            public
        }).collect();
        let contract_address = contract_address.unwrap_or_else(|| *DUMMY_CONTRACT_ADDRESS);
        let common_point: Public = H512::from_str("717a4d00b2ef52d4afef9aeae6f2534052d82376d2087b2827bcfacc9dd9e14dfff5801a9874d52c45514dcd424fd86ff352da06762aba2f9d76c0f33959568b").unwrap();
        let encrypted_point: Public = H512::from_str("051077c43d396847f678469081f53a74c1e38597c996cb21436050725dcb0a9030406b1341d0a11db36ddcdeec5aff3c51509bb847b4bc1809f4156cd73482b4").unwrap();

        let coefficient_commitments: Vec<Public> = vec![
            "680645e4ab2388b74a2966eb04eba11f07607721517676131c78f9102dbd611f9a84728bc4ef681a0dbc6817e6fc63283b2bdd14d0a30e56781003058cbefcb8".parse().unwrap(),
            "a8539eb82bebc299ecc51c086f0ac873f126c1b35a8c7dc14bde2e7b3e9de70c22384a7cdf4efa99897cd2b410a1738a67b89d900caa0651bcf9f1ed2025e1f7".parse().unwrap(),
            "8607260761cf43b99ca3d7bb8c150c48958d26011ab1a7bbd104f9374d06ed015ce2baf1b6da05b19e0a7d9687acb795ae2bc002ef23aae91075ea425b3bca4a".parse().unwrap(),
            "a9e7e7bc0d95cd1f0c3fc075143da4e7a0d6790b0890bb65ae4c6aa47511ea31289f7bebf4b488e92d256983a5c5daa5522aedcf24f1bb77ac27537956e2ba93".parse().unwrap(),
        ];

        let encrypted_datas: Vec<_> = (0..5)
            .map(|i| DocumentKeyShare {
                author: Default::default(),
                threshold: 3,
                public: Default::default(),
                common_point: Some(common_point.clone()),
                encrypted_point: Some(encrypted_point.clone()),
                versions: vec![DocumentKeyShareVersion {
                    hash: Default::default(),
                    id_numbers: id_numbers.clone().into_iter().collect(),
                    secret_share: secret_shares[i].clone(),
                    coefficient_commitments: Some(coefficient_commitments.clone()),
                }],
            })
            .collect();
        let signing_shares: Vec<DocumentKeyShare> = signing_shares.iter()
            .map(|share| DocumentKeyShare {
                author: Default::default(),
                threshold: 2,
                public: signing_public.clone(),
                common_point: None,
                encrypted_point: None,
                versions: vec![DocumentKeyShareVersion {
                    hash: Default::default(),
                    id_numbers: id_numbers.clone().into_iter().collect(),
                    secret_share: share.clone(),
                    coefficient_commitments: None,
                }]
            })
            .collect();
        let acl_storages: Vec<_> = (0..5)
            .map(|i| Arc::new(acl_create(i)))
            .collect();
        let eth_clients = eth_client_create(5);
        let clusters: Vec<_> = (0..5)
            .map(|i| {
                let cluster = Arc::new(DummyCluster::new(
                    id_numbers.iter().nth(i).clone().unwrap().0,
                ));
                for id_number in &id_numbers {
                    cluster.add_node(id_number.0.clone());
                }
                cluster
            })
            .collect();
        let signature = crypto::publickey::sign(requester.secret(), &session_id).unwrap();
        let sessions: Vec<_> = (0..5)
            .map(|i| {
                if i==0 {
                    SessionImpl::new_from_master(
                        SessionParams {
                            meta: SessionMeta {
                                id: session_id,
                                self_node_id: id_numbers.iter().nth(i).clone().unwrap().0,
                                master_node_id: id_numbers.iter().nth(0).clone().unwrap().0,
                                threshold: encrypted_datas[i].threshold,
                                configured_nodes_count: 5,
                                connected_nodes_count: 5,
                            },
                            access_key: access_key.clone(),
                            decryption_key_share: encrypted_datas[i].clone(),
                            acl_storage: acl_storages[i].clone(),
                            cluster: clusters[i].clone(),
                            nonce: 0,
                            self_public: publics[i].clone(),
                            signing_key_share: signing_shares[i].clone(),
                            log_contract_address: Some(contract_address.clone()),
                            eth_client: eth_clients[i].clone(),
                        },
                        Requester::Signature(signature.clone()),
                        payload.clone()
                    )
                } else {
                    SessionImpl::new_from_slave(
                        SessionParams {
                            meta: SessionMeta {
                                id: session_id,
                                self_node_id: id_numbers.iter().nth(i).clone().unwrap().0,
                                master_node_id: id_numbers.iter().nth(0).clone().unwrap().0,
                                threshold: encrypted_datas[i].threshold,
                                configured_nodes_count: 5,
                                connected_nodes_count: 5,
                            },
                            access_key: access_key.clone(),
                            decryption_key_share: encrypted_datas[i].clone(),
                            acl_storage: acl_storages[i].clone(),
                            cluster: clusters[i].clone(),
                            nonce: 0,
                            self_public: publics[i].clone(),
                            signing_key_share: signing_shares[i].clone(),
                            log_contract_address: Some(contract_address.clone()),
                            eth_client: eth_clients[i].clone(),
                        }
                    )
                }
                    .unwrap()
                    .0
            })
            .collect();

        (requester, clusters, acl_storages, sessions, eth_clients)
    }

    fn do_messages_exchange(
        clusters: &[Arc<DummyCluster>],
        sessions: &[SessionImpl],
    ) -> Result<(), Error> {
        do_messages_exchange_until(clusters, sessions, |_, _, _| false)
    }

    fn do_messages_exchange_until<F>(
        clusters: &[Arc<DummyCluster>],
        sessions: &[SessionImpl],
        mut cond: F,
    ) -> Result<(), Error>
        where
            F: FnMut(&NodeId, &NodeId, &Message) -> bool,
    {
        let mut queue: VecDeque<(NodeId, NodeId, Message)> = VecDeque::new();
        while let Some((mut from, mut to, mut message)) = clusters
            .iter()
            .filter_map(|c| c.take_message().map(|(to, msg)| (c.node(), to, msg)))
            .next()
        {
            if cond(&from, &to, &message) {
                break;
            }

            let mut is_queued_message = false;
            loop {
                let session = &sessions[sessions.iter().position(|s| s.node() == &to).unwrap()];
                match session.on_message(&from, &message) {
                    Ok(_) => {
                        if let Some(qmessage) = queue.pop_front() {
                            from = qmessage.0;
                            to = qmessage.1;
                            message = qmessage.2;
                            is_queued_message = true;
                            continue;
                        }
                        break;
                    }
                    Err(Error::TooEarlyForRequest) => {
                        if is_queued_message {
                            queue.push_front((from, to, message));
                        } else {
                            queue.push_back((from, to, message));
                        }
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(())
    }

    fn prepare_decryption_in_cluster_of_single_node(requester: &KeyPair, payload: Vec<U256>, eth_client: Option<Arc<dyn EthClient>>, contract_address: Option<Address>) -> (SessionImpl, Public) {
        let mut nodes = BTreeMap::new();
        let self_node_id = Random.generate().public().clone();
        nodes.insert(self_node_id, Random.generate().secret().clone());
        let msg = [1u8; 32].into();
        let requester = Requester::Signature(
            crypto::publickey::sign(requester.secret(), &msg).unwrap(),
        );
        let cluster = Arc::new(DummyCluster::new(self_node_id.clone()));
        cluster.add_node(self_node_id);

        let secret = Random.generate().secret().clone();
        let random = Random.generate().secret().clone();
        let mut common_point = ec_math_utils::generation_point();
        ec_math_utils::public_mul_secret(&mut common_point, &random).unwrap();
        let mut encrypted_point = ec_math_utils::generation_point();
        ec_math_utils::public_mul_secret(&mut encrypted_point, &secret).unwrap();
        ec_math_utils::public_mul_secret(&mut encrypted_point, &random).unwrap();
        ec_math_utils::public_add(&mut encrypted_point, &Public::from_str(SECRET_PLAIN).unwrap()).unwrap();
        let mut public = ec_math_utils::generation_point();
        ec_math_utils::public_mul_secret(&mut public, &secret).unwrap();

        let signing_public = H512::from_str("d8d2e815d080ceed1527bfb01af2f8ac908fa94e70c19440c4e245b80c254a05b078a4cd0fa6755e496b16d0fa2cc756cf7bf1dbc4a63988868a971a2a020d6e").unwrap();
        let eth_client = match eth_client {
            Some(eth_client) => eth_client,
            None => Arc::new(DummyEthClient::new()),
        };

        let coeff = {
            let mut g = ec_math_utils::generation_point();
            ec_math_utils::public_mul_secret(&mut g, &secret).unwrap();
            g
        };

        let params = SessionParams {
            meta: SessionMeta {
                id: SessionId::from([1u8; 32]),
                self_node_id: self_node_id.clone(),
                master_node_id: self_node_id.clone(),
                threshold: 0,
                configured_nodes_count: 1,
                connected_nodes_count: 1,
            },
            access_key: Random.generate().secret().clone(),
            decryption_key_share: DocumentKeyShare {
                author: Default::default(),
                threshold: 0,
                public: public,
                common_point: Some(common_point),
                encrypted_point: Some(encrypted_point),
                versions: vec![DocumentKeyShareVersion {
                    hash: Default::default(),
                    id_numbers: nodes.clone(),
                    secret_share: secret.clone(),
                    coefficient_commitments: Some(vec![coeff])
                }]
            },
            signing_key_share: DocumentKeyShare {
                author: Default::default(),
                threshold: 0,
                public: signing_public.clone(),
                common_point: None,
                encrypted_point: None,
                versions: vec![DocumentKeyShareVersion {
                    hash: Default::default(),
                    id_numbers: nodes.clone(),
                    secret_share: SIGNING_SECRET_PLAIN.parse().unwrap(),
                    coefficient_commitments: None
                }]
            },
            acl_storage: Arc::new(DummyAclStorage::default()),
            cluster: cluster,
            nonce: 0,
            self_public: Default::default(),
            log_contract_address: Some(contract_address.unwrap_or_else(|| *DUMMY_CONTRACT_ADDRESS)),
            eth_client: eth_client,
        };
        let (session, _) = SessionImpl::new_from_master(params,  requester, payload).unwrap();
        return (session, signing_public);
    }

    fn random_key_share(nodes: BTreeMap<NodeId,Secret>) -> DocumentKeyShare {
        let secret = Random.generate().secret().clone();
        let mut commitment = ec_math_utils::generation_point();
        ec_math_utils::public_mul_secret(&mut commitment, &secret).unwrap();
        DocumentKeyShare {
            author: Default::default(),
            threshold: 0,
            public: Default::default(),
            common_point: Some(Random.generate().public().clone()),
            encrypted_point: Some(Random.generate().public().clone()),
            versions: vec![DocumentKeyShareVersion {
                hash: Default::default(),
                id_numbers: nodes,
                secret_share: secret,
                coefficient_commitments: Some(vec![commitment])
            }],
        }
    }

    // struct ChainClientMock {
    //
    // }
    //
    // impl SecretStoreChain for ChainClientMock {
    //     fn add_listener(&self, _target: Arc<dyn NewBlocksNotify>) {
    //         unimplemented!()
    //     }
    //
    //     fn is_trusted(&self) -> bool {
    //         unimplemented!()
    //     }
    //
    //     fn transact_contract(&self, _contract: Address, _tx_data: Bytes) -> Result<(), crypto::publickey::Error> {
    //         unimplemented!()
    //     }
    //
    //     fn read_contract_address(&self, _registry_name: &str, address: &ContractAddress) -> Option<Address> {
    //         match address {
    //             ContractAddress::Address(address) => Some(address.clone()),
    //             _ => Some(DUMMY_CONTRACT_ADDRESS.clone())
    //         }
    //     }
    //
    //     fn call_contract(&self, _block_id: BlockId, _contract_address: Address, _data: Bytes) -> Result<Bytes, String> {
    //         Ok(vec![])
    //     }
    //
    //
    //     fn block_hash(&self, _id: BlockId) -> Option<H256> {
    //         unimplemented!()
    //     }
    //
    //     fn block_number(&self, _id: BlockId) -> Option<u64> {
    //         unimplemented!()
    //     }
    //
    //     fn retrieve_last_logs(&self, _filter: Filter) -> Option<Vec<RawLog>> {
    //         unimplemented!()
    //     }
    //
    //     fn get_confirmed_block_hash(&self) -> Option<H256> {
    //         unimplemented!()
    //     }
    // }

    #[test]
    fn constructs_in_cluster_of_single_node() {
        let mut nodes = BTreeMap::new();
        let self_node_id = Random.generate().public().clone();
        nodes.insert(self_node_id, Random.generate().secret().clone());
        let msg = [1u8; 32].into();
        let requester = Requester::Signature(
            crypto::publickey::sign(Random.generate().secret(), &msg).unwrap(),
        );
        let payload = vec![U256([1,2,3,4]), U256([5,6,7,8])];
        let params = SessionParams {
            meta: SessionMeta {
                id: SessionId::from([1u8; 32]),
                self_node_id: self_node_id.clone(),
                master_node_id: self_node_id.clone(),
                threshold: 0,
                configured_nodes_count: 1,
                connected_nodes_count: 1,
            },
            access_key: Random.generate().secret().clone(),
            decryption_key_share: random_key_share(nodes.clone()),
            signing_key_share: random_key_share(nodes),
            acl_storage: Arc::new(DummyAclStorage::default()),
            cluster: Arc::new(DummyCluster::new(self_node_id.clone())),
            nonce: 0,
            self_public: Default::default(),
            log_contract_address: Some(Address::default()),
            eth_client: Arc::new(DummyEthClient::new()),
        };
        match SessionImpl::new_from_master(params,  requester, payload) {
            Ok(_) => (),
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn runs_in_cluster_of_single_node() {
        let requester_keypair = Random.generate();
        let payload = vec![U256([1,2,3,4]), U256([5,6,7,8])];
        let (session, _) = prepare_decryption_in_cluster_of_single_node(&requester_keypair, payload, None, None);
        session.initialize().unwrap();
        // session is finished
        let state = session.state().lock();
        match state.deref() {
            SessionState::Master(MasterState::Completed(shadow)) => {
                assert_correct_proxy_dec(&requester_keypair, shadow);
            }
            _ => panic!("expected completion")
        }
    }

    #[test]
    fn fails_to_initialize_if_threshold_is_wrong() {
        let mut nodes = BTreeMap::new();
        let self_node_id = Random.generate().public().clone();
        nodes.insert(self_node_id.clone(), Random.generate().secret().clone());
        nodes.insert(
            Random.generate().public().clone(),
            Random.generate().secret().clone(),
        );
        let session = SessionImpl::new_from_master(
            SessionParams {
                meta: SessionMeta {
                    id: SessionId::from(DUMMY_SESSION_ID),
                    self_node_id: self_node_id.clone(),
                    master_node_id: self_node_id.clone(),
                    threshold: 2,
                    configured_nodes_count: 1,
                    connected_nodes_count: 1,
                },
                access_key: Random.generate().secret().clone(),
                decryption_key_share: DocumentKeyShare {
                    author: Default::default(),
                    threshold: 2,
                    public: Default::default(),
                    common_point: Some(Random.generate().public().clone()),
                    encrypted_point: Some(Random.generate().public().clone()),
                    versions: vec![DocumentKeyShareVersion {
                        hash: Default::default(),
                        id_numbers: nodes.clone(),
                        secret_share: Random.generate().secret().clone(),
                        coefficient_commitments: Some(vec![Random.generate().public().clone(), Random.generate().public().clone(), Random.generate().public().clone()])
                    }],
                },
                signing_key_share: DocumentKeyShare {
                    author: Default::default(),
                    threshold: 0,
                    public: Default::default(),
                    common_point: Some(Random.generate().public().clone()),
                    encrypted_point: Some(Random.generate().public().clone()),
                    versions: vec![DocumentKeyShareVersion {
                        hash: Default::default(),
                        id_numbers: nodes,
                        secret_share: Random.generate().secret().clone(),
                        coefficient_commitments: None
                    }],
                },
                acl_storage: Arc::new(DummyAclStorage::default()),
                cluster: Arc::new(DummyCluster::new(self_node_id.clone())),
                nonce: 0,
                self_public: Random.generate().public().clone(),
                log_contract_address: Some(Address::default()),
                eth_client: Arc::new(DummyEthClient::new()),
            },
            Requester::Signature(
                crypto::publickey::sign(
                    Random.generate().secret(),
                    &SessionId::from(DUMMY_SESSION_ID),
                )
                        .unwrap(),
                ),
               DUMMY_PAYLOAD.clone()
        )
        .unwrap()
        .0;
        assert_eq!(
            session.initialize(),
            Err(Error::ConsensusUnreachable)
        );
    }

    #[test]
    fn fails_to_initialize_when_already_initialized() {
        let (_, _, _, sessions) = prepare_decryption_sessions();
        assert_eq!(
            sessions[0]
                .initialize()
                .unwrap(),
            ()
        );
        assert_eq!(
            sessions[0]
                .initialize()
                .unwrap_err(),
            Error::InvalidStateForRequest
        );
    }

    #[test]
    fn fails_to_accept_initialization_when_already_initialized() {
        let (_, _, _, sessions) = prepare_decryption_sessions();
        assert_eq!(
            sessions[0]
                .initialize()
                .unwrap(),
            ()
        );
        assert_eq!(
            sessions[0].process_message(sessions[1].node(), &DecryptionWithPayloadMessage::KeyVersionNegotiation(DecryptionWithPayloadKeyVersionNegotiation {
                signing_key: KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
                    session: (*JOINT_SIGNATURE_KEY_ID).into(),
                    sub_session: sessions[0].core.access_key.clone().into(),
                    session_nonce: sessions[0].core.nonce
                }),
                decryption_key: KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
                    session: SessionId::from(DUMMY_SESSION_ID).into(),
                    sub_session: sessions[0].core.access_key.clone().into(),
                    session_nonce: sessions[0].core.nonce
                })
            })),
            Err(Error::InvalidMessage));
    }

    // #[test]
    // fn fails_to_partial_decrypt_if_requested_by_slave() {
    //     let (_, _, _, sessions) = prepare_decryption_sessions();
    //     assert_eq!(
    //         sessions[1]
    //             .on_consensus_message(
    //                 sessions[0].node(),
    //                 &message::DecryptionConsensusWithPayloadMessage {
    //                     session: SessionId::from(DUMMY_SESSION_ID).into(),
    //                     sub_session: sessions[0].access_key().clone().into(),
    //                     session_nonce: 0,
    //                     origin: None,
    //                     message: message::ConsensusMessageWithPayload::InitializeConsensusSession(
    //                         message::InitializeConsensusSessionWithPayload {
    //                             requester: Requester::Signature(
    //                                 crypto::publickey::sign(
    //                                     Random.generate().secret(),
    //                                     &SessionId::from(DUMMY_SESSION_ID)
    //                                 )
    //                                 .unwrap()
    //                             )
    //                             .into(),
    //                             version: Default::default(),
    //                             payload: DUMMY_PAYLOAD.iter().map(|x| x.into()).collect()
    //                         }
    //                     ),
    //                 }
    //             )
    //             .unwrap(),
    //         ()
    //     );
    //     assert_eq!(
    //         sessions[1]
    //             .on_partial_decryption_requested(
    //                 sessions[2].node(),
    //                 &message::RequestPartialDecryption {
    //                     session: SessionId::from(DUMMY_SESSION_ID).into(),
    //                     sub_session: sessions[0].access_key().clone().into(),
    //                     session_nonce: 0,
    //                     request_id: Random.generate().secret().clone().into(),
    //                     is_shadow_decryption: false,
    //                     is_broadcast_session: false,
    //                     nodes: sessions
    //                         .iter()
    //                         .map(|s| s.node().clone().into())
    //                         .take(4)
    //                         .collect(),
    //                 }
    //             )
    //             .unwrap_err(),
    //         Error::InvalidMessage
    //     );
    // }

    // #[test]
    // fn fails_to_partial_decrypt_if_wrong_number_of_nodes_participating() {
    //     let (_, _, _, sessions) = prepare_decryption_sessions();
    //     assert_eq!(
    //         sessions[1]
    //             .on_consensus_message(
    //                 sessions[0].node(),
    //                 &message::DecryptionConsensusWithPayloadMessage {
    //                     session: SessionId::from(DUMMY_SESSION_ID).into(),
    //                     sub_session: sessions[0].access_key().clone().into(),
    //                     session_nonce: 0,
    //                     origin: None,
    //                     message: message::ConsensusMessageWithPayload::InitializeConsensusSession(
    //                         message::InitializeConsensusSessionWithPayload {
    //                             requester: Requester::Signature(
    //                                 crypto::publickey::sign(
    //                                     Random.generate().secret(),
    //                                     &SessionId::from(DUMMY_SESSION_ID)
    //                                 )
    //                                 .unwrap()
    //                             )
    //                             .into(),
    //                             version: Default::default(),
    //                             payload: DUMMY_PAYLOAD.iter().map(|x| x.into()).collect()
    //                         }
    //                     ),
    //                 }
    //             )
    //             .unwrap(),
    //         ()
    //     );
    //     assert_eq!(
    //         sessions[1]
    //             .on_partial_decryption_requested(
    //                 sessions[0].node(),
    //                 &message::RequestPartialDecryption {
    //                     session: SessionId::from(DUMMY_SESSION_ID).into(),
    //                     sub_session: sessions[0].access_key().clone().into(),
    //                     session_nonce: 0,
    //                     request_id: Random.generate().secret().clone().into(),
    //                     is_shadow_decryption: false,
    //                     is_broadcast_session: false,
    //                     nodes: sessions
    //                         .iter()
    //                         .map(|s| s.node().clone().into())
    //                         .take(2)
    //                         .collect(),
    //                 }
    //             )
    //             .unwrap_err(),
    //         Error::InvalidMessage
    //     );
    // }

    // #[test]
    // fn fails_to_accept_partial_decrypt_if_not_waiting() {
    //     let (_, _, _, sessions) = prepare_decryption_sessions();
    //     assert_eq!(
    //         sessions[0]
    //             .on_partial_decryption(
    //                 sessions[1].node(),
    //                 &message::PartialDecryption {
    //                     session: SessionId::from(DUMMY_SESSION_ID).into(),
    //                     sub_session: sessions[0].access_key().clone().into(),
    //                     session_nonce: 0,
    //                     request_id: Random.generate().secret().clone().into(),
    //                     shadow_point: Random.generate().public().clone().into(),
    //                     decrypt_shadow: None,
    //                 }
    //             )
    //             .unwrap_err(),
    //         Error::InvalidStateForRequest
    //     );
    // }

    // #[test]
    // fn fails_to_accept_partial_decrypt_twice() {
    //     let (_, clusters, _, sessions) = prepare_decryption_sessions();
    //     sessions[0]
    //         .initialize(Default::default(), Default::default())
    //         .unwrap();
    //
    //     let mut pd_from = None;
    //     let mut pd_msg = None;
    //     do_messages_exchange_until(&clusters, &sessions, |from, _, msg| match msg {
    //         &Message::DecryptionWithPayload(DecryptionWithPayloadMessage::PartialDecryption(ref msg)) => {
    //             pd_from = Some(from.clone());
    //             pd_msg = Some(msg.clone());
    //             true
    //         }
    //         _ => false,
    //     })
    //     .unwrap();
    //
    //     assert_eq!(
    //         sessions[0]
    //             .on_partial_decryption(pd_from.as_ref().unwrap(), &pd_msg.clone().unwrap())
    //             .unwrap(),
    //         ()
    //     );
    //     assert_eq!(
    //         sessions[0]
    //             .on_partial_decryption(pd_from.as_ref().unwrap(), &pd_msg.unwrap())
    //             .unwrap_err(),
    //         Error::InvalidNodeForRequest
    //     );
    // }

    #[test]
    fn decryption_fails_on_session_timeout() {
        let (_, _, _, sessions) = prepare_decryption_sessions();
        assert!(sessions[0].decrypted_secret().is_none());
        sessions[0].on_session_timeout();
        let data = sessions[0].data.lock();
        match data.deref() {
            &SessionState::Failed(_) => (),
            _ => panic!("Expected SessionState::Failed(Error::ConsensusTemporaryUnreachable), got {:?}", data.deref()),
        }
        // assert_eq!(&SessionState::Failed(Error::ConsensusTemporaryUnreachable), &data);
        // assert_eq!(
        //     sessions[0].decrypted_secret().unwrap().unwrap_err(),
        //     Error::ConsensusTemporaryUnreachable
        // );
    }

    // #[test]
    // fn node_is_marked_rejected_when_timed_out_during_initialization_confirmation() {
    //     let (_, _, _, sessions) = prepare_decryption_sessions();
    //     sessions[0].initialize().unwrap();
    //
    //     // 1 node disconnects => we still can recover secret
    //     sessions[0].on_node_timeout(sessions[1].node());
    //     assert!(sessions[0]
    //         .data
    //         .lock()
    //         .consensus_session
    //         .consensus_job()
    //         .rejects()
    //         .contains_key(sessions[1].node()));
    //     assert_eq!(sessions[0].state(), ConsensusSessionState::EstablishingConsensus);
    //
    //     // 2 node are disconnected => we can not recover secret
    //     sessions[0].on_node_timeout(sessions[2].node());
    //     assert!(sessions[0].state() == ConsensusSessionState::Failed);
    // }

    // #[test]
    // fn session_does_not_fail_if_rejected_node_disconnects() {
    //     let (_, clusters, acl_storages, sessions) = prepare_decryption_sessions();
    //     let key_pair = Random.generate();
    //
    //     acl_storages[1].prohibit(
    //         public_to_address(key_pair.public()),
    //         SessionId::from(DUMMY_SESSION_ID),
    //     );
    //     sessions[0]
    //         .initialize()
    //         .unwrap();
    //
    //     do_messages_exchange_until(&clusters, &sessions, |_, _, _| {
    //         sessions[0].state() == ConsensusSessionState::WaitingForPartialResults
    //     })
    //     .unwrap();
    //
    //     // 1st node disconnects => ignore this
    //     sessions[0].on_node_timeout(sessions[1].node());
    //     assert_eq!(
    //         sessions[0].state(),
    //         ConsensusSessionState::EstablishingConsensus
    //     );
    // }

    // #[test]
    // fn session_does_not_fail_if_requested_node_disconnects() {
    //     let (_, clusters, _, sessions) = prepare_decryption_sessions();
    //     sessions[0]
    //         .initialize()
    //         .unwrap();
    //
    //     do_messages_exchange_until(&clusters, &sessions, |_, _, _| {
    //         sessions[0].state() == ConsensusSessionState::WaitingForPartialResults
    //     })
    //     .unwrap();
    //
    //     // 1 node disconnects => we still can recover secret
    //     sessions[0].on_node_timeout(sessions[1].node());
    //     assert_eq!(sessions[0].state(), ConsensusSessionState::EstablishingConsensus);
    //
    //     // 2 node are disconnected => we can not recover secret
    //     sessions[0].on_node_timeout(sessions[2].node());
    //     assert_eq!(sessions[0].state(), ConsensusSessionState::Failed);
    // }

    // #[test]
    // fn session_does_not_fail_if_node_with_shadow_point_disconnects() {
    //     let (_, clusters, _, sessions) = prepare_decryption_sessions();
    //     sessions[0]
    //         .initialize(Default::default(), Default::default())
    //         .unwrap();
    //
    //     do_messages_exchange_until(&clusters, &sessions, |_, _, _| {
    //         sessions[0].state() == ConsensusSessionState::WaitingForPartialResults
    //             && sessions[0]
    //                 .data
    //                 .lock()
    //                 .consensus_session
    //                 .computation_job()
    //                 .responses()
    //                 .len()
    //                 == 2
    //     })
    //     .unwrap();
    //
    //     // disconnects from the node which has already sent us its own shadow point
    //     let disconnected = sessions[0]
    //         .data
    //         .lock()
    //         .consensus_session
    //         .computation_job()
    //         .responses()
    //         .keys()
    //         .filter(|n| *n != sessions[0].node())
    //         .cloned()
    //         .nth(0)
    //         .unwrap();
    //     sessions[0].on_node_timeout(&disconnected);
    //     assert_eq!(
    //         sessions[0].state(),
    //         ConsensusSessionState::EstablishingConsensus
    //     );
    // }

    // #[test]
    // fn session_restarts_if_confirmed_node_disconnects() {
    //     let (_, clusters, _, sessions) = prepare_decryption_sessions();
    //     sessions[0]
    //         .initialize(Default::default(), Default::default())
    //         .unwrap();
    //
    //     do_messages_exchange_until(&clusters, &sessions, |_, _, _| {
    //         sessions[0].state() == ConsensusSessionState::WaitingForPartialResults
    //     })
    //     .unwrap();
    //
    //     // disconnects from the node which has already confirmed its participation
    //     let disconnected = sessions[0]
    //         .data
    //         .lock()
    //         .consensus_session
    //         .computation_job()
    //         .requests()
    //         .iter()
    //         .cloned()
    //         .nth(0)
    //         .unwrap();
    //     sessions[0].on_node_timeout(&disconnected);
    //     assert_eq!(
    //         sessions[0].state(),
    //         ConsensusSessionState::EstablishingConsensus
    //     );
    //     assert!(sessions[0]
    //         .data
    //         .lock()
    //         .consensus_session
    //         .computation_job()
    //         .rejects()
    //         .contains_key(&disconnected));
    //     assert!(!sessions[0]
    //         .data
    //         .lock()
    //         .consensus_session
    //         .computation_job()
    //         .requests()
    //         .contains(&disconnected));
    // }

    // #[test]
    // fn session_does_not_fail_if_non_master_node_disconnects_from_non_master_node() {
    //     let (_, clusters, _, sessions) = prepare_decryption_sessions();
    //     sessions[0].initialize().unwrap();
    //
    //     do_messages_exchange_until(&clusters, &sessions, |_, _, _| {
    //         sessions[0].state() == ConsensusSessionState::WaitingForPartialResults
    //     })
    //     .unwrap();
    //
    //     // disconnects from the node which has already confirmed its participation
    //     sessions[1].on_node_timeout(sessions[2].node());
    //     assert_eq!(sessions[0].state(), ConsensusSessionState::WaitingForPartialResults);
    //     assert_eq!(sessions[1].state(), ConsensusSessionState::ConsensusEstablished);
    // }

    #[test]
    fn complete_shadow_dec_session() {
        let (key_pair, clusters, _, sessions) = prepare_decryption_sessions();

        // now let's try to do a decryption
        sessions[0].initialize().unwrap();

        do_messages_exchange(&clusters, &sessions).unwrap();

        // now check that:
        // 5 of 5 sessions are in Finished state
        assert_all_finished(&sessions);
        assert_eq!(
            sessions
                .iter()
                .enumerate()
                .filter(|(i,s)| {
                    let state = s.state().lock();
                    match *state {
                        SessionState::Master(MasterState::Completed(_)) if i == &0 => true,
                        SessionState::Slave(SlaveState::Completed) if i != &0 => true,
                        _ => false,
                     }
                })
                .count(),
            5
        );

        let decrypted_secret = sessions[0].decrypted_secret().unwrap().unwrap();
        assert_correct_proxy_dec(&key_pair, &decrypted_secret);
    }

    fn assert_correct_proxy_dec(key_pair: &KeyPair, decrypted_secret: &ProxyEncryptedDocumentKey) {

        let mut c1 = decrypted_secret.common_point.clone();
        ec_math_utils::public_mul_secret(&mut c1, key_pair.secret()).unwrap();
        let mut decrypted_message = decrypted_secret.encrypted_point.clone();
        ec_math_utils::public_sub(&mut decrypted_message, &c1).unwrap();

        assert_eq!(decrypted_message, H512::from_str(SECRET_PLAIN).unwrap());
    }

    #[test]
    fn failed_shadow_dec_session() {
        let (key_pair, clusters, acl_storages, sessions) = prepare_decryption_sessions();

        // now let's try to do a decryption
        sessions[0].initialize().unwrap();

        // we need 4 out of 5 nodes to agree to do a decryption
        // let's say that 2 of these nodes are disagree
        let document = [1u8; 32].into();
        acl_storages[1].prohibit(public_to_address(key_pair.public()), document);
        acl_storages[2].prohibit(public_to_address(key_pair.public()), document);

        assert_eq!(
            do_messages_exchange(&clusters, &sessions).unwrap_err(),
            Error::ConsensusUnreachable
        );

        // check that master has failed state
        match *sessions[0].state().lock() {
            SessionState::Failed(_) => (),
            _ => panic!("expected failed state"),
        }
        // check that nodes 2 and 3 have failed consensus
        assert!(sessions[1..3].iter().all(|s| {
            let state = s.state().lock();
            match *state {
                SessionState::Master(MasterState::DecryptionConsensus(SessionMasterStateDecryptionConsensus { ref key_access_session, .. }))
                | SessionState::Slave(SlaveState::DecryptionConsensus(SessionSlaveStateDecryptionConsensus { ref key_access_session, .. }))
                | SessionState::Master(MasterState::Decryption(SessionMasterStateDecryption { ref key_access_session, .. }))
                | SessionState::Slave(SlaveState::Decryption(SessionSlaveStateDecryption { ref key_access_session, .. })) => {
                    key_access_session.state() == ConsensusSessionState::Failed
                }
                _ => false
            }
        }));
    }

    #[test]
    fn complete_shadow_dec_session_with_acl_check_failed_on_master() {
        let (key_pair, clusters, acl_storages, sessions) = prepare_decryption_sessions();

        // we need 4 out of 5 nodes to agree to do a decryption
        // let's say that 1 of these nodes (master) disagrees
        acl_storages[0].prohibit(
            public_to_address(key_pair.public()),
            SessionId::from(DUMMY_SESSION_ID),
        );

        // now let's try to do a shadow decryption
        sessions[0].initialize().unwrap();

        do_messages_exchange(&clusters, &sessions).unwrap();

        // now check that secret can still be decrypted
        assert_all_finished(&sessions);
        let decrypted_secret = sessions[0].decrypted_secret().unwrap().unwrap();
        assert_correct_proxy_dec(&key_pair, &decrypted_secret);
    }

    #[test]
    fn decryption_message_fails_when_nonce_is_wrong() {
        let (_, _, _, sessions) = prepare_decryption_sessions();
        assert_eq!(
            sessions[1].process_message(
                sessions[0].node(),
                &message::DecryptionWithPayloadMessage::KeyVersionNegotiation(
                    message::DecryptionWithPayloadKeyVersionNegotiation {
                        signing_key: KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
                            session: SessionId::from(DUMMY_SESSION_ID).into(),
                            sub_session: sessions[0].access_key().clone().into(),
                            session_nonce: 10
                        }),
                        decryption_key: KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
                            session: SessionId::from(DUMMY_SESSION_ID).into(),
                            sub_session: sessions[0].access_key().clone().into(),
                            session_nonce: 10
                        })
                    }
                )
            ),
            Err(Error::ReplayProtection)
        );
    }

    // #[test]
    // fn decryption_works_when_share_owners_are_isolated() {
    //     let (key_pair, clusters, _, sessions) = prepare_decryption_sessions();
    //
    //     // we need 4 out of 5 nodes to agree to do a decryption
    //     // let's say that 1 of these nodes (master) is isolated
    //     let isolated_node_id = sessions[4].core.meta.self_node_id.clone();
    //     for cluster in &clusters {
    //         cluster.remove_node(&isolated_node_id);
    //     }
    //
    //     // now let's try to do a decryption
    //     sessions[0].initialize().unwrap();
    //     do_messages_exchange(&clusters, &sessions).unwrap();
    //
    //     assert_all_finished(&sessions);
    //
    //     let decrypted_secret = sessions[0].decrypted_secret().unwrap().unwrap();
    //     assert_correct_shadow_dec(&key_pair, &decrypted_secret);
    // }

    // #[test]
    // fn decryption_session_origin_is_known_to_all_initialized_nodes() {
    //     let (_, clusters, _, sessions) = prepare_decryption_sessions();
    //     sessions[0]
    //         .initialize(
    //             Some(Address::from_low_u64_be(1)),
    //             Default::default()
    //         )
    //         .unwrap();
    //     do_messages_exchange(&clusters, &sessions).unwrap();
    //
    //     // all session must have origin set
    //     assert_eq!(
    //         5,
    //         sessions
    //             .iter()
    //             .filter(|&s| s.origin() == Some(Address::from_low_u64_be(1)))
    //             .count()
    //     );
    // }

    struct AclStorageTestParams {
        expected_address: Address,
        expected_document: ServerKeyId,
        expected_payload: Vec<U256>,
        return_value: bool,
        pub call_count: Arc<Mutex<i32>>
    }

    impl AclStorage for AclStorageTestParams {
        fn check(&self, _requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
            if document == &*JOINT_SIGNATURE_KEY_ID {
                Ok(true)
            }else{
                panic!("expected call to check_with_payload");
            }
        }

        fn check_with_payload(&self, requester: Address, document: &ServerKeyId, authorization_payload: &Vec<U256>) -> Result<bool, Error> {
            assert_eq!(self.expected_address, requester);
            assert_eq!(&self.expected_document, document);
            assert_eq!(&self.expected_payload, authorization_payload);
            {
                let mut call_count = self.call_count.lock();
                *call_count += 1;
            }
            Ok(self.return_value)
        }
    }

    fn assert_all_finished(sessions: &Vec<SessionImpl>) {
        for (i,session) in sessions.iter().enumerate() {
            assert!(session.is_finished(), "at {}", i);
        }
    }

    #[test]
    fn session_forwards_payload() {
        let requester = Random.generate();
        let document = SessionId::from(DUMMY_SESSION_ID);
        let payload = vec![U256([1,2,3,4])];
        let call_count = Arc::new(Mutex::new(0));
        let (_, clusters, _, sessions) = prepare_decryption_sessions_given_acl(requester.clone(), payload.clone(),|_| {
            AclStorageTestParams {
                expected_address: requester.address(),
                expected_document: document.clone(),
                expected_payload: payload.clone(),
                return_value: true,
                call_count: call_count.clone()
            }
        });
        sessions[0]
            .initialize()
            .unwrap();
        do_messages_exchange(&clusters, &sessions).unwrap();
        assert_all_finished(&sessions);
        assert_eq!(*call_count.lock(), 5);
    }

    #[test]
    fn session_forwards_empty_payload() {
        // let _ = ::env_logger::Builder::from_default_env()
        // 	.filter_level(LevelFilter::Debug)
        // 	.init();
        let requester = Random.generate();
        let document = SessionId::from(DUMMY_SESSION_ID);
        let payload = vec![];
        let call_count = Arc::new(Mutex::new(0));
        let (_, clusters, _, sessions) = prepare_decryption_sessions_given_acl(requester.clone(), payload.clone(),|_| {
            AclStorageTestParams {
                expected_address: requester.address(),
                expected_document: document.clone(),
                expected_payload: payload.clone(),
                return_value: true,
                call_count: call_count.clone()
            }
        });
        sessions[0]
            .initialize()
            .unwrap();
        do_messages_exchange(&clusters, &sessions).unwrap();
        assert_all_finished(&sessions);
        assert_eq!(*call_count.lock(), 5);
    }

    struct DummyChainClient {
        contract_address: Address,
    }

    impl SecretStoreChain for DummyChainClient {
        fn add_listener(&self, _target: Arc<dyn NewBlocksNotify>) {
            unimplemented!()
        }

        fn is_trusted(&self) -> bool {
            true
        }

        fn transact_contract(&self, _contract: Address, _tx_data: Bytes) -> Result<(), crypto::publickey::Error> {
            unimplemented!()
        }

        fn read_contract_address(&self, _registry_name: &str, _address: &ContractAddress) -> Option<Address> {
            Some(self.contract_address.clone())
        }

        fn call_contract(&self, _block_id: BlockId, _contract_address: Address, _data: Bytes) -> Result<Bytes, String> {
            unimplemented!()
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

    fn assert_correct_transaction(submitted_tx: &Vec<u8>, expected_nonce: U256, expected_gas_price: U256, expected_to: &Address, signing_public: &Public, chain_id: u64) -> H256 {
        let rlp = Rlp::new(submitted_tx);
        assert!(rlp.is_list());
        assert_eq!(rlp.item_count().unwrap(), 9);
        let nonce: U256 = rlp.val_at(0).unwrap();
        let gas_price: U256 = rlp.val_at(1).unwrap();
        let gas_limit: U256 = rlp.val_at(2).unwrap();
        let to: Address = rlp.val_at(3).unwrap();
        let value: U256 = rlp.val_at(4).unwrap();
        let data: Vec<u8> = rlp.val_at(5).unwrap();
        let v: u64 = rlp.val_at::<u64>(6).unwrap() - chain_id * 2 - 35;
        let r: H256 = rlp.val_at(7).unwrap();
        let s: H256 = rlp.val_at(8).unwrap();
        let signature = Signature::from_rsv(&r, &s, v as u8);
        assert_eq!(nonce, expected_nonce);
        assert_eq!(gas_price, expected_gas_price);
        assert_eq!(&to, expected_to);
        assert_eq!(value, U256::zero());
        let hash = RawTransaction {
            nonce,
            to: Some(to),
            value,
            gas_price,
            gas: gas_limit,
            data,
            chain_id
        }.hash();
        let is_valid = verify_public(&signing_public, &signature, &hash).unwrap();
        assert!(is_valid);
        return hash;
    }

    #[test]
    fn session_submits_valid_transaction() {
        // let _ = ::env_logger::Builder::from_default_env()
        // 	.filter_level(LevelFilter::Debug)
        // 	.init();
        let requester = KeyPair::from_secret("3b643388318f9faeb77d085c011bc9b36d0635ea8afd24804dfff51efcbd5b83".parse().unwrap()).unwrap();
        let payload = vec![];
        let contract_address = Address::from_str("731a10897d267e19b34503ad902d0a29173ba4b1").unwrap();
        let nonce = U256([0,0,0,0]);
        let gas_price = U256([100000,0,0,0]);
        let chain_id = 536u64;
        let (_, clusters, _, sessions, eth_clients) = prepare_decryption_sessions_given_eth_client(requester.clone(), payload.clone(), single_dummy_eth_client(
             DummyEthClient::new_with(gas_price.clone(), Some(chain_id))
        ), Some(contract_address.clone()));
        sessions[0]
            .initialize()
            .unwrap();
        do_messages_exchange(&clusters, &sessions).unwrap();
        assert_all_finished(&sessions);

        let signing_public = sessions[0].core.signing_key_share.public.clone();
        let signing_address = parity_crypto::publickey::public_to_address(&signing_public);

        // only master chain client submitted a transaction
        let (_, submitted_tx) = {
            let submitted_tx = eth_clients[0].transactions();
            assert_eq!(submitted_tx.len(), 1);
            assert_eq!(submitted_tx[&signing_address].len(), 1);
            submitted_tx[&signing_address][0].clone()
        };

        let tx_hash = assert_correct_transaction(&submitted_tx, nonce, gas_price,&contract_address, &signing_public, chain_id);
        assert_eq!(tx_hash, "9ad8cac580b89b89a9fd7ec009b4a7af39f40d1f069fa2c7a1c30fa0dba7114b".parse().unwrap());
    }

    #[test]
    fn cluster_of_single_node_submits_valid_transaction() {
        let requester = Random.generate();
        let payload = vec![U256([1,2,3,4]), U256([5,6,7,8])];
        let contract_address = Address::from_str("731a10897d267e19b34503ad902d0a29173ba4b1").unwrap();
        let nonce = U256([0,0,0,0]);
        let gas_price = U256([10,0,0,0]);
        let chain_id = 1565;
        let eth_client = Arc::new(DummyEthClient::new_with(gas_price.clone(), Some(chain_id)));
        let (session, signing_public) = prepare_decryption_in_cluster_of_single_node(&requester, payload, Some(eth_client.clone()), Some(contract_address.clone()));
        session.initialize().unwrap();
        // session is finished
        assert_all_finished(&vec![session]);

        // check signature
        let submitted_transactions = eth_client.transactions();
        // expect 1 transaction from 1 account
        assert_eq!(submitted_transactions.len(), 1);
        let signing_address = parity_crypto::publickey::public_to_address(&signing_public);
        assert_eq!(submitted_transactions[&signing_address].len(), 1);

        let (_, submitted_tx) = submitted_transactions[&signing_address][0].clone();
        // let submitted_tx = chain_client.submitted_tx.lock().as_ref().unwrap().clone();
        assert_correct_transaction(&submitted_tx, nonce, gas_price, &contract_address, &signing_public, chain_id);
    }

    struct StoringClusterDummy {
        pub broadcast: Mutex<Vec<Message>>,
        pub send_to: Mutex<HashMap<NodeId, Vec<Message>>>,
    }

    impl StoringClusterDummy {
        pub fn new() -> Self {
            StoringClusterDummy {
                broadcast: Mutex::new(vec![]),
                send_to: Mutex::new(HashMap::new())
            }
        }
    }

    impl Cluster for StoringClusterDummy {
        fn broadcast(&self, message: Message) -> Result<(), Error> {
            let mut vec_ref = self.broadcast.lock();
            vec_ref.push(message);
            Ok(())
        }

        fn send(&self, to: &NodeId, message: Message) -> Result<(), Error> {
            let mut map = self.send_to.lock();
            match map.get_mut(to) {
                Some(v) => v.push(message),
                None => {
                    map.insert(to.clone(), vec![message]);
                }
            }
            Ok(())
        }

        fn is_connected(&self, _node: &NodeId) -> bool {
            unimplemented!()
        }

        fn nodes(&self) -> BTreeSet<NodeId> {
            unimplemented!()
        }

        fn configured_nodes_count(&self) -> usize {
            unimplemented!()
        }

        fn connected_nodes_count(&self) -> usize {
            unimplemented!()
        }
    }

    #[test]
    fn key_version_negotiation_buffer_empty_after_construction() {
        let mut buf = KeyVersionNegotiationBuffer::new();
        // no messages in buffer after construction
        let cluster = StoringClusterDummy::new();
        buf.send_to_cluster(&cluster).unwrap();
        assert_eq!(0, cluster.broadcast.lock().len());
        assert_eq!(0, cluster.send_to.lock().len());
    }

    #[test]
    fn key_version_negotiation_buffer_correctly_broadcasts() {
        let mut buf = KeyVersionNegotiationBuffer::new();
        let msg1 = KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
            session: SerializableH256::from(DUMMY_SESSION_ID),
            sub_session: Random.generate().secret().clone().into(),
            session_nonce: 0
        });
        let msg2 = KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
            session: SerializableH256::from(DUMMY_SESSION_ID),
            sub_session: Random.generate().secret().clone().into(),
            session_nonce: 1
        });
        buf.buffer_broadcast_decryption(msg1.clone()).unwrap();
        buf.buffer_broadcast_signing(msg2.clone()).unwrap();

        let cluster = StoringClusterDummy::new();
        buf.send_to_cluster(&cluster).unwrap();
        let vec = cluster.broadcast.lock();
        assert_eq!(1, vec.len());
        match vec[0] {
            Message::DecryptionWithPayload(DecryptionWithPayloadMessage::KeyVersionNegotiation(ref dual_negotiation)) => {
                assert_eq!(format!("{:?}", &msg1), format!("{:?}", dual_negotiation.decryption_key));
                assert_eq!(format!("{:?}", &msg2), format!("{:?}", dual_negotiation.signing_key));
            }
            _ => panic!("Unexpected message")
        }
        assert_eq!(0, cluster.send_to.lock().len());
    }

    #[test]
    fn key_version_negotiation_buffer_correctly_sends() {
        let mut buf = KeyVersionNegotiationBuffer::new();
        let msg1 = KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
            session: SerializableH256::from(DUMMY_SESSION_ID),
            sub_session: Random.generate().secret().clone().into(),
            session_nonce: 0
        });
        let msg2 = KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
            session: SerializableH256::from(DUMMY_SESSION_ID),
            sub_session: Random.generate().secret().clone().into(),
            session_nonce: 1
        });
        let msg3 = KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
            session: SerializableH256::from(DUMMY_SESSION_ID),
            sub_session: Random.generate().secret().clone().into(),
            session_nonce: 2
        });
        let msg4 = KeyVersionNegotiationMessage::RequestKeyVersions(RequestKeyVersions {
            session: SerializableH256::from(DUMMY_SESSION_ID),
            sub_session: Random.generate().secret().clone().into(),
            session_nonce: 3
        });
        let n1 = Random.generate().public().clone();
        let n2 = Random.generate().public().clone();

        buf.buffer_send_decryption(&n1, msg1.clone()).unwrap();
        buf.buffer_send_signing(&n1, msg3.clone()).unwrap();
        buf.buffer_send_signing(&n2, msg4.clone()).unwrap();
        buf.buffer_send_decryption(&n2, msg2.clone()).unwrap();

        let cluster = StoringClusterDummy::new();

        buf.send_to_cluster(&cluster).unwrap();

        assert_eq!(0, cluster.broadcast.lock().len());
        let map = cluster.send_to.lock();
        assert_eq!(2, map.len());
        let msgs_for_n1 = map.get(&n1).unwrap();
        assert_eq!(1, msgs_for_n1.len());
        match &msgs_for_n1[0] {
            Message::DecryptionWithPayload(DecryptionWithPayloadMessage::KeyVersionNegotiation(ref dual_negotiation)) => {
                assert_eq!(
                    format!("{:?}", dual_negotiation.decryption_key),
                    format!("{:?}", msg1)
                );
                assert_eq!(
                    format!("{:?}", dual_negotiation.signing_key),
                    format!("{:?}", msg3)
                );
            },
            _ => panic!("Unexpected")
        }
        let msgs_for_n2 = map.get(&n2).unwrap();
        assert_eq!(1, msgs_for_n2.len());
        match &msgs_for_n2[0] {
            Message::DecryptionWithPayload(DecryptionWithPayloadMessage::KeyVersionNegotiation(ref dual_negotiation)) => {
                assert_eq!(
                    format!("{:?}", dual_negotiation.decryption_key),
                    format!("{:?}", msg2)
                );
                assert_eq!(
                    format!("{:?}", dual_negotiation.signing_key),
                    format!("{:?}", msg4)
                );
            },
            _ => panic!("Unexpected")
        }
    }

    #[test]
    fn test_append_transaction() {
        let tx_data = "d7ec193d0000000000000000000000000000002874b72cce0ef4e22aaba3d7c60906763d6138383364616663343830643436366565303465306436646139383662643738000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000030000000000254b00c36b9b67c76eca686090bf127ef61fe333fd0c9085f412ef0000000000226634642432ee40440435463163e0da59d7b6e5ae22ab591b0c4800000000000882d3ea3b061d1d6051cea15e4046daa547ad5c13ba4fd1c0b305";
        let tx_data: Vec<u8> = tx_data.from_hex().unwrap();
        let nonce = U256([1254,0,0,0]);
        let gas_price = U256([1000000000, 0, 0, 0]);
        let gas_limit = U256([21000,0,0,0]);
        let contract_address = Address::from_str("731a10897d267e19b34503ad902d0a29173ba4b1").unwrap();
        let chain_id: u64 = 1234;
        let mut rlp = RlpStream::new();
        rlp.begin_unbounded_list();
        append_transaction(&mut rlp, &nonce, &gas_price, &gas_limit, &contract_address, &U256::zero(), &tx_data);
        rlp.append(&chain_id);
        rlp.append(&U256::zero());
        rlp.append(&U256::zero());
        rlp.finalize_unbounded_list();
        let tx = rlp.out();
        assert_eq!(
            format!("0x{}", tx.to_hex()),
            // generated with https://toolkit.abdk.consulting/ethereum#transaction
            "0xf9010c8204e6843b9aca0082520894731a10897d267e19b34503ad902d0a29173ba4b180b8e4d7ec193d0000000000000000000000000000002874b72cce0ef4e22aaba3d7c60906763d6138383364616663343830643436366565303465306436646139383662643738000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000030000000000254b00c36b9b67c76eca686090bf127ef61fe333fd0c9085f412ef0000000000226634642432ee40440435463163e0da59d7b6e5ae22ab591b0c4800000000000882d3ea3b061d1d6051cea15e4046daa547ad5c13ba4fd1c0b3058204d28080"
        );
    }

    #[test]
    fn test_transaction_hash() {
        let tx = "f9010c8204e6843b9aca0082520894731a10897d267e19b34503ad902d0a29173ba4b180b8e4d7ec193d0000000000000000000000000000002874b72cce0ef4e22aaba3d7c60906763d6138383364616663343830643436366565303465306436646139383662643738000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000030000000000254b00c36b9b67c76eca686090bf127ef61fe333fd0c9085f412ef0000000000226634642432ee40440435463163e0da59d7b6e5ae22ab591b0c4800000000000882d3ea3b061d1d6051cea15e4046daa547ad5c13ba4fd1c0b3058204d28080".from_hex().unwrap();
        let hash = hash_transaction(&tx);
        assert_eq!(
            format!("0x{:x}", hash),
            // generated with web3.utils.keccak256
            "0xfb5f4292773238838e57dcdf5ac65dae2257955be98fd57d82beffbb25c8da5f"
        );

    }

    #[test]
    fn fails_if_log_contract_not_set() {
        let mut nodes = BTreeMap::new();
        let self_node_id = Random.generate().public().clone();
        let other_node_id = Random.generate().public().clone();
        nodes.insert(self_node_id, Random.generate().secret().clone());
        nodes.insert(other_node_id.clone(), Random.generate().secret().clone());
        let cluster = DummyCluster::new(self_node_id.clone());
        cluster.add_node(other_node_id);

        let keypair = Random.generate();
        let requester = Requester::Public(keypair.public().clone());
        let from_master = SessionImpl::new_from_master(
            SessionParams {
                meta: SessionMeta {
                    id: SessionId::from([1u8; 32]),
                    self_node_id: self_node_id.clone(),
                    master_node_id: self_node_id.clone(),
                    threshold: 0,
                    configured_nodes_count: 1,
                    connected_nodes_count: 1,
                },
                access_key: Random.generate().secret().clone(),
                decryption_key_share: random_key_share(nodes.clone()),
                signing_key_share: random_key_share(nodes.clone()),
                acl_storage: Arc::new(DummyAclStorage::default()),
                cluster: Arc::new(DummyCluster::new(self_node_id.clone())),
                nonce: 0,
                self_public: Default::default(),
                log_contract_address: None,
                eth_client: Arc::new(DummyEthClient::new()),
            },
            requester.clone(),
            vec![]
        );
        assert!(from_master.is_err());

        let from_slave = SessionImpl::new_from_slave(
            SessionParams {
                meta: SessionMeta {
                    id: SessionId::from([1u8; 32]),
                    self_node_id: self_node_id.clone(),
                    master_node_id: self_node_id.clone(),
                    threshold: 0,
                    configured_nodes_count: 1,
                    connected_nodes_count: 1,
                },
                access_key: Random.generate().secret().clone(),
                decryption_key_share: random_key_share(nodes.clone()),
                signing_key_share: random_key_share(nodes),
                acl_storage: Arc::new(DummyAclStorage::default()),
                cluster: Arc::new(cluster),
                nonce: 0,
                self_public: Default::default(),
                log_contract_address: None,
                eth_client: Arc::new(DummyEthClient::new()),
            }
        );
        assert!(from_slave.is_err());
    }
}
