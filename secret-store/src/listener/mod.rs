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

pub mod http_listener;
pub mod service_contract;
pub mod service_contract_aggregate;
pub mod service_contract_listener;
mod tasks_queue;

use ethereum_types::U256;
use std::collections::BTreeSet;
use std::sync::Arc;
use futures::Future;
use traits::{ServerKeyGenerator, DocumentKeyServer, MessageSigner, AdminSessionsServer, KeyServer};
use types::{Error, Public, MessageHash, EncryptedMessageSignature, RequestSignature, ServerKeyId,
	EncryptedDocumentKey, EncryptedDocumentKeyShadow, NodeId, Requester};
#[cfg(test)]
use key_server_cluster::ClusterClient;
use key_server_cluster::decryption_session_with_payload::ProxyEncryptedDocumentKey;


/// Available API mask.
#[derive(Debug, Default)]
pub struct ApiMask {
	/// Accept server key generation requests.
	pub server_key_generation_requests: bool,
	/// Accept server key retrieval requests.
	pub server_key_retrieval_requests: bool,
	/// Accept document key store requests.
	pub document_key_store_requests: bool,
	/// Accept document key shadow retrieval requests.
	pub document_key_shadow_retrieval_requests: bool,
}

/// Combined HTTP + service contract listener.
pub struct Listener {
	key_server: Arc<dyn KeyServer>,
	_http: Option<http_listener::KeyServerHttpListener>,
	_contract: Option<Arc<service_contract_listener::ServiceContractListener>>,
}

impl ApiMask {
	/// Create mask that accepts all requests.
	pub fn all() -> Self {
		ApiMask {
			server_key_generation_requests: true,
			server_key_retrieval_requests: true,
			document_key_store_requests: true,
			document_key_shadow_retrieval_requests: true,
		}
	}
}

impl Listener {
	/// Create new listener.
	pub fn new(key_server: Arc<dyn KeyServer>, http: Option<http_listener::KeyServerHttpListener>, contract: Option<Arc<service_contract_listener::ServiceContractListener>>) -> Self {
		Self {
			key_server: key_server,
			_http: http,
			_contract: contract,
		}
	}
}

impl KeyServer for Listener {
	#[cfg(test)]
	fn cluster(&self) -> Arc<dyn ClusterClient> {
		self.key_server.cluster()
	}
}

impl ServerKeyGenerator for Listener {
	fn generate_key(
		&self,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
		self.key_server.generate_key(key_id, author, threshold)
	}

	fn restore_key_public(
		&self,
		key_id: ServerKeyId,
		author: Requester,
	) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
		self.key_server.restore_key_public(key_id, author)
	}

	fn generate_joint_signature_key(&self) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
		self.key_server.generate_joint_signature_key()
	}
}

impl DocumentKeyServer for Listener {
	fn store_document_key(
		&self,
		key_id: ServerKeyId,
		author: Requester,
		common_point: Public,
		encrypted_document_key: Public,
	) -> Box<dyn Future<Item=(), Error=Error> + Send> {
		self.key_server.store_document_key(key_id, author, common_point, encrypted_document_key)
	}

	fn generate_document_key(
		&self,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Box<dyn Future<Item=EncryptedDocumentKey, Error=Error> + Send> {
		self.key_server.generate_document_key(key_id, author, threshold)
	}

	fn restore_document_key(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Box<dyn Future<Item=EncryptedDocumentKey, Error=Error> + Send> {
		self.key_server.restore_document_key(key_id, requester)
	}

	fn restore_document_key_shadow(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Box<dyn Future<Item=EncryptedDocumentKeyShadow, Error=Error> + Send> {
		self.key_server.restore_document_key_shadow(key_id, requester)
	}

	fn restore_document_key_shadow_payload(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
		payload: Vec<U256>,
	) -> Box<dyn Future<Item = ProxyEncryptedDocumentKey, Error = Error> + Send> {
		self.key_server.restore_document_key_shadow_payload(key_id, requester, payload)
    	}
}

impl MessageSigner for Listener {
	fn sign_message_schnorr(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
		message: MessageHash,
	) -> Box<dyn Future<Item=EncryptedMessageSignature, Error=Error> + Send> {
		self.key_server.sign_message_schnorr(key_id, requester, message)
	}

	fn sign_message_ecdsa(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
		message: MessageHash,
	) -> Box<dyn Future<Item=EncryptedMessageSignature, Error=Error> + Send> {
		self.key_server.sign_message_ecdsa(key_id, requester, message)
	}
}

impl AdminSessionsServer for Listener {
	fn change_servers_set(
		&self,
		old_set_signature: RequestSignature,
		new_set_signature: RequestSignature,
		new_servers_set: BTreeSet<NodeId>,
	) -> Box<dyn Future<Item=(), Error=Error> + Send> {
		self.key_server.change_servers_set(old_set_signature, new_set_signature, new_servers_set)
	}
}
