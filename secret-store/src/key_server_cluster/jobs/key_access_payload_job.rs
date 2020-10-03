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

use ethereum_types::U256;
use key_server_cluster::jobs::job_session::{
    JobExecutor, JobPartialRequestAction, JobPartialResponseAction,
};
use key_server_cluster::{AclStorage, Error, NodeId, Requester, SessionId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Purpose of this job is to construct set of nodes, which have agreed to provide access to the given key for the given requestor.
pub struct KeyAccessWithPayloadJob {
    /// Key id.
    id: SessionId,
    /// ACL storage.
    acl_storage: Arc<dyn AclStorage>,
    /// Job state
    state: KeyAccessWithPayloadState,
    /// true if slave owns key share of requested version
    has_key_share: bool,
}

enum KeyAccessWithPayloadState {
    PARTIAL,
    FULL(Requester, Vec<U256>),
}

pub struct KeyAccessWithPayloadPartialJobRequest {
    pub requester: Requester,
    pub payload: Vec<U256>,
}

impl KeyAccessWithPayloadJob {
    pub fn new_on_slave(id: SessionId, acl_storage: Arc<dyn AclStorage>) -> Self {
        KeyAccessWithPayloadJob {
            id,
            acl_storage,
            state: KeyAccessWithPayloadState::PARTIAL,
            has_key_share: true,
        }
    }

    pub fn new_on_master(
        id: SessionId,
        acl_storage: Arc<dyn AclStorage>,
        requester: Requester,
        payload: Vec<U256>,
    ) -> Self {
        KeyAccessWithPayloadJob {
            id,
            acl_storage,
            state: KeyAccessWithPayloadState::FULL(requester, payload),
            has_key_share: true,
        }
    }
    
    pub fn set_has_key_share(&mut self, has_key_share: bool) {
        self.has_key_share = has_key_share;
    }

    pub fn requester(&self) -> Option<&Requester> {
        match &self.state {
            KeyAccessWithPayloadState::PARTIAL => None,
            KeyAccessWithPayloadState::FULL(requester, _) => Some(requester),
        }
    }
}

impl JobExecutor for KeyAccessWithPayloadJob {
    type PartialJobRequest = KeyAccessWithPayloadPartialJobRequest;
    type PartialJobResponse = bool;
    type JobResponse = BTreeSet<NodeId>;

    fn prepare_partial_request(
        &self,
        _node: &NodeId,
        _nodes: &BTreeSet<NodeId>,
    ) -> Result<KeyAccessWithPayloadPartialJobRequest, Error> {
        match &self.state {
            KeyAccessWithPayloadState::FULL(requester, payload) => {
                Ok(KeyAccessWithPayloadPartialJobRequest {
                    requester: requester.clone(),
                    payload: payload.clone(),
                })
            }
            KeyAccessWithPayloadState::PARTIAL => Err(Error::Internal(
                "prepare_partial_request must be called on master node".into(),
            )),
        }
    }

    fn process_partial_request(
        &mut self,
        partial_request: KeyAccessWithPayloadPartialJobRequest,
    ) -> Result<JobPartialRequestAction<bool>, Error> {
        if !self.has_key_share {
            return Ok(JobPartialRequestAction::Reject(false));
        }
        //update state
        self.state = KeyAccessWithPayloadState::FULL(partial_request.requester.clone(), partial_request.payload.clone());

        self.acl_storage
            .check_with_payload(
                partial_request
                    .requester
                    .address(&self.id)
                    .map_err(Error::InsufficientRequesterData)?,
                &self.id,
                &partial_request.payload,
            )
            .map(|is_confirmed| {
                if is_confirmed {
                    JobPartialRequestAction::Respond(true)
                } else {
                    JobPartialRequestAction::Reject(false)
                }
            })
    }

    fn check_partial_response(
        &mut self,
        _sender: &NodeId,
        partial_response: &bool,
    ) -> Result<JobPartialResponseAction, Error> {
        Ok(if *partial_response {
            JobPartialResponseAction::Accept
        } else {
            JobPartialResponseAction::Reject
        })
    }

    fn compute_response(
        &self,
        partial_responses: &BTreeMap<NodeId, bool>,
    ) -> Result<BTreeSet<NodeId>, Error> {
        Ok(partial_responses.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use crypto::publickey::{Random, Generator};
    use key_server_cluster::jobs::key_access_payload_job::KeyAccessWithPayloadJob;
    use types::Requester;
    use ::{ServerKeyId, Error};
    use ethereum_types::{U256, Address, H256};
    use acl_storage::AclStorage;
    use std::sync::Arc;
    use key_server_cluster::jobs::job_session::{JobExecutor, JobPartialRequestAction, JobPartialResponseAction};
    use std::collections::{BTreeSet, BTreeMap};

    struct AclStorageMockPanic;

    impl AclStorage for AclStorageMockPanic {
        fn check(&self, _: Address, _: &ServerKeyId) -> Result<bool, Error> {
            panic!("check should not be called");
        }

        fn check_with_payload(&self, _: Address, _: &ServerKeyId, _: &Vec<U256>) -> Result<bool, Error> {
            panic!("check_with_payload should not be called");
        }
    }

    struct AclStorageMock {
        expected_address: Address,
        expected_document: ServerKeyId,
        expected_payload: Vec<U256>,
    }

    impl AclStorage for AclStorageMock {
        fn check(&self, _: Address, _: &ServerKeyId) -> Result<bool, Error> {
            panic!("check should not be called")
        }

        fn check_with_payload(&self, requester: Address, document: &ServerKeyId, authorization_payload: &Vec<U256>) -> Result<bool, Error> {
            assert_eq!(self.expected_address, requester);
            assert_eq!(&self.expected_document, document);
            assert_eq!(&self.expected_payload, authorization_payload);
            return Ok(true);
        }
    }

    #[test]
    fn test_key_access_payload_job() {
        let session_id = H256([0; 32]);
        let master_acl: Arc<dyn AclStorage> = Arc::new(AclStorageMockPanic);
        let requester = Requester::Public(Random.generate().public().clone());
        let payload = vec![U256([1,2,3,4]), U256([5,6,7,8])];
        let mut master_job = KeyAccessWithPayloadJob::new_on_master(session_id.clone(), master_acl, requester.clone(), payload.clone());

        let slave_acl: Arc<dyn AclStorage> = Arc::new(AclStorageMock {
            expected_address: requester.address(&session_id).unwrap(),
            expected_document: session_id.clone(),
            expected_payload: payload.clone(),
        });
        let mut slave_job = KeyAccessWithPayloadJob::new_on_slave(session_id.clone(), slave_acl);

        //assume both have key shares
        master_job.set_has_key_share(true);
        slave_job.set_has_key_share(true);

        let master_id = Random.generate().public().clone();
        let slave_id = Random.generate().public().clone();
        let mut nodes = BTreeSet::new();
        nodes.insert(master_id.clone());
        nodes.insert(slave_id.clone());

        // run interaction
        let partial_request = master_job.prepare_partial_request(&slave_id, &nodes).unwrap();
        let partial_request_action = slave_job.process_partial_request(partial_request).unwrap();
        let partial_response = match partial_request_action {
            JobPartialRequestAction::Respond(response) => response,
            _ => panic!("expected slave to respond")
        };
        let response_action = master_job.check_partial_response(&slave_id, &partial_response).unwrap();
        assert_eq!(JobPartialResponseAction::Accept, response_action);
        let mut partial_responses = BTreeMap::new();
        partial_responses.insert(slave_id.clone(), partial_response);
        // compute final outcome
        let result = master_job.compute_response(&partial_responses).unwrap();
        let mut expected_result = BTreeSet::new();
        expected_result.insert(slave_id.clone());
        assert_eq!(expected_result, result);
    }

    struct AclStorageMockReject;

    impl AclStorage for AclStorageMockReject {
        fn check(&self, _: Address, _: &ServerKeyId) -> Result<bool, Error> {
            panic!("check should not be called");
        }

        fn check_with_payload(&self, _: Address, _: &ServerKeyId, _: &Vec<U256>) -> Result<bool, Error> {
            return Ok(false);
        }
    }

    #[test]
    fn test_key_access_payload_job_reject() {
        let session_id = H256([0; 32]);
        let master_acl: Arc<dyn AclStorage> = Arc::new(AclStorageMockPanic);
        let slave_acl: Arc<dyn AclStorage> = Arc::new(AclStorageMockReject);
        let requester = Requester::Public(Random.generate().public().clone());
        let payload = vec![U256([1,2,3,4]), U256([5,6,7,8])];
        let mut master_job = KeyAccessWithPayloadJob::new_on_master(session_id.clone(), master_acl, requester.clone(), payload.clone());
        let mut slave_job = KeyAccessWithPayloadJob::new_on_slave(session_id.clone(), slave_acl);

        //assume both have key shares
        master_job.set_has_key_share(true);
        slave_job.set_has_key_share(true);

        let master_id = Random.generate().public().clone();
        let slave_id = Random.generate().public().clone();
        let mut nodes = BTreeSet::new();
        nodes.insert(master_id.clone());
        nodes.insert(slave_id.clone());

        // run interaction
        let partial_request = master_job.prepare_partial_request(&slave_id, &nodes).unwrap();
        let partial_request_action = slave_job.process_partial_request(partial_request).unwrap();
        match partial_request_action {
            JobPartialRequestAction::Reject(_) => (),
            _ => panic!("expected slave not to respond")
        };
    }

    struct AclStorageMockAccept;

    impl AclStorage for AclStorageMockAccept {
        fn check(&self, _: Address, _: &ServerKeyId) -> Result<bool, Error> {
            panic!("check should not be called");
        }

        fn check_with_payload(&self, _: Address, _: &ServerKeyId, _: &Vec<U256>) -> Result<bool, Error> {
            Ok(true)
        }
    }

    #[test]
    fn test_key_access_payload_no_key_shares() {
        let session_id = H256([0; 32]);
        let master_acl: Arc<dyn AclStorage> = Arc::new(AclStorageMockPanic);
        let slave_acl: Arc<dyn AclStorage> = Arc::new(AclStorageMockAccept);
        let requester = Requester::Public(Random.generate().public().clone());
        let payload = vec![U256([1,2,3,4]), U256([5,6,7,8])];
        let mut master_job = KeyAccessWithPayloadJob::new_on_master(session_id.clone(), master_acl, requester.clone(), payload.clone());
        let mut slave_job = KeyAccessWithPayloadJob::new_on_slave(session_id.clone(), slave_acl);

        //assume master has key shares
        master_job.set_has_key_share(true);
        slave_job.set_has_key_share(false);

        let master_id = Random.generate().public().clone();
        let slave_id = Random.generate().public().clone();
        let mut nodes = BTreeSet::new();
        nodes.insert(master_id.clone());
        nodes.insert(slave_id.clone());

        // run interaction
        let partial_request = master_job.prepare_partial_request(&slave_id, &nodes).unwrap();
        let partial_request_action = slave_job.process_partial_request(partial_request).unwrap();
        match partial_request_action {
            JobPartialRequestAction::Reject(_) => (),
            _ => panic!("expected slave not to respond")
        };
    }
}
