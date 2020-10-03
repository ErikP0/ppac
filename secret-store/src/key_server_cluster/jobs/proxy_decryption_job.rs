use key_server_cluster::{NodeId, DocumentKeyShare};
use crypto::publickey::{Public, Secret};
use ethereum_types::H256;
use key_server_cluster::jobs::job_session::{JobExecutor, JobPartialResponseAction, JobPartialRequestAction};
use std::collections::{BTreeMap, BTreeSet};
use key_server_cluster::math;
use Error;
use key_server_cluster::math::PartialDecryptionShare;

pub struct ProxyDecryptionJob {
    /// This node id.
    self_node_id: NodeId,
    /// Requester public key.
    requester: Public,
    /// Key share.
    key_share: DocumentKeyShare,
    /// Key version.
    key_version: H256,
    /// a nonce for this job
    nonce: Secret,
}

pub type ProxyDecryptionJobRequest = ();

#[derive(Clone)]
pub struct ProxyDecryptionJobResponse {
    /// ElGamal ciphertext part 1: C_1 = k * G
    pub common_point: Public,
    /// ElGamal ciphertext part 2: C_2 = M + k * R
    pub encrypted_point: Public,
}

impl ProxyDecryptionJob {
    pub fn new(self_node_id: NodeId, requester: Public, key_share: DocumentKeyShare, key_version: H256, nonce: Secret) -> Result<ProxyDecryptionJob, Error> {
        let has_coefficient_commitments = key_share.version(&key_version)?.coefficient_commitments.is_some();
        if !has_coefficient_commitments {
            return Err(Error::EthKey("Key has not been generated with coefficient commitments".to_string()));
        }
        Ok(ProxyDecryptionJob {
            self_node_id,
            requester,
            key_share,
            key_version,
            nonce
        })
    }
}

impl JobExecutor for ProxyDecryptionJob {
    type PartialJobRequest = ProxyDecryptionJobRequest;
    type PartialJobResponse = PartialDecryptionShare;
    type JobResponse = ProxyDecryptionJobResponse;

    fn prepare_partial_request(&self, _: &NodeId, _: &BTreeSet<NodeId>) -> Result<Self::PartialJobRequest, Error> {
        Ok(())
    }

    fn process_partial_request(&mut self, _partial_request: Self::PartialJobRequest) -> Result<JobPartialRequestAction<Self::PartialJobResponse>, Error> {
        // access share
        let key = self.key_share.version(&self.key_version)?;
        let self_id = key.id_numbers.get(&self.self_node_id).expect("self participates");
        let common_point = self.key_share.common_point.as_ref().expect("proxy decryption is only possible if a encrypted value is stored");
        let encrypted_point = self.key_share.encrypted_point.as_ref().expect("proxy decryption is only possible if a encrypted value is stored");
        let share_commitment = math::compute_share_commitment(key.coefficient_commitments.as_ref().expect("checked in contructor"), self_id)?;

        let nonce_point = math::compute_public_share(&self.nonce)?;
        let public_knowledge = vec![common_point.clone(), encrypted_point.clone(), share_commitment.clone(), self.requester.clone(), nonce_point];
        let decryption_share = math::compute_decryption_share(&key.secret_share, common_point, &self.requester, &public_knowledge)?;
        Ok(JobPartialRequestAction::Respond(decryption_share))
    }

    fn check_partial_response(&mut self, sender: &NodeId, partial_response: &Self::PartialJobResponse) -> Result<JobPartialResponseAction, Error> {
        let key = self.key_share.version(&self.key_version)?;
        let sender_id = match key.id_numbers.get(sender) {
            Some(sender_id) => sender_id,
            // unknown sender
            None => return Ok(JobPartialResponseAction::Reject),
        };
        let common_point = self.key_share.common_point.as_ref().expect("proxy decryption is only possible if a encrypted value is stored");
        let encrypted_point = self.key_share.encrypted_point.as_ref().expect("proxy decryption is only possible if a encrypted value is stored");
        let coefficient_commitments = key.coefficient_commitments.as_ref().expect("checked in contructor");

        let verification_success = math::verify_decryption_share(coefficient_commitments, sender_id, common_point, encrypted_point, &self.requester, &self.nonce, partial_response)?;
        if verification_success {
            Ok(JobPartialResponseAction::Accept)
        }else{
            Ok(JobPartialResponseAction::Reject)
        }
    }

    fn compute_response(&self, partial_responses: &BTreeMap<NodeId, Self::PartialJobResponse>) -> Result<Self::JobResponse, Error> {
        let key_share_version = self.key_share.version(&self.key_version)?;
        let valid_responses: Vec<_> = partial_responses.iter()
            .filter_map(|(nodeid, response)|
                match key_share_version.id_numbers.get(nodeid) {
                    Some(id) => Some((id.clone(), response.common_point.clone(), response.encrypted_point.clone())),
                    None => None,
                }
            )
            .collect();
        if valid_responses.len() <= self.key_share.threshold {
            return Err(Error::NotEnoughNodesForThreshold);
        }

        // aggregate
        let encrypted_point = self.key_share.encrypted_point.as_ref().expect("proxy decryption is only possible if a encrypted value is stored");
        let (d1,d2) = math::aggregate_decryption_shares(valid_responses, encrypted_point)?;
        Ok(ProxyDecryptionJobResponse {
            common_point: d1,
            encrypted_point: d2
        })
    }
}

#[cfg(test)]
mod tests {
    use key_storage::{DocumentKeyShare, DocumentKeyShareVersion};
    use ethereum_types::H256;
    use key_server_cluster::math;
    use crypto::publickey::{Random, Public, ec_math_utils, Generator};
    use key_server_cluster::jobs::proxy_decryption_job::{ProxyDecryptionJob};
    use key_server_cluster::jobs::job_session::{JobExecutor, JobPartialResponseAction};
    use std::collections::{BTreeSet, BTreeMap};
    use key_server_cluster::jobs::job_session::JobPartialRequestAction;
    use key_server_cluster::math::{PartialDecryptionShare};

    fn prepare_key_shares(t: usize, n: usize, message: &Public) -> (Vec<DocumentKeyShare>, Vec<Public>, H256) {
        let poly = math::generate_random_polynom(t).unwrap();
        let ids: Vec<_> = (0..n).map(|_| (math::generate_random_point().unwrap(), math::generate_random_scalar().unwrap())).collect();

        let coefficients: Vec<_> = poly.iter().map(|coeff| {
            let mut g = ec_math_utils::generation_point();
            ec_math_utils::public_mul_secret(&mut g, coeff).unwrap();
            g
        })
            .collect();

        // encrypt message
        let e = math::encrypt_secret(message, &coefficients[0]).unwrap();
        let version = H256::zero();
        let shares = ids.iter()
            .map(|(_, id)| {
                let share = math::compute_polynom(&poly, id).unwrap();
                DocumentKeyShare {
                    author: Default::default(),
                    threshold: t,
                    public: coefficients[0].clone(),
                    common_point: Some(e.common_point.clone()),
                    encrypted_point: Some(e.encrypted_point.clone()),
                    versions: vec![DocumentKeyShareVersion {
                        hash: version.clone(),
                        id_numbers: ids.iter().cloned().collect(),
                        secret_share: share,
                        coefficient_commitments: Some(coefficients.clone())
                    }]
                }
            })
            .collect();
        return (shares, ids.into_iter().map(|(nodeid, _)| nodeid).collect(), version);
    }

    #[test]
    fn proxy_decryption_job() {
        let message = math::generate_random_point().unwrap();
        let (shares, ids, version) = prepare_key_shares(4, 5, &message);

        let requester = Random.generate();
        let nonce = math::generate_random_scalar().unwrap();

        let mut master = ProxyDecryptionJob::new(ids[0].clone(), requester.public().clone(), shares[0].clone(), version.clone(), nonce.clone()).unwrap();
        let mut slaves: Vec<_> = (1..5).map(|i| ProxyDecryptionJob::new(ids[i].clone(), requester.public().clone(), shares[i].clone(), version.clone(), nonce.clone()).unwrap())
            .collect();

        let id_set: BTreeSet<_> = ids.iter().cloned().collect();
        let self_request = master.prepare_partial_request(&ids[0], &id_set).unwrap();
        let self_response = match master.process_partial_request(self_request).unwrap() {
            JobPartialRequestAction::Respond(response) => response,
            _ => panic!("unexpected"),
        };
        let requests = (1..5).map(|i| {
            (i,master.prepare_partial_request(&ids[i], &id_set).unwrap())
        });
        let responses: BTreeMap<Public, PartialDecryptionShare> = requests
            .map(|(i, request)| {
                let response = slaves.get_mut(i-1).unwrap().process_partial_request(request)
                        .unwrap();
                match response {
                    JobPartialRequestAction::Respond(response) => (ids[i].clone(), response),
                    _ => panic!("unexpected")
                }
            })
            .chain(vec![(ids[0].clone(), self_response)])
            .collect();

        // verify responses
        for (nodeid, response) in &responses {
            let action = master.check_partial_response(nodeid, response);
            assert_eq!(action, Ok(JobPartialResponseAction::Accept));
        }

        // compute job result
        let res = master.compute_response(&responses).unwrap();

        // decrypt & check
        let mut c1 = res.common_point;
        ec_math_utils::public_mul_secret(&mut c1, requester.secret()).unwrap();
        let mut c2 = res.encrypted_point;
        ec_math_utils::public_sub(&mut c2, &c1).unwrap();

        assert_eq!(message, c2);
    }

    #[test]
    fn verification_works() {
        let message = math::generate_random_point().unwrap();
        let (shares, ids, version) = prepare_key_shares(4, 5, &message);

        let requester = Random.generate();
        let nonce = math::generate_random_scalar().unwrap();
        let mut master = ProxyDecryptionJob::new(ids[0].clone(), requester.public().clone(), shares[0].clone(), version.clone(), nonce.clone()).unwrap();
        // create a valid response
        let mut slave = ProxyDecryptionJob::new(ids[1].clone(), requester.public().clone(), shares[1].clone(), version.clone(), nonce.clone()).unwrap();
        let response = slave.process_partial_request(()).unwrap();
        let response = match response {
            JobPartialRequestAction::Respond(response) => response,
            _ => panic!()
        };
        // is valid
        {
            let res = master.check_partial_response(&ids[1], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Accept, res);
        }

        // sent from a different node
        {
            let res = master.check_partial_response(&ids[2], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Reject, res);
        }

        // replay from previous decryption
        {
            let mut master = ProxyDecryptionJob::new(ids[0].clone(), requester.public().clone(), shares[0].clone(), version.clone(), math::generate_random_scalar().unwrap()).unwrap();
            let res = master.check_partial_response(&ids[1], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Reject, res);
        }

        // not using the correct share
        {
            let mut modified_share = shares[1].clone();
            modified_share.versions.get_mut(0).unwrap().secret_share = math::generate_random_scalar().unwrap();
            let mut slave = ProxyDecryptionJob::new(ids[1].clone(), requester.public().clone(), modified_share, version.clone(), nonce.clone()).unwrap();
            let response = slave.process_partial_request(()).unwrap().take_response();
            let res = master.check_partial_response(&ids[1], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Reject, res);
        }

        // using a different ciphertext (1)
        {
            let mut modified_share = shares[1].clone();
            modified_share.encrypted_point = Some(math::generate_random_point().unwrap());
            let mut slave = ProxyDecryptionJob::new(ids[1].clone(), requester.public().clone(), modified_share, version.clone(), nonce.clone()).unwrap();
            let response = slave.process_partial_request(()).unwrap().take_response();
            let res = master.check_partial_response(&ids[1], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Reject, res);
        }

        // using a different ciphertext (2)
        {
            let mut modified_share = shares[1].clone();
            modified_share.common_point = Some(math::generate_random_point().unwrap());
            let mut slave = ProxyDecryptionJob::new(ids[1].clone(), requester.public().clone(), modified_share, version.clone(), nonce.clone()).unwrap();
            let response = slave.process_partial_request(()).unwrap().take_response();
            let res = master.check_partial_response(&ids[1], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Reject, res);
        }

        // using a different requester
        {
            let other_requester = math::generate_random_point().unwrap();
            let mut slave = ProxyDecryptionJob::new(ids[1].clone(), other_requester, shares[1].clone(), version.clone(), nonce.clone()).unwrap();
            let response = slave.process_partial_request(()).unwrap().take_response();
            let res = master.check_partial_response(&ids[1], &response).unwrap();
            assert_eq!(JobPartialResponseAction::Reject, res);
        }
    }
}
