use ethereum_types::{H256, U256};
use crate::error::Error;
use std::io::Read;

pub type ProvingKey = Vec<u8>;

#[derive(Clone)]
pub struct Document {
    content: Vec<u8>
}

impl Document {

    pub fn from_reader<R: Read>(mut reader: R) -> Result<Document, Error> {
        let mut content = Vec::new();
        reader.read_to_end(&mut content).map_err(|ioerr| Error::Io(format!("{}", ioerr)))?;
        Ok(Document {
            content
        })
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Document {
            content: bytes
        }
    }

    pub fn hash(&self) -> H256 {
        H256(tiny_keccak::keccak256(&self.content))
    }

    pub fn content(&self) -> &Vec<u8> {
        &self.content
    }
}

#[derive(Debug)]
pub struct PendingDocumentUploadReceipt {
    /// the unique id of the document (here: the sha256 hash of the document)
    pub document_id: H256,
    pub encrypted_document: Vec<u8>,
    /// the proving key used to generate zk-proofs to access the document again
    pub proving_key: ProvingKey,
    /// the transaction hash of the document-submission transaction submitted to the ACL contract
    /// note: the transaction may be pending immediately after [Client::upload](struct.Client.html#method.upload)
    pub acl_submission_hash: H256,
}

impl PendingDocumentUploadReceipt {
    pub fn new(document_id: H256, encrypted_document: Vec<u8>, proving_key: ProvingKey, acl_submission_hash: H256) -> Self {
        PendingDocumentUploadReceipt {
            document_id,
            encrypted_document,
            proving_key,
            acl_submission_hash
        }
    }

    pub fn confirm(self, acl_submission_block_num: U256) -> DocumentUploadReceipt {
        DocumentUploadReceipt {
            original: self,
            acl_submission_block_num,
        }
    }
}

#[derive(Debug)]
pub struct DocumentUploadReceipt {
    /// the unique id of the document (here: the sha256 hash of the document)
    pub original: PendingDocumentUploadReceipt,
    /// the block number in which the document-submission transaction was mined
    pub acl_submission_block_num: U256
}

#[cfg(test)]
mod tests {
    use ethereum_types::H256;
    use crate::document::Document;

    #[test]
    fn test_document_hash() {
        let document = "This is a very top secret document".to_string();
        assert_eq!(
            // https://emn178.github.io/online-tools/keccak_256.html
            "14f715d0d66977c8a4706d07e8e658e4980adde11e32235ec43e647043c5be3d".parse::<H256>().unwrap(),
                   Document::from_reader(document.as_bytes()).unwrap().hash()
        )
    }
}