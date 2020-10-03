// this code is adapted from https://github.com/synlestidae/ethereum-tx-sign licensed under MIT License

use ethereum_types::{
    H160,
    H256,
    U256
};

use crypto::publickey::Signature;
use rlp::RlpStream;

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RawTransaction {
    /// Nonce
    pub nonce: U256,
    /// Recipient (None when contract creation)
    pub to: Option<H160>,
    /// Transfered value
    pub value: U256,
    /// Gas Price
    pub gas_price: U256,
    /// Gas amount
    pub gas: U256,
    /// Input data
    pub data: Vec<u8>,

    pub chain_id: u64,
}

impl RawTransaction {

    /// Returns the RLP-encoded transaction with the signature
    pub fn signed(&self, signature: &Signature) -> Vec<u8> {
        let mut r_n = Vec::from(signature.r());
        let mut s_n = Vec::from(signature.s());
        let v = signature.v() as u64 + self.chain_id * 2 + 35;
        while r_n[0] == 0 {
            r_n.remove(0);
        }
        while s_n[0] == 0 {
            s_n.remove(0);
        }
        let mut tx = RlpStream::new();
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&v);
        tx.append(&r_n);
        tx.append(&s_n);
        tx.finalize_unbounded_list();
        tx.out()
    }

    pub fn hash(&self) -> H256 {
        let mut hash = RlpStream::new();
        hash.begin_unbounded_list();
        self.encode(&mut hash);
        hash.append(&self.chain_id);
        hash.append(&U256::zero());
        hash.append(&U256::zero());
        hash.finalize_unbounded_list();
        keccak256_hash(&hash.out())
    }

    pub fn hash_with_signature(&self, signature: &Signature) -> H256 {
        let rlp = self.signed(signature);
        return keccak256_hash(&rlp);
    }

    fn encode(&self, s: &mut RlpStream) {
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        if let Some(ref t) = self.to {
            s.append(t);
        } else {
            s.append(&vec![]);
        }
        s.append(&self.value);
        s.append(&self.data);
    }
}

fn keccak256_hash(bytes: &[u8]) -> H256 {
    H256(tiny_keccak::keccak256(bytes))
    // let mut hasher = tiny_keccak::Keccak::
    // hasher.update(bytes);
    // let mut resp: [u8; 32] = Default::default();
    // hasher.finalize(&mut resp);
    // H256(resp)
}

#[cfg(test)]
mod tests {
    use transaction_signature::RawTransaction;
    use rustc_hex::{FromHex, ToHex};
    use crypto::publickey::Secret;
    use ethereum_types::{U256, H160};

    const ETH_CHAIN_ID: u64 = 3;

    #[test]
    fn test_raw_signature() {
        let tx = RawTransaction {
            nonce: U256::from(0),
            to: Some(H160::zero()),
            value: U256::zero(),
            gas_price: U256::from(10000),
            gas: U256::from(21240),
            data: "7f7465737432000000000000000000000000000000000000000000000000000000600057".from_hex().unwrap(),
            chain_id: ETH_CHAIN_ID
        };

        let secret: Secret = "2a3526dd05ad2ebba87673f711ef8c336115254ef8fcd38c4d8166db9a8120e4".parse().unwrap();
        let signature = parity_crypto::publickey::sign(&secret, &tx.hash()).unwrap();
        let raw_rlp_bytes = tx.signed(&signature);

        let result = "f885808227108252f894000000000000000000000000000000000000000080a47f74657374320000000000000000000000000000000000000000000000000000006000572aa0b4e0309bc4953b1ca0c7eb7c0d15cc812eb4417cbd759aa093d38cb72851a14ca036e4ee3f3dbb25d6f7b8bd4dac0b4b5c717708d20ae6ff08b6f71cbf0b9ad2f4";
        assert_eq!(result, raw_rlp_bytes.to_hex());
    }

    #[test]
    fn test_hash_with_signature() {
        let tx = RawTransaction {
            nonce: U256::from(0),
            to: Some(H160::zero()),
            value: U256::zero(),
            gas_price: U256::from(10000),
            gas: U256::from(21656),
            data: "7f7465737432000000000000000000000000000000000000000000000000000000600057".from_hex().unwrap(),
            chain_id: 0x11
        };

        let secret: Secret = "4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7".parse().unwrap();
        let signature = parity_crypto::publickey::sign(&secret, &tx.hash()).unwrap();

        assert_eq!(tx.hash_with_signature(&signature), "1d90c854c7fb5b3fe6da288372873dd1c2cc0e2c54bc3860209e69335592ab29".parse().unwrap());
    }
}