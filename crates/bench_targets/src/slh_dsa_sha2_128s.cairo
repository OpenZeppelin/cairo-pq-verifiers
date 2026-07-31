//! Benchmark account for the SLH-DSA-SHA2-128s verifier.
//!
//! The account stores the two-felt `PK.seed || PK.root` public key and validates a
//! 491-felt FIPS 205 signature over the transaction hash. Loading the key and the full
//! signature from transaction information are part of the measured validation cost.

#[starknet::contract]
pub mod SlhDsaSha2_128sAccount {
    use pqbench_slh_dsa_sha2_128s::SlhDsaSha2_128sVerifier;
    use starknet::storage::{MutableVecTrait, StoragePointerReadAccess, Vec, VecTrait};
    use crate::IValidateBench;

    #[storage]
    struct Storage {
        public_key: Vec<felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        for value in public_key {
            self.public_key.push(value);
        }
    }

    #[abi(embed_v0)]
    impl ValidateBenchImpl of IValidateBench<ContractState> {
        fn validate(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let mut public_key = array![];
            let len = self.public_key.len();
            let mut i = 0;
            while i != len {
                public_key.append(self.public_key.at(i).read());
                i += 1;
            }
            let valid = SlhDsaSha2_128sVerifier::verify(
                tx_info.transaction_hash, public_key.span(), tx_info.signature,
            );
            assert!(valid, "invalid signature");
            starknet::VALIDATED
        }
    }
}
