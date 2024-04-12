use crate::error::MangekyouError;
use crate::traits::AllowedRng;

use solana_zk_token_sdk::curve25519::ristretto::{PodRistrettoPoint, multiscalar_multiply_ristretto};
use solana_zk_token_sdk::curve25519::scalar::{PodScalar};

use solana_program::keccak::hash; // Assuming Keccak hash for example purposes

use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;

/// Represents a public key of which is use to verify outputs for a verifiable random function (VRF).
pub trait VRFPublicKey {
    type PrivateKey: VRFPrivateKey<PublicKey = Self>;
}

/// Represents a private key used to compute outputs for a verifiable random function (VRF).
pub trait VRFPrivateKey {
    type PublicKey: VRFPublicKey<PrivateKey = Self>;
}

/// A keypair for a verifiable random function (VRF).
pub trait VRFKeyPair<const OUTPUT_SIZE: usize> {
    type Proof: VRFProof<OUTPUT_SIZE, PublicKey = Self::PublicKey>;
    type PrivateKey: VRFPrivateKey<PublicKey = Self::PublicKey>;
    type PublicKey: VRFPublicKey<PrivateKey = Self::PrivateKey>;

    /// Generate a new keypair using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;

    /// Generate a proof for the given input.
    fn prove(&self, input: &[u8]) -> Self::Proof;

    /// Compute both hash and proof for the given input.
    fn output(&self, input: &[u8]) -> ([u8; OUTPUT_SIZE], Self::Proof) {
        let proof = self.prove(input);
        let output = proof.to_hash();
        (output, proof)
    }
}

/// A proof that the output of a VRF was computed correctly.
pub trait VRFProof<const OUTPUT_SIZE: usize> {
    type PublicKey: VRFPublicKey;

    /// Verify the correctness of this proof.
    fn verify(&self, input: &[u8], public_key: &Self::PublicKey) -> Result<(), MangekyouError>;

    /// Verify the correctness of this proof and VRF output.
    fn verify_output(
        &self,
        input: &[u8],
        public_key: &Self::PublicKey,
        output: &[u8; OUTPUT_SIZE],
    ) -> Result<(), MangekyouError> {
        self.verify(input, public_key)?;
        if &self.to_hash() != output {
            return Err(MangekyouError::GeneralOpaqueError);
        }
        Ok(())
    }

    /// Compute the output of the VRF with this proof.
    fn to_hash(&self) -> [u8; OUTPUT_SIZE];
}

/// An implementation of an Elliptic Curve VRF (ECVRF) using the Ristretto255 group.
/// The implementation follows the specifications in draft-irtf-cfrg-vrf-15
/// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/).
pub mod ecvrf {
    use crate::error::MangekyouError;
    // use crate::groups::{GroupElement, MultiScalarMul, Scalar};
    use curve25519_dalek_ng::scalar::{Scalar as RistrettoScalar};
    use curve25519_dalek_ng::constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT};
    use crate::hash::{HashFunction, ReverseWrapper, Sha512};
    use crate::serde_helpers::ToFromByteArray;
    use crate::traits::AllowedRng;
    use crate::kamui_vrf::{VRFKeyPair, VRFPrivateKey, VRFProof, VRFPublicKey};
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroize;
    use solana_zk_token_sdk::curve25519::ristretto::{PodRistrettoPoint, multiscalar_multiply_ristretto};
    use solana_zk_token_sdk::curve25519::scalar::*;
    use sha2::{Sha256, Digest};



    /// draft-irtf-cfrg-vrf-15 specifies suites for suite-strings 0x00-0x04 and notes that future
    /// designs should specify a different suite_string constant, so we use "sui_vrf" here.
    const SUITE_STRING: &[u8; 7] = b"sui_vrf";

    /// Length of challenges. Must not exceed the length of field elements which is 32 in this case.
    /// We set C_LEN = 16 which is the same as the existing ECVRF suites in draft-irtf-cfrg-vrf-15.
    const C_LEN: usize = 16;

    /// Default hash function
    type H = Sha512;

    /// Domain separation tag used in ecvrf_encode_to_curve (see also draft-irtf-cfrg-hash-to-curve-16)
    const DST: &[u8; 49] = b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sui_vrf";

    pub struct ECVRFPublicKey(PodRistrettoPoint);

    impl VRFPublicKey for ECVRFPublicKey {
        type PrivateKey = ECVRFPrivateKey;
    }
    /// Assuming a function that attempts to convert a hash output to a Ristretto point.
    /// This is a placeholder and should be replaced with a proper deterministic mapping if available.
    fn hash_to_ristretto_point(hash_output: &[u8]) -> PodRistrettoPoint {
        // This is a simplified and not directly secure way to map a hash to a curve point.
        // It's crucial to replace this with a secure hash-to-curve algorithm.
        let compressed = CompressedRistretto::from_slice(hash_output);
        match compressed.decompress() {
            Some(point) => PodRistrettoPoint(point.compress().to_bytes()),
            None => panic!("Hash output cannot be mapped directly to a Ristretto point"),
        }
    }
    impl ECVRFPublicKey {
        /// Encode the given binary string as curve point. See section 5.4.1.2 of draft-irtf-cfrg-vrf-15.
        fn ecvrf_encode_to_curve_solana(&self, alpha_string: &[u8]) -> PodRistrettoPoint {
            // Hash the input alpha_string using SHA-256
            let mut hasher = Sha256::new();
            hasher.update(alpha_string);
            let hash_output = hasher.finalize();
    
            // Attempt to map the hash output to a Ristretto point
            // Note: This step is crucial and must be securely implemented in a real scenario.
            hash_to_ristretto_point(&hash_output[..])
        }

        /// Implements ECVRF_validate_key which checks the validity of a public key. See section 5.4.5
        /// of draft-irtf-cfrg-vrf-15.
        fn valid(&self) -> bool {
            self.0 != PodRistrettoPoint::zeroed()
        }
    } 

    pub struct ECVRFPrivateKey(PodScalar);

    impl VRFPrivateKey for ECVRFPrivateKey {
        type PublicKey = ECVRFPublicKey;
    }

    impl ECVRFPrivateKey {
        /// Generate scalar/nonce from binary string. See section 5.4.2.2. of draft-irtf-cfrg-vrf-15.
        fn ecvrf_nonce_generation(&self, h_string: &[u8]) -> PodScalar {
            let hashed_sk_string = H::digest(self.0.to_byte_array());
            let mut truncated_hashed_sk_string = [0u8; 32];
            truncated_hashed_sk_string.copy_from_slice(&hashed_sk_string.digest[32..64]);

            let mut hash_function = H::default();
            hash_function.update(truncated_hashed_sk_string);
            hash_function.update(h_string);
            let k_string = hash_function.finalize();

            PodScalar(RistrettoScalar::from_bytes_mod_order_wide(&k_string.digest).to_bytes())
        }
    }

    pub struct ECVRFKeyPair {
        pub pk: ECVRFPublicKey,
        pub sk: ECVRFPrivateKey,
    }

    /// Generate challenge from five points. See section 5.4.3. of draft-irtf-cfrg-vrf-15.
    fn ecvrf_challenge_generation(points: [&PodRistrettoPoint; 5]) -> Challenge {
        let mut hash = H::default();
        hash.update(SUITE_STRING);
        hash.update([0x02]); //challenge_generation_domain_separator_front
        points.into_iter().for_each(|p| hash.update(p.compress()));
        hash.update([0x00]); //challenge_generation_domain_separator_back
        let digest = hash.finalize();

        let mut challenge_bytes = [0u8; C_LEN];
        challenge_bytes.copy_from_slice(&digest.digest[..C_LEN]);
        Challenge(challenge_bytes)
    }

    /// Type representing a scalar of [C_LEN] bytes.
    struct Challenge([u8; C_LEN]);

    impl From<&Challenge> for PodScalar {
        fn from(c: &Challenge) -> Self {
            let mut scalar = [0u8; 32];
            scalar[..C_LEN].copy_from_slice(&c.0);
            PodScalar(RistrettoScalar::from_bytes_mod_order(&scalar).to_bytes())
        }
    }

    impl VRFKeyPair<64> for ECVRFKeyPair {
        type Proof = ECVRFProof;
        type PrivateKey = ECVRFPrivateKey;
        type PublicKey = ECVRFPublicKey;

        fn generate<R: AllowedRng>(rng: &mut R) -> Self {
            let s = PodScalar::from(RistrettoScalar::random(rng));
            ECVRFKeyPair::from(ECVRFPrivateKey(s))
        }

        // fn prove(&self, alpha_string: &[u8]) -> ECVRFProof {
        //     // Follows section 5.1 of draft-irtf-cfrg-vrf-15.

        //     let h = self.pk.ecvrf_encode_to_curve(alpha_string);
        //     let h_string = h.compress();
        //     let gamma = h * self.sk.0;
        //     let k = self.sk.ecvrf_nonce_generation(&h_string);

        //     let c = ecvrf_challenge_generation([
        //         &self.pk.0,
        //         &h,
        //         &gamma,
        //         &(RistrettoPoint::generator() * k),
        //         &(h * k),
        //     ]);
        //     let s = k + RistrettoScalar::from(&c) * self.sk.0;

        //     ECVRFProof { gamma, c, s }
        // }

        fn prove(&self, alpha_string: &[u8]) -> ECVRFProof {
            // Hash the input to a curve point using the public key's method
            let h_point = self.pk.ecvrf_encode_to_curve_solana(alpha_string);

            // Perform the scalar multiplication k * H to get gamma
            let gamma = multiply_ristretto(PodScalar::from(h_point), self.pk.0);
    
            // Generate nonce k using the private key and alpha_string
            // Here, we simulate the generation of nonce from the hashed combination of private key and alpha_string
            // This is a simplified version and should be replaced with a secure hash-to-scalar function
            let k = self.sk.ecvrf_nonce_generation(alpha_string);
    
    

    
            // Compute the challenge c based on the VRF draft specification
            // This involves hashing certain elements including the public key, gamma, and the original point H
            let c = ecvrf_challenge_generation(&[
                &self.pk.0, // Public key as a point
                &h_pod,     // The hashed point of the input
                &gamma,     // The gamma point from scalar multiplication
                // Additional points as required by the protocol
            ]);
    
            // Compute the proof scalar s = (k + c*x) mod q
            // Where x is the private key scalar, and q is the order of the group
            let s = add_ristretto(k, multiply_ristretto(PodScalar::from(&c), self.sk.0));
    
            Ok(ECVRFProof { gamma, c: c.into(), s })
        }
    }

    impl From<ECVRFPrivateKey> for ECVRFKeyPair {
        fn from(sk: ECVRFPrivateKey) -> Self {
            let p = PodRistrettoPoint::from(RISTRETTO_BASEPOINT_POINT) * sk.0;
            ECVRFKeyPair {
                pk: ECVRFPublicKey(p),
                sk,
            }
        }
    }

    pub struct ECVRFProof {
        gamma: PodRistrettoPoint,
        c: Challenge,
        s: PodScalar,
    }

    impl VRFProof<64> for ECVRFProof {
        type PublicKey = ECVRFPublicKey;


        fn verify(
            &self,
            alpha_string: &[u8],
            public_key: &Self::PublicKey,
        ) -> Result<(), MangekyouError> {
            // Ensure the public key is valid
            if !public_key.valid() {
                return Err(MangekyouError::InvalidInput);
            }
    
            // Encode the input alpha_string to a curve point using the public key method
            let h_point = public_key.ecvrf_encode_to_curve_solana(alpha_string);
    
            // Convert the gamma (RistrettoPoint) from the proof to PodRistrettoPoint for operations
            let gamma_pod = PodRistrettoPoint::from(self.gamma);
    
            // Convert the challenge and scalar from the proof to PodScalar for operations
            let challenge_pod = PodScalar(RistrettoScalar::from_bytes_mod_order_wide(&self.c.0).to_bytes());
            let s_pod = PodScalar(RistrettoScalar::from_bytes_mod_order_wide(&self.s.to_bytes()).to_bytes());
    
            // Compute U = s*B - c*Y using multiscalar multiplication
            let u_point = multiscalar_multiply_ristretto(
                &[s_pod, -challenge_pod],
                &[PodRistrettoPoint::from(RISTRETTO_BASEPOINT_POINT), PodRistrettoPoint::from(public_key.0)],
            ).ok_or(MangekyouError::InvalidInput);
    
            // Compute V = s*H - c*Gamma using multiscalar multiplication
            let v_point = multiscalar_multiply_ristretto(
                &[s_pod, -challenge_pod],
                &[PodRistrettoPoint::from(h_point), gamma_pod],
            ).ok_or(MangekyouError::InvalidInput);
    
            // Recompute the challenge c' using the ecvrf_challenge_generation function
            let c_prime_bytes = ecvrf_challenge_generation([
                &public_key.0,
                &h_point,
                &self.gamma,
                &PodRistrettoPoint::from(u_point),
                &PodRistrettoPoint::from(v_point),
            ]);
            let c_prime = PodScalar(RistrettoScalar::from_bytes_mod_order_wide(&c_prime_bytes.0).to_bytes());
    
            // Check if the recomputed challenge matches the original challenge
            if c_prime != challenge_pod {
                return Err(MangekyouError::GeneralOpaqueError);
            }
    
            Ok(())
        }

        fn to_hash(&self) -> [u8; 64] {
            // Follows section 5.2 of draft-irtf-cfrg-vrf-15.
            let mut hash = H::default();
            hash.update(SUITE_STRING);
            hash.update([0x03]); // proof_to_hash_domain_separator_front
            hash.update(self.gamma.compress());
            hash.update([0x00]); // proof_to_hash_domain_separator_back
            hash.finalize().digest
        }
    }
}
