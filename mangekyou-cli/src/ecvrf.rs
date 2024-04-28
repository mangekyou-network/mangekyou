// Copyright (c) 2022, Mangekyou Network, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use mangekyou::kamui_vrf::ecvrf::{ECVRFKeyPair, ECVRFPrivateKey, ECVRFProof, ECVRFPublicKey};
use mangekyou::kamui_vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;
use std::io::{Error, ErrorKind};

#[derive(Parser)]
#[command(name = "ecvrf-cli")]
#[command(about = "Elliptic Curve Verifiable Random Function (ECVRF) over Ristretto255 according to draft-irtf-cfrg-vrf-15.", long_about = None)]
enum Command {
    /// Generate a key pair for proving and verification.
    Keygen,

    /// Create an output/hash and a proof.
    Prove(ProveArguments),

    /// Verify an output/hash and a proof.
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct ProveArguments {
    /// The hex encoded input string.
    #[clap(short, long)]
    input: String,

    /// A hex encoding of the secret key. Corresponds to a scalar in Ristretto255 and must be 32 bytes.
    #[clap(short, long)]
    secret_key: String,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// Hex-encoded Sha512 hash of the proof. Must be 64 bytes.
    #[clap(short, long)]
    output: String,

    /// Encoding of the proof to verify. Must be 80 bytes.
    #[clap(short, long)]
    proof: String,

    /// Hex encoding of the input string used to generate the proof.
    #[clap(short, long)]
    input: String,

    /// The public key corresponding to the secret key used to generate the proof.
    #[clap(short = 'k', long)]
    public_key: String,
}

fn main() {
    match execute(Command::parse()) {
        Ok(res) => {
            println!("{}", res);
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

fn execute(cmd: Command) -> Result<String, std::io::Error> {
    match cmd {
        Command::Keygen => {
            let keypair = ECVRFKeyPair::generate(&mut thread_rng());
            let sk_string =
                hex::encode(&keypair.sk);
            let pk_string =
                hex::encode(&keypair.pk);

            let mut result = "Secret key: ".to_string();
            result.push_str(&sk_string);
            result.push_str("\nPublic key: ");
            result.push_str(&pk_string);
            Ok(result)
        }

        Command::Prove(arguments) => {
            // Parse inputs
            let secret_key_bytes = hex::decode(arguments.secret_key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid private key."))?;
            let alpha_string = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input string."))?;

            // Create keypair from the secret key bytes
            let secret_key = ECVRFPrivateKey::from_bytes(&secret_key_bytes).unwrap();
            let kp = ECVRFKeyPair::from(secret_key);

            // Generate proof
            let proof = kp.prove(&alpha_string);
            let proof_string = hex::encode(proof.to_bytes());
            let proof_hash = hex::encode(proof.to_hash());

            let mut result = "Proof:  ".to_string();
            result.push_str(&proof_string);
            result.push_str("\nOutput: ");
            result.push_str(&proof_hash);
            Ok(result)
        }

        Command::Verify(arguments) => {
            // Parse inputs
            let public_key_bytes = hex::decode(arguments.public_key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid public key."))?;
            let alpha_string = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input string."))?;
            let proof_bytes = hex::decode(arguments.proof)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid proof string."))?;
            let output_bytes = hex::decode(arguments.output)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output string."))?;
            let output: [u8; 64] = output_bytes
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Output must be 64 bytes."))?;

            // Create public key and proof from parsed bytes
            let public_key: ECVRFPublicKey =
                ECVRFPublicKey::from_bytes(&public_key_bytes).unwrap();
            let proof: ECVRFProof = ECVRFProof::from_bytes(&proof_bytes).unwrap();

            if proof
                .verify_output(&alpha_string, &public_key, &output)
                .is_ok()
            {
                return Ok("Proof verified correctly!".to_string());
            }
            Err(Error::new(ErrorKind::Other, "Proof is not correct."))
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{execute, Command, ProveArguments, VerifyArguments};
    use regex::Regex;

    #[test]
    fn test_keygen() {
        let result = execute(Command::Keygen).unwrap();
        let expected =
            Regex::new(r"Secret key: ([0-9a-fA-F]{64})\nPublic key: ([0-9a-fA-F]{64})").unwrap();
        assert!(expected.is_match(&result));
    }

    #[test]
    fn test_prove() {
        let input = "4869204b616d756921";
        let secret_key = "673d09357e636004c6129349a4019120ff09c0f5cb3204c67a64d5b661f93007";
        let result = execute(Command::Prove(ProveArguments {
            input: input.to_string(),
            secret_key: secret_key.to_string(),
        }))
        .unwrap();
        let expected = "Proof:  42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261d9cd24cdb47ab446b86451974dab1ea382065e17c22085c63cfd7059ec834d08433c3158debd8e69547997a07fa083c9\nOutput: cd6a1b9e6751a55fec6e196c8a62a0ddbe64b080ebcbd571ecab1c28d80a94d809ca8d803fafbc814874de36f6540055057faafdba85395e6ae2b7256cbde94b";
        assert_eq!(expected, result);

        let invalid_input = "InvalidInput";
        assert!(execute(Command::Prove(ProveArguments {
            input: invalid_input.to_string(),
            secret_key: secret_key.to_string(),
        }))
        .is_err());

        let invalid_secret_key = "30db47c03e2ba49e89ca7bd67a242fed8a8700d19077ce9ce01c32aeb74d700f";
        assert!(execute(Command::Prove(ProveArguments {
            input: input.to_string(),
            secret_key: invalid_secret_key.to_string(),
        }))
        .is_err());
    }

    #[test]
    fn test_verify() {
        let input = "4869204b616d756921";
        let public_key = "42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261";
        let proof = "42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261d9cd24cdb47ab446b86451974dab1ea382065e17c22085c63cfd7059ec834d08433c3158debd8e69547997a07fa083c9";
        let output = "cd6a1b9e6751a55fec6e196c8a62a0ddbe64b080ebcbd571ecab1c28d80a94d809ca8d803fafbc814874de36f6540055057faafdba85395e6ae2b7256cbde94b";
        let result = execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }))
        .unwrap();
        let expected = "Proof verified correctly!";
        assert_eq!(expected, result);

        let invalid_input = "InvalidInput";
        assert!(execute(Command::Verify(VerifyArguments {
            input: invalid_input.to_string(),
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }))
        .is_err());

        let invalid_public_key = "1a85c9b8492fc311a85892bdc3d60f05dde89ee055a724e30b33b4353f695734";
        assert!(execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: invalid_public_key.to_string(),
            proof: proof.to_string(),
            output: output.to_string(),
        }))
        .is_err());

        let incorrect_proof = "2640d12c11a372c726348d60ec74ac80320960ba541fb3e66af0a21590c0a75bf5ccf408d5070c5de77f87c733512f575b4a03511d0031dc2e78ab1582fbbef919b52732c8cb1f44b27ad1d1293dec0e";
        assert!(execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: incorrect_proof.to_string(),
            output: output.to_string(),
        }))
        .is_err());

        let invalid_proof = "2640d12c11a372c726348d60ec74ac80320960ba541fb3e66af0a21590c0a75bf5ccf408d5070c5de77f87c733512f575b4a03511d0031dc2e78ab1582fbbef919b52732c8cb1f44b27ad1d1293dec0";
        assert!(execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: invalid_proof.to_string(),
            output: output.to_string(),
        }))
        .is_err());

        let invalid_output = "84588b918a6c9f5b8b74e56a305bb1c2d44e73f68457e991a1dc8defd51672c36b07a2fa95b9f1e701d0152b35d373ab8c48468f0de4bb5abfe84504319fd00";
        assert!(execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: invalid_output.to_string(),
        }))
        .is_err());

        let incorrect_output = "84588b918a6c9f5b8b74e56a305bb1c2d44e73f68457e991a1dc8defd51672c36b07a2fa95b9f1e701d0152b35d373ab8c48468f0de4bb5abfe84504319fd00d";
        assert!(execute(Command::Verify(VerifyArguments {
            input: input.to_string(),
            public_key: public_key.to_string(),
            proof: proof.to_string(),
            output: incorrect_output.to_string(),
        }))
        .is_err());
    }
}
