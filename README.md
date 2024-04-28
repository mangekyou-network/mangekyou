## Benchmarks

In `mangekyou`, one can compare all currently implemented cryptographic schemes by running:
```
$ cargo bench
```

## Usage

### Generate keys
```
cargo run --bin ecvrf-cli keygen
```

This outputs a secret key and a public key in hex format. Both the secret and public keys are 32-byte strings:
```
Secret key: 673d09357e636004c6129349a4019120ff09c0f5cb3204c67a64d5b661f93007
Public key: 42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261
```

### Compute VRF output and proof

To compute the VRF output and proof for the input string Hi Kamui!, which is 4869204b616d756921 in hexadecimal, with the key pair generated previously, run the following command:

```
cargo run --bin ecvrf-cli prove --input 4869204b616d756921 --secret-key 673d09357e636004c6129349a4019120ff09c0f5cb3204c67a64d5b661f93007
```

This should the 80-byte proof and VRF 64-byte output, both in hex format:
```
Proof:  42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261d9cd24cdb47ab446b86451974dab1ea382065e17c22085c63cfd7059ec834d08433c3158debd8e69547997a07fa083c9
Output: cd6a1b9e6751a55fec6e196c8a62a0ddbe64b080ebcbd571ecab1c28d80a94d809ca8d803fafbc814874de36f6540055057faafdba85395e6ae2b7256cbde94b
```

### Verify proof

1. You can verify the proof and output in a solana smart contract using mangekyou::ecvrf::ecvrf_verify from the Mangekyou Network (coming soon)

2. You can also use the CLI tool for verification:

```
cargo run --bin ecvrf-cli verify --output cd6a1b9e6751a55fec6e196c8a62a0ddbe64b080ebcbd571ecab1c28d80a94d809ca8d803fafbc814874de36f6540055057faafdba85395e6ae2b7256cbde94b --proof 42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261d9cd24cdb47ab446b86451974dab1ea382065e17c22085c63cfd7059ec834d08433c3158debd8e69547997a07fa083c9 --input 4869204b616d756921 --public-key 42b1b195493d8977f9432c1ea8208a8cf9adba1be06ed555ee1732c5b0637261
```

The preceding command returns the verification:
```
Proof verified correctly!
```

## Tests

There exist unit tests for all primitives in all three crates, which can be run by: 
```
$ cargo test
```