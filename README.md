# Ducketh

Ducketh is your local companion when trying to decode some unknown Ethereum smart contract signature.

## Installation

Ducketh is for now only available as a crate. Install it using `cargo install`
```bash
cargo install ducketh
```

## Quick start

Add some ABIs to your local Ducketh registry:
```bash
# Recursively add every ABIs in the './artifacts' folder
ducketh abi add ./artifacts -r
```

Try decoding some hexadecimal value
```bash
# Try decoding 0x8c5be1e5 <- `Approval` event of an ERC721 or ERC20
ducketh woot 0x8c5be1e5
```

## Additional details

The CLI informations can be displayed using `help` or `-h` on individual command
```bash
# General informations
ducketh help
# Informations on `woot` command
ducketh woot -h
```

## Alternatives

When the decoding is not successful, adding more ABIs may help. Otherwise, one can visit https://openchain.xyz/signatures for larger data sets.
