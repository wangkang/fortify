# Fortify

[![Go Build](https://github.com/struqt/fortify/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/struqt/fortify/actions/workflows/go.yml)

**Fortify** is a command-line tool designed to enhance file security through encryption.

It uses AES-256 as the encryption method.
The AES-256 secret key is protected using either Shamir's Secret Sharing (SSS) or RSA encryption.

## Features

* Encrypts file using AES-256.
* Protects the AES key with either Shamir's Secret Sharing (SSS) or RSA encryption.
* Offers functionalities for encryption, decryption, and execution of fortified files.

## Usage Overview

#### With SSS

- Encrypt/decrypt/execute with specified key parts:
    1. Generate key parts: `fortify sss random -p <number_of_shares> -t <threshold> --prefix <key_prefix>`
    2. Encrypt: `fortify encrypt -i <input_file> <key_part1> <key_part2> ...`
    3. Decrypt: `fortify decrypt -i <fortified_file> <key_part1> <key_part2> ...`
    4. Execute: `fortify execute -i <fortified_file> <key_part1> <key_part2> ...`
- Encrypt with randomly generated key parts: `fortify encrypt -i <input_file> -o <output_file>`

#### With RSA

* Encrypt with public key: `fortify encrypt -i <input_file> -k rsa <public_key_file>`
* Decrypt with private key: `fortify decrypt -i <fortified_file> <private_key_file>`
* Execute with private key: `fortify execute -i <fortified_file> <private_key_file>`

## License

This project is licensed under the MIT License.

---

# Developer's Guide

## Contributing

Feel free to contribute by submitting issues or pull requests. We welcome any suggestions or improvements.

## Build

To build the current workspace, run the following command:

```shell
bash build.sh
```

```shell
pushd build && ./fortify -h && ./fortify version; popd
```

## Working with SSS (Shamir's Secret Sharing)

### Encrypt with Random New Key Parts

```shell
pushd build/sss && ../fortify encrypt -i ../fortify -o fortified; popd
```

This command encrypts the specified file using Shamir's Secret Sharing with randomly generated key parts.

### Encrypt and Decrypt with Specified Key Parts

Generate random key parts:

```shell
pushd build && ./fortify sss random -p3 -t2 --prefix ../debug/key_sss/p; popd
```

Encrypt the file using specified key parts:

```shell
pushd build && ./fortify encrypt -i fortify -T ../debug/key_sss/p3of3.json ../debug/key_sss/p1of3.json; popd
```

Decrypt the fortified file using specified key parts:

```shell
pushd build && ./fortify decrypt -i fortified.data ../debug/key_sss/p1of3.json ../debug/key_sss/p2of3.json; popd
```

Execute the fortified file using specified key parts:

```shell
pushd build && ./fortify execute -i fortified.data ../debug/key_sss/p2of3.json ../debug/key_sss/p3of3.json; popd
```

## Working with RSA

Generate RSA key pairs:

```shell
bash debug_keygen.sh
```

### Encrypt with RSA Public Key

Encrypt the file using an RSA public key:

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -T -k rsa ../../debug/key_rsa/id_rsa.pub; popd
```

Encrypt the file using an RSA public key in PEM format:

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -T -k rsa ../../debug/key_rsa/id_rsa_pem.pub; popd
```

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -T -k rsa ../../debug/key_rsa/id_rsa_pkcs8.pub; popd
# Will Fail
```

> - PKCS #8 public key is unsupported

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -T -k rsa ../../debug/key_rsa/id_rsa_rfc4716.pub; popd
# Will Fail
```

> - RFC 4716 public key is unsupported

### Execute the Fortified File with RSA Private Key

Execute the fortified file using an RSA private key:

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa; popd
```

Execute the fortified file using an RSA private key in PEM format:

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa_pem; popd
```

Execute the fortified file using an RSA private key in RFC 4716 format:

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa_rfc4716; popd
```

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa_pkcs8; popd
# Will Fail
```

> - encrypted PKCS #8 private key is unsupported
