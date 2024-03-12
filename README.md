# Fortify

**Fortify** is a command-line tool designed to enhance file security through encryption.

## Features

* Fortifies any file through encryption, then decrypts or executes the fortified files.
* Encrypts file using AES-256.
* Protects the AES secret key with either Shamir's Secret Sharing (SSS) or RSA encryption.

## Usage Overview

### Install the Latest version

```shell
go install github.com/wangkang/fortify@latest
```

```shell
fortify version
```

### Shamir's Secret Sharing (SSS)

#### Encryption

Encrypt files with randomly generated key parts:

```
fortify encrypt -i <input_file> -o <output_file>
```

Encrypt files with specified key parts:

```
fortify sss random -b 32 -p <number_of_shares> -t <threshold>
fortify encrypt -i <input_file> <key_part1> <key_part2> ...
```

#### Decryption

Decrypt files with specified key parts:

```
fortify decrypt -i <fortified_file> <key_part1> <key_part2> ...
```

#### Execution

Execute fortified files with specified key parts:

```
fortify execute -i <fortified_file> <key_part1> <key_part2> ...
```

### RSA Encryption

#### Encryption

Encrypt files with RSA public key:

```
fortify encrypt -i <input_file> -k rsa <public_key_file>
```

#### Decryption

Decrypt files with RSA private key:

```
fortify decrypt -i <fortified_file> <private_key_file>
```

#### Execution

Execute fortified files with RSA private key:

```
fortify execute -i <fortified_file> <private_key_file>
```

---

# Developer's Guide

[![Release](https://github.com/wangkang/fortify/actions/workflows/release.yml/badge.svg)](https://github.com/wangkang/fortify/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/wangkang/fortify)](https://goreportcard.com/report/github.com/wangkang/fortify)

## License

This project is licensed under the MIT License.

## Contributing

We welcome contributions through issue submissions and pull requests. Feel free to suggest improvements or report
issues.

## Build

To build the project, run:

```shell
bash build.sh
```

After building, execute the following commands to confirm the result:

```shell
pushd build && ./fortify -h && ./fortify version; popd
```

## Shamir's Secret Sharing (SSS)

### Splitting and Combining Secret Shares

To split and combine secret shares, use the following commands:

```shell
pushd build/sss && ../fortify sss split -vT ../fortify; popd
```

```shell
pushd build/sss && ../fortify sss combine -o combined.out -vT 1of5.json 3of5.json 5of5.json; popd
```

**Tips:**

- For enhanced security, store generated secret shares in different locations.
- While suitable for processing large files, this method may not be optimal for smaller files.

### Encrypting with Randomly Generated Secret Key

Encrypt files with randomly generated key parts:

```shell
pushd build/sss && ../fortify encrypt -i ../fortify -T; popd
```

Decrypt fortified files with specified key parts:

```shell
pushd build/sss && ../fortify decrypt -i fortified.data -T fortified.key1of2.json fortified.key2of2.json; popd
```

Execute fortified files with specified key parts:

```shell
pushd build/sss && ../fortify execute -i fortified.data fortified.key1of2.json fortified.key2of2.json -- encrypt -h; popd
```

### Encrypting and Decrypting with Specified Key Parts

Generate new random key parts:

```shell
pushd build/sss && ../fortify sss random -p3 -t2 --prefix p; popd
```

Encrypt files using specified key parts:

```shell
pushd build/sss && ../fortify encrypt -i ../fortify -vT p1of3.json p2of3.json; popd
```

Decrypt fortified files using specified key parts:

```shell
pushd build/sss && ../fortify decrypt -i fortified.data -vT p1of3.json p3of3.json; popd
```

Execute fortified files using specified key parts:

```shell
pushd build/sss && ../fortify execute -i fortified.data p2of3.json p3of3.json; popd
```

## RSA Encryption

Generate RSA key pairs:

```shell
bash debug_keygen.sh
```

### Encrypting with RSA Public Key

Encrypt files using RSA public key:

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -k rsa -vT ../../debug/key_rsa/id_rsa.pub; popd
```

Encrypt files using RSA public key in PEM format:

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -k rsa -vT ../../debug/key_rsa/id_rsa_pem.pub; popd
```

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -k rsa  -vT ../../debug/key_rsa/id_rsa_pkcs8.pub; popd
# Will Fail
```

> - PKCS #8 public key is unsupported

```shell
pushd build/rsa && ../fortify encrypt -i ../fortify -k rsa -vT ../../debug/key_rsa/id_rsa_rfc4716.pub; popd
# Will Fail
```

> - RFC 4716 public key is unsupported

### Execute Fortified Files with RSA Private Key

Execute fortified files using RSA private key:

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa; popd
```

Execute fortified files using RSA private key in PEM format:

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa_pem; popd
```

Execute fortified files using RSA private key in RFC 4716 format:

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa_rfc4716; popd
```

```shell
pushd build/rsa && ../fortify execute -i fortified.data ../../debug/key_rsa/id_rsa_pkcs8; popd
# Will Fail
```

> - encrypted PKCS #8 private key is unsupported

---
