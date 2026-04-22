# ThreeNcr.TokenCrypt (3ncr.org)

[![Test](https://github.com/3ncr/tokencrypt-csharp/actions/workflows/test.yml/badge.svg)](https://github.com/3ncr/tokencrypt-csharp/actions/workflows/test.yml)
[![NuGet](https://img.shields.io/nuget/v/ThreeNcr.TokenCrypt.svg)](https://www.nuget.org/packages/ThreeNcr.TokenCrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[3ncr.org](https://3ncr.org/) is a standard for string encryption / decryption
(algorithms + storage format), originally intended for encrypting tokens in
configuration files but usable for any UTF-8 string. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the official .NET implementation.

## Install

```
dotnet add package ThreeNcr.TokenCrypt
```

Requires .NET 8.0 or later. AES-256-GCM and SHA3-256 come from
`System.Security.Cryptography`; Argon2id comes from
[Konscious.Security.Cryptography.Argon2](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2)
and PBKDF2-SHA3 helpers in interop tests use
[BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography).

## Usage

Pick a factory based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key, skip the KDF and pass it directly.

```csharp
using ThreeNcr;

byte[] key = new byte[32];
System.Security.Cryptography.RandomNumberGenerator.Fill(key);
using TokenCrypt tc = TokenCrypt.FromRawKey(key);
```

For a high-entropy secret that is not already 32 bytes (e.g. a random API
token), hash it through SHA3-256:

```csharp
using ThreeNcr;

using TokenCrypt tc = TokenCrypt.FromSha3("some-high-entropy-api-token");
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use `TokenCrypt.FromArgon2id`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(`m=19456 KiB, t=2, p=1`). The salt must be at least 16 bytes.

```csharp
using ThreeNcr;
using System.Text;

using TokenCrypt tc = TokenCrypt.FromArgon2id(
    "correct horse battery staple",
    Encoding.UTF8.GetBytes("0123456789abcdef"));
```

### Legacy: PBKDF2-SHA3 (existing data only)

This library does not implement the legacy PBKDF2-SHA3 KDF that earlier 3ncr.org
libraries (Go, Node.js, PHP) shipped for backward compatibility. If you need to
decrypt data produced by that KDF, derive the 32-byte key with BouncyCastle's
`Pkcs5S2ParametersGenerator` backed by a `Sha3Digest(256)` (or any
PBKDF2-SHA3-256 implementation) and pass the result to `FromRawKey`.

### Encrypt / decrypt

```csharp
using ThreeNcr;

using TokenCrypt tc = TokenCrypt.FromSha3("some-high-entropy-api-token");

string encrypted = tc.Encrypt3ncr("08019215-B205-4416-B2FB-132962F9952F");
// e.g. "3ncr.org/1#pHRu..."

string decrypted = tc.DecryptIf3ncr(encrypted);
```

`DecryptIf3ncr` returns its input unchanged when the value does not start with
the `3ncr.org/1#` header. This makes it safe to route every configuration value
through it regardless of whether it was encrypted.

Decryption failures (bad tag, truncated input, malformed base64) throw
`ThreeNcr.TokenCryptException`.

## Cross-implementation interop

This implementation decrypts the canonical v1 envelope test vectors shared with
the [Go](https://github.com/3ncr/tokencrypt),
[Node.js](https://github.com/3ncr/nodencrypt),
[PHP](https://github.com/3ncr/tokencrypt-php),
[Python](https://github.com/3ncr/tokencrypt-python),
[Rust](https://github.com/3ncr/tokencrypt-rust), and
[Java](https://github.com/3ncr/tokencrypt-java) reference libraries. The 32-byte
AES key those vectors were originally derived from (PBKDF2-SHA3-256 of
`secret = "a"`, `salt = "b"`, `iterations = 1000`) is hardcoded in the test
suite for envelope-level interop — this library only exposes the modern KDFs.
See `tests/ThreeNcr.TokenCrypt.Tests/TokenCryptTests.cs`.

## License

MIT — see [LICENSE](LICENSE).
