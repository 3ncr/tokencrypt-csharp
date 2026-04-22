# ThreeNcr.TokenCrypt (3ncr.org)

.NET implementation of the [3ncr.org](https://3ncr.org/) v1 string encryption
standard.

3ncr.org is a small, interoperable format for encrypted strings, originally
intended for encrypting tokens in configuration files but usable for any UTF-8
string. v1 uses AES-256-GCM with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

## Install

```
dotnet add package ThreeNcr.TokenCrypt
```

Requires .NET 8.0 or later.

## Usage

Pick a factory based on the entropy of your secret.

### Recommended: Argon2id (low-entropy secrets)

For passwords or passphrases, use `TokenCrypt.FromArgon2id`. It uses the
parameters recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(m=19456 KiB, t=2, p=1). Salt must be at least 16 bytes.

```csharp
using ThreeNcr;

using TokenCrypt tc = TokenCrypt.FromArgon2id(
    "correct horse battery staple",
    System.Text.Encoding.UTF8.GetBytes("0123456789abcdef"));
```

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

### Legacy: PBKDF2-SHA3

The original `(secret, salt, iterations)` KDF is kept for backward compatibility
with data encrypted by earlier 3ncr.org libraries. It is **deprecated** — prefer
`FromArgon2id`, `FromRawKey`, or `FromSha3` for new code.

```csharp
using ThreeNcr;

#pragma warning disable CS0618
using TokenCrypt tc = TokenCrypt.FromPbkdf2Sha3("my-secret", "my-salt", 1000);
#pragma warning restore CS0618
```

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

This implementation decrypts the canonical v1 test vectors shared with the
[Go](https://github.com/3ncr/tokencrypt),
[Node.js](https://github.com/3ncr/nodencrypt),
[PHP](https://github.com/3ncr/tokencrypt-php),
[Python](https://github.com/3ncr/tokencrypt-python),
[Rust](https://github.com/3ncr/tokencrypt-rust), and
[Java](https://github.com/3ncr/tokencrypt-java) reference libraries
(`secret = "a"`, `salt = "b"`, `iterations = 1000`). See
`tests/ThreeNcr.TokenCrypt.Tests/TokenCryptTests.cs`.

## License

MIT
