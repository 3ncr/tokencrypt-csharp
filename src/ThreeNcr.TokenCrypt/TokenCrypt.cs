using System;
using System.Security.Cryptography;
using System.Text;

using Konscious.Security.Cryptography;

using Org.BouncyCastle.Crypto.Digests;

namespace ThreeNcr;

/// <summary>
/// .NET implementation of the <see href="https://3ncr.org/">3ncr.org</see>
/// v1 string encryption standard.
/// </summary>
/// <remarks>
/// <para>The v1 envelope is
/// <c>3ncr.org/1#&lt;base64(iv[12] || ciphertext || tag[16])&gt;</c> using
/// AES-256-GCM with a 12-byte random IV and base64 without padding. The
/// envelope is agnostic of how the 32-byte AES key was derived; pick a
/// factory based on the entropy of the input secret.</para>
/// </remarks>
public sealed class TokenCrypt : IDisposable
{
    /// <summary>3ncr.org v1 envelope header.</summary>
    public const string HeaderV1 = "3ncr.org/1#";

    private const int AesKeySize = 32;
    private const int IvSize = 12;
    private const int TagSize = 16;

    // 3ncr.org recommended Argon2id parameters (https://3ncr.org/1/ — Key
    // Derivation section).
    private const int Argon2idMemoryKiB = 19456;
    private const int Argon2idTimeCost = 2;
    private const int Argon2idParallelism = 1;
    private const int Argon2idMinSaltBytes = 16;

    private readonly AesGcm _cipher;
    private bool _disposed;

    private TokenCrypt(byte[] key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }
        if (key.Length != AesKeySize)
        {
            throw new ArgumentException(
                $"key must be exactly {AesKeySize} bytes, got {key.Length}",
                nameof(key));
        }
        _cipher = new AesGcm(key, TagSize);
    }

    /// <summary>
    /// Build a <see cref="TokenCrypt"/> from a raw 32-byte AES-256 key.
    /// </summary>
    /// <remarks>
    /// Use this when your secret is already high-entropy and exactly 32
    /// bytes (for example, loaded from a key-management service). The
    /// caller's array is copied internally, so it may be zeroed after this
    /// call returns.
    /// </remarks>
    public static TokenCrypt FromRawKey(byte[] key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }
        byte[] copy = new byte[key.Length];
        Buffer.BlockCopy(key, 0, copy, 0, key.Length);
        try
        {
            return new TokenCrypt(copy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    /// <summary>
    /// Derive the AES key from a high-entropy secret via a single SHA3-256
    /// hash.
    /// </summary>
    /// <remarks>
    /// Suitable for random pre-shared keys, UUIDs, or long random API
    /// tokens — inputs that already carry at least 128 bits of unique
    /// entropy. For low-entropy inputs such as user passwords, prefer
    /// <see cref="FromArgon2id(byte[], byte[])"/>.
    /// </remarks>
    public static TokenCrypt FromSha3(byte[] secret)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }
        Sha3Digest digest = new(256);
        digest.BlockUpdate(secret, 0, secret.Length);
        byte[] key = new byte[AesKeySize];
        digest.DoFinal(key, 0);
        try
        {
            return new TokenCrypt(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Convenience overload: UTF-8 encodes <paramref name="secret"/> before hashing.</summary>
    public static TokenCrypt FromSha3(string secret)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }
        return FromSha3(Encoding.UTF8.GetBytes(secret));
    }

    /// <summary>
    /// Derive the AES key from a low-entropy secret via Argon2id using the
    /// 3ncr.org v1 recommended parameters (m=19456 KiB, t=2, p=1).
    /// </summary>
    /// <remarks>
    /// <paramref name="salt"/> must be at least 16 bytes. For deterministic
    /// derivation across implementations, pass the same salt.
    /// </remarks>
    public static TokenCrypt FromArgon2id(byte[] secret, byte[] salt)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }
        if (salt is null || salt.Length < Argon2idMinSaltBytes)
        {
            int got = salt?.Length ?? 0;
            throw new ArgumentException(
                $"salt must be at least {Argon2idMinSaltBytes} bytes, got {got}",
                nameof(salt));
        }
        using Argon2id argon2 = new(secret)
        {
            Salt = salt,
            DegreeOfParallelism = Argon2idParallelism,
            Iterations = Argon2idTimeCost,
            MemorySize = Argon2idMemoryKiB,
        };
        byte[] key = argon2.GetBytes(AesKeySize);
        try
        {
            return new TokenCrypt(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Convenience overload: UTF-8 encodes <paramref name="secret"/> before hashing.</summary>
    public static TokenCrypt FromArgon2id(string secret, byte[] salt)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }
        return FromArgon2id(Encoding.UTF8.GetBytes(secret), salt);
    }

    /// <summary>Encrypt a UTF-8 string and return a <c>3ncr.org/1#...</c> value.</summary>
    public string Encrypt3ncr(string plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        ThrowIfDisposed();
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        Span<byte> iv = stackalloc byte[IvSize];
        RandomNumberGenerator.Fill(iv);
        byte[] buffer = new byte[IvSize + plaintextBytes.Length + TagSize];
        iv.CopyTo(buffer.AsSpan(0, IvSize));
        Span<byte> ciphertext = buffer.AsSpan(IvSize, plaintextBytes.Length);
        Span<byte> tag = buffer.AsSpan(IvSize + plaintextBytes.Length, TagSize);
        _cipher.Encrypt(iv, plaintextBytes, ciphertext, tag);
        return HeaderV1 + Convert.ToBase64String(buffer).TrimEnd('=');
    }

    /// <summary>
    /// If <paramref name="value"/> has the <c>3ncr.org/1#</c> header,
    /// decrypt it; otherwise return it unchanged.
    /// </summary>
    /// <remarks>
    /// This makes it safe to route every configuration value through
    /// <see cref="DecryptIf3ncr(string)"/> regardless of whether it was
    /// encrypted.
    /// </remarks>
    /// <exception cref="TokenCryptException">
    /// The value is a 3ncr token but cannot be decoded or authenticated.
    /// </exception>
    public string DecryptIf3ncr(string value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }
        if (!value.StartsWith(HeaderV1, StringComparison.Ordinal))
        {
            return value;
        }
        return Decrypt(value.Substring(HeaderV1.Length));
    }

    private string Decrypt(string body)
    {
        ThrowIfDisposed();
        // Spec emits no padding; re-pad here so Convert.FromBase64String accepts it.
        int padCount = (4 - body.Length % 4) % 4;
        string padded = padCount == 0 ? body : body + new string('=', padCount);
        byte[] buffer;
        try
        {
            buffer = Convert.FromBase64String(padded);
        }
        catch (FormatException e)
        {
            throw new TokenCryptException("invalid base64 payload", e);
        }
        if (buffer.Length < IvSize + TagSize)
        {
            throw new TokenCryptException("truncated 3ncr token");
        }
        int ciphertextLength = buffer.Length - IvSize - TagSize;
        ReadOnlySpan<byte> iv = buffer.AsSpan(0, IvSize);
        ReadOnlySpan<byte> ciphertext = buffer.AsSpan(IvSize, ciphertextLength);
        ReadOnlySpan<byte> tag = buffer.AsSpan(IvSize + ciphertextLength, TagSize);
        byte[] plaintextBytes = new byte[ciphertextLength];
        try
        {
            _cipher.Decrypt(iv, ciphertext, tag, plaintextBytes);
        }
        catch (CryptographicException e)
        {
            throw new TokenCryptException("authentication tag verification failed", e);
        }
        return Encoding.UTF8.GetString(plaintextBytes);
    }

    /// <summary>Releases the underlying AES-GCM cipher resources.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _cipher.Dispose();
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TokenCrypt));
        }
    }
}
