using System;

namespace ThreeNcr;

/// <summary>
/// Thrown when a <c>3ncr.org/1#...</c> value cannot be decoded or decrypted
/// (malformed base64, truncated payload, or authentication tag mismatch).
/// </summary>
public class TokenCryptException : Exception
{
    /// <summary>Create a new <see cref="TokenCryptException"/> with a message.</summary>
    public TokenCryptException(string message) : base(message) { }

    /// <summary>Create a new <see cref="TokenCryptException"/> with a message and an inner exception.</summary>
    public TokenCryptException(string message, Exception innerException) : base(message, innerException) { }
}
