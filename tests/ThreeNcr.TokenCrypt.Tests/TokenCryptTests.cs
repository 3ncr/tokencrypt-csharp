using System;
using System.Security.Cryptography;
using System.Text;

using Xunit;

namespace ThreeNcr.Tests;

public class TokenCryptTests
{
    /// <summary>
    /// Canonical v1 test vectors shared across Go, Node, PHP, Python, Rust,
    /// Java, and .NET implementations. Derived via PBKDF2-SHA3-256 with
    /// secret="a", salt="b", iterations=1000.
    /// </summary>
    public static TheoryData<string, string> CanonicalVectors() => new()
    {
        { "a", "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8" },
        { "test", "3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc" },
        {
            "08019215-B205-4416-B2FB-132962F9952F",
            "3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ"
        },
        {
            "перевірка",
            "3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ"
        },
    };

    private static TokenCrypt Legacy() => TokenCrypt.FromPbkdf2Sha3("a", "b", 1000);

    private static byte[] RandomKey()
    {
        byte[] k = new byte[32];
        RandomNumberGenerator.Fill(k);
        return k;
    }

    [Theory]
    [MemberData(nameof(CanonicalVectors))]
    public void DecryptsCanonicalVector(string plaintext, string encrypted)
    {
        using TokenCrypt tc = Legacy();
        Assert.Equal(plaintext, tc.DecryptIf3ncr(encrypted));
    }

    [Theory]
    [MemberData(nameof(CanonicalVectors))]
    public void RoundTripsCanonicalPlaintext(string plaintext, string _ignoredEncrypted)
    {
        using TokenCrypt tc = Legacy();
        string enc = tc.Encrypt3ncr(plaintext);
        Assert.StartsWith(TokenCrypt.HeaderV1, enc);
        Assert.Equal(plaintext, tc.DecryptIf3ncr(enc));
    }

    [Fact]
    public void RoundTripsEdgeCases()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        string[] cases =
        {
            string.Empty,
            "x",
            "hello, world",
            "08019215-B205-4416-B2FB-132962F9952F",
            "перевірка 🌍 中文 ✓",
            new string('a', 4096),
        };
        foreach (string p in cases)
        {
            string enc = tc.Encrypt3ncr(p);
            Assert.Equal(p, tc.DecryptIf3ncr(enc));
        }
    }

    [Fact]
    public void Non3ncrReturnedUnchanged()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        string s = "plain config value";
        Assert.Same(s, tc.DecryptIf3ncr(s));
    }

    [Fact]
    public void EmptyStringReturnedUnchanged()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        string s = string.Empty;
        Assert.Same(s, tc.DecryptIf3ncr(s));
    }

    [Fact]
    public void IvUniquenessAcrossEncryptions()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        string a = tc.Encrypt3ncr("same plaintext");
        string b = tc.Encrypt3ncr("same plaintext");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void TamperedPayloadIsRejected()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        string enc = tc.Encrypt3ncr("sensitive value");
        string body = enc.Substring(TokenCrypt.HeaderV1.Length);
        char[] chars = body.ToCharArray();
        int idx = chars.Length / 2;
        chars[idx] = chars[idx] == 'A' ? 'B' : 'A';
        string tampered = TokenCrypt.HeaderV1 + new string(chars);
        Assert.Throws<TokenCryptException>(() => tc.DecryptIf3ncr(tampered));
    }

    [Fact]
    public void TruncatedPayloadIsRejected()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        TokenCryptException ex = Assert.Throws<TokenCryptException>(
            () => tc.DecryptIf3ncr(TokenCrypt.HeaderV1 + "AAAA"));
        Assert.Contains("truncated", ex.Message);
    }

    [Fact]
    public void DecoderAcceptsPaddedInput()
    {
        using TokenCrypt tc = Legacy();
        const string plaintext = "a";
        const string encrypted = "3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8";
        string body = encrypted.Substring(TokenCrypt.HeaderV1.Length);
        int padCount = (4 - body.Length % 4) % 4;
        string padded = TokenCrypt.HeaderV1 + body + new string('=', padCount);
        Assert.Equal(plaintext, tc.DecryptIf3ncr(padded));
    }

    [Fact]
    public void EncoderEmitsNoPadding()
    {
        using TokenCrypt tc = TokenCrypt.FromRawKey(RandomKey());
        string enc = tc.Encrypt3ncr("some value");
        Assert.DoesNotContain("=", enc);
    }

    [Fact]
    public void FromSha3RoundTrip()
    {
        using TokenCrypt tc = TokenCrypt.FromSha3("some-high-entropy-api-token");
        string enc = tc.Encrypt3ncr("hello");
        Assert.Equal("hello", tc.DecryptIf3ncr(enc));
    }

    [Fact]
    public void FromSha3BytesAndStringAgree()
    {
        const string secret = "some-high-entropy-api-token";
        using TokenCrypt a = TokenCrypt.FromSha3(secret);
        using TokenCrypt b = TokenCrypt.FromSha3(Encoding.UTF8.GetBytes(secret));
        string enc = a.Encrypt3ncr("hello");
        Assert.Equal("hello", b.DecryptIf3ncr(enc));
    }

    [Fact]
    public void FromArgon2idRoundTrip()
    {
        using TokenCrypt tc = TokenCrypt.FromArgon2id(
            "correct horse battery staple",
            Encoding.UTF8.GetBytes("0123456789abcdef"));
        foreach (object[] args in CanonicalVectors())
        {
            string p = (string)args[0];
            string enc = tc.Encrypt3ncr(p);
            Assert.Equal(p, tc.DecryptIf3ncr(enc));
        }
    }

    [Fact]
    public void FromArgon2idRejectsShortSalt()
    {
        Assert.Throws<ArgumentException>(
            () => TokenCrypt.FromArgon2id("secret", Encoding.UTF8.GetBytes("short")));
    }

    [Fact]
    public void FromArgon2idWrongSecretFailsToDecrypt()
    {
        byte[] salt = Encoding.UTF8.GetBytes("0123456789abcdef");
        using TokenCrypt right = TokenCrypt.FromArgon2id("right secret", salt);
        using TokenCrypt wrong = TokenCrypt.FromArgon2id("wrong secret", salt);
        string enc = right.Encrypt3ncr("hello");
        Assert.Throws<TokenCryptException>(() => wrong.DecryptIf3ncr(enc));
    }

    [Fact]
    public void FromRawKeyRejectsWrongLength()
    {
        Assert.Throws<ArgumentException>(() => TokenCrypt.FromRawKey(new byte[31]));
        Assert.Throws<ArgumentException>(() => TokenCrypt.FromRawKey(new byte[33]));
        Assert.Throws<ArgumentException>(() => TokenCrypt.FromRawKey(new byte[0]));
    }

    [Fact]
    public void RawKeyInputIsDefensivelyCopied()
    {
        byte[] key = RandomKey();
        byte[] original = (byte[])key.Clone();
        using TokenCrypt tc = TokenCrypt.FromRawKey(key);
        Array.Clear(key, 0, key.Length);
        string enc = tc.Encrypt3ncr("hello");
        using TokenCrypt same = TokenCrypt.FromRawKey(original);
        Assert.Equal("hello", same.DecryptIf3ncr(enc));
    }
}
