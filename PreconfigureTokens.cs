// Copyright (c) 2025 Duplicati Inc.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace DuplicatiIngress;

/// <summary>
/// Service for getting information about preconfigured tokens
/// </summary>
public interface IPreconfiguredTokens
{
    /// <summary>
    /// Gets the parsed token or <c>null</c> if the token is invalid
    /// </summary>
    /// <param name="token">The token</param>
    ParsedIngressToken? GetPreconfiguredToken(string token);
}

/// <summary>
/// Configuration for whitelist/blacklist overrides
/// </summary>
public sealed record PreconfiguredTokensConfig
{
    /// <summary>
    /// List of token entries
    /// </summary>
    /// <param name="OrganizationId">The organization id</param>
    /// <param name="KeyId">The key id</param>
    public record TokenListEntry
    {
        /// <summary>
        /// The organization id
        /// </summary>
        [JsonPropertyName("organizationId")]
        public required string OrganizationId { get; init; }

        /// <summary>
        /// The key id
        /// </summary>
        [JsonPropertyName("keyId")]
        public required string KeyId { get; init; }
    }

    /// <summary>
    /// The whitelisted tokens, key is the token, value is the organization id and key id
    /// </summary>
    public required IReadOnlyDictionary<string, TokenListEntry> WhitelistTokens { get; init; }

    /// <summary>
    /// The blacklisted tokens
    /// </summary>
    public required HashSet<string> BlacklistTokens { get; init; }

    /// <summary>
    /// Flag indicating whether the configuration is empty
    /// </summary>
    public bool IsEmpty => WhitelistTokens.Count == 0 && BlacklistTokens.Count == 0;

    /// <summary>
    /// Gets an empty instance
    /// </summary>
    /// <returns>An empty instance</returns>
    internal static PreconfiguredTokensConfig CreateEmpty()
        => new PreconfiguredTokensConfig
        {
            WhitelistTokens = new Dictionary<string, TokenListEntry>(),
            BlacklistTokens = new HashSet<string>()
        };
}

/// <summary>
/// Service for getting information about preconfigured tokens
/// </summary>
public class PreconfiguredTokens(IEncryptionKeyProvider encryptionKeyProvider, PreconfiguredTokensConfig preconfiguredTokensConfig) : IPreconfiguredTokens
{
    /// <inheritdoc />
    public ParsedIngressToken? GetPreconfiguredToken(string token)
    {
        if (preconfiguredTokensConfig.IsEmpty)
            return null;

        if (preconfiguredTokensConfig.BlacklistTokens.Contains(token))
            throw new SecurityTokenValidationException("Invalid token, blacklisted");

        if (preconfiguredTokensConfig.WhitelistTokens.TryGetValue(token, out var tokenEntry) && !string.IsNullOrWhiteSpace(tokenEntry?.OrganizationId) && !string.IsNullOrWhiteSpace(tokenEntry?.KeyId))
        {
            var encryptionKey = encryptionKeyProvider.GetEncryptionKey(tokenEntry.KeyId);
            if (string.IsNullOrWhiteSpace(encryptionKey))
                throw new SecurityTokenValidationException("Invalid token, key not found");
            return new ParsedIngressToken(tokenEntry.OrganizationId, tokenEntry.KeyId, encryptionKey);
        }

        return null;
    }

    /// <summary>
    /// Loads the a whitelist and blacklist from storage
    /// </summary>
    /// <param name="config">The environment configuration</param>
    /// <returns>The parsed token configuration</returns>
    public static async Task<PreconfiguredTokensConfig> LoadFromStorage(TokenRuleOverrideConfig? config)
    {
        if (config == null || !config.IsValid)
            return PreconfiguredTokensConfig.CreateEmpty();

        var blacklistedTokens = new HashSet<string>();
        var whitelistedTokens = new Dictionary<string, PreconfiguredTokensConfig.TokenListEntry>();

        var tokenLoader = KVPSButter.KVPSLoader.CreateIKVPS(config.Storage);
        if (!string.IsNullOrWhiteSpace(config.BlacklistEntry))
        {
            await using var fs = await tokenLoader.ReadAsync(config.BlacklistEntry)
                ?? throw new InvalidOperationException("Failed to read blacklisted tokens");

            blacklistedTokens = await JsonSerializer.DeserializeAsync<HashSet<string>>(fs)
                ?? throw new InvalidOperationException("Failed to parse blacklisted tokens");
        }

        if (!string.IsNullOrWhiteSpace(config.WhitelistEntry))
        {
            await using var fs = await tokenLoader.ReadAsync(config.WhitelistEntry)
                ?? throw new InvalidOperationException("Failed to read whitelisted tokens");

            whitelistedTokens = await JsonSerializer.DeserializeAsync<Dictionary<string, PreconfiguredTokensConfig.TokenListEntry>>(fs)
                ?? throw new InvalidOperationException("Failed to parse whitelisted tokens");
        }

        return new PreconfiguredTokensConfig()
        {
            WhitelistTokens = whitelistedTokens,
            BlacklistTokens = blacklistedTokens
        };
    }
}
