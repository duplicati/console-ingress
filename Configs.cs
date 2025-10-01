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
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace DuplicatiIngress;

/// <summary>
/// Represents the Messaging configuration
/// </summary>
/// <param name="ConnectionString">The Messaging connection string</param>
public record MessagingConfig(string ConnectionString);

/// <summary>
/// Represents the environment configuration
/// </summary>
/// <param name="Hostname">The hostname</param>
/// <param name="IsProd">Whether the environment is production</param>
/// <param name="Storage">The storage</param>
/// <param name="RedirectUrl">The redirect URL for unmatched requests to the server</param>
/// <param name="MachineName">The machine name</param>
public record EnvironmentConfig(
    string? Hostname,
    bool IsProd,
    string Storage,
    string? RedirectUrl = null,
    string? MachineName = null
);

/// <summary>
/// Represents the JWT configuration
/// </summary>
/// <param name="Authority">The authority</param>
/// <param name="Audience">The audience</param>
/// <param name="SigningKey">The signing key</param>
public record JWTConfig(
    string Authority,
    string Audience,
    string? SigningKey = null)
{
    /// <summary>
    /// Gets the symmetric security key
    /// </summary>
    public SymmetricSecurityKey SymmetricSecurityKey => new(Encoding.UTF8.GetBytes(SigningKey!));
}

/// <summary>
/// Represents the encryption key configuration
/// </summary>
/// <param name="EncryptionKeys">The encryption keys</param>
public record EncryptionKeyConfig(
    Dictionary<string, string> EncryptionKeys
);

/// <summary>
/// Configuration for whitelist/blacklist overrides
/// </summary>
/// <param name="Storage">The storage location</param>
/// <param name="WhitelistEntry">The whitelist filename</param>
/// <param name="BlacklistEntry">The blacklist filename</param>
public record TokenRuleOverrideConfig(
    string Storage,
    string WhitelistEntry,
    string BlacklistEntry
)
{
    /// <summary>
    /// Gets a value indicating whether the configuration is valid
    /// </summary>
    public bool IsValid => !string.IsNullOrWhiteSpace(Storage)
        && !string.IsNullOrWhiteSpace(WhitelistEntry)
        && !string.IsNullOrWhiteSpace(BlacklistEntry);
}