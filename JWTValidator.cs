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
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace DuplicatiIngress;

/// <summary>
/// Represents the JWT validator
/// </summary>
public interface IJWTValidator
{
    /// <summary>
    /// Validates the token and returns the parsed token
    /// </summary>
    ParsedIngressToken Validate(string token);
}

/// <summary>
/// Represents the JWT validator and token parser
/// </summary>
public class JWTValidator : IJWTValidator
{
    /// <summary>
    /// The cached token validation parameters
    /// </summary>
    private readonly TokenValidationParameters TokenValidationParameters;
    /// <summary>
    /// The encryption key provider
    /// </summary>
    private readonly IEncryptionKeyProvider EncryptionKeyProvider;

    /// <summary>
    /// The environment configuration
    /// </summary>
    private readonly EnvironmentConfig EnvironmentConfig;

    /// <summary>
    /// Initializes a new instance of the <see cref="JWTValidator"/> class
    /// </summary>
    /// <param name="encryptionKeyProvider">The encryption key provider</param>
    /// <param name="jWTConfig">The JWT configuration</param>
    public JWTValidator(IEncryptionKeyProvider encryptionKeyProvider, JWTConfig jWTConfig, EnvironmentConfig environmentConfig)
    {
        EncryptionKeyProvider = encryptionKeyProvider;
        TokenValidationParameters = GetTokenValidationParameters(jWTConfig);
        EnvironmentConfig = environmentConfig;
    }

    /// <summary>
    /// Gets the token validation parameters
    /// </summary>
    /// <param name="jWTConfig">The JWT configuration</param>
    /// <returns>The token validation parameters</returns>
    private static TokenValidationParameters GetTokenValidationParameters(JWTConfig jWTConfig)
        => new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jWTConfig.Authority,
            ValidAudience = jWTConfig.Audience,
            IssuerSigningKey = string.IsNullOrEmpty(jWTConfig.SigningKey) ? null : jWTConfig.SymmetricSecurityKey
        };

    /// <summary>
    /// The token type to accept
    /// </summary>
    private const string TokenType = "ingress";

    /// <summary>
    /// Represents the claim types
    /// </summary>
    private static class ClaimTypes
    {
        /// <summary>
        /// The organization id
        /// </summary>
        public const string OrganizationId = "oid";
        /// <summary>
        /// The encryption key id
        /// </summary>
        public const string KeyId = "kid";
        /// <summary>
        /// The token type
        /// </summary>
        public const string Type = "typ";
    }

    /// <summary>
    /// Validates the token
    /// </summary>
    /// <param name="token">The token</param>
    /// <param name="tokenValidationParameters">The token validation parameters</param>
    /// <param name="securityToken">The parsed security token</param>
    private static void ValidateToken(string token, TokenValidationParameters tokenValidationParameters, out SecurityToken? securityToken)
    {
        new JwtSecurityTokenHandler().ValidateToken(token, tokenValidationParameters, out securityToken);

        // Validate token type
        if (securityToken is not JwtSecurityToken jwtToken || jwtToken.Claims.First(c => c.Type == ClaimTypes.Type).Value != TokenType)
            throw new SecurityTokenValidationException("Invalid token type");
    }

    /// <inheritdoc />    
    public ParsedIngressToken Validate(string token)
    {
        ValidateToken(token, TokenValidationParameters, out var securityToken);

        var jwtToken = (JwtSecurityToken)securityToken!;
        var orgId = jwtToken.Claims.First(c => c.Type == ClaimTypes.OrganizationId).Value;
        var keyId = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.KeyId)?.Value;

        if (string.IsNullOrWhiteSpace(orgId))
            throw new SecurityTokenValidationException("Organization ID is missing");

        if (EnvironmentConfig.DisableReportEncryption ?? false)
            return new ParsedIngressToken(orgId, null!, null!);

        if (string.IsNullOrWhiteSpace(keyId))
            throw new SecurityTokenValidationException("Key ID is missing");

        var encryptionKey = EncryptionKeyProvider.GetEncryptionKey(keyId);
        if (string.IsNullOrWhiteSpace(encryptionKey))
            throw new SecurityTokenValidationException("Encryption key is missing");

        return new ParsedIngressToken(orgId, keyId, encryptionKey);
    }
}
