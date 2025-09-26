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
using System.Text.Json;
using System.Text.Json.Nodes;
using KVPSButter;
using MassTransit;
using Serilog;
using UuidExtensions;

namespace DuplicatiIngress;

/// <summary>
/// Represents the ingress handler
/// </summary>
/// <param name="httpContextAccessor">The HTTP context accessor</param>
/// <param name="legacyTokens">The legacy tokens</param>
/// <param name="jWTValidator">The JWT validator</param>
/// <param name="busControl">The bus control</param>
/// <param name="storage">The storage</param>
public class IngressHandler(
    IHttpContextAccessor httpContextAccessor,
    IPreconfiguredTokens preconfiguredTokens,
    IJWTValidator jWTValidator,
    IBusControl busControl,
    IPublishIngressMessage publishIngressMessage,
    IKVPS storage
)
{
    /// <summary>
    /// The maximum payload size for a report
    /// </summary>
    private const int MaxPayloadSize = 2 * 1024 * 1024;

    /// <summary>
    /// Maps the POST request
    /// </summary>
    /// <param name="token">The token</param>
    public async Task MapPost(string token, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(httpContextAccessor.HttpContext!.Request.ContentType) && !httpContextAccessor.HttpContext!.Request.ContentType.Contains("application/json"))
            throw new UserReportedException("Invalid media type", 415);

        // Store the data in a temporary file
        string? tempFileToDelete = null;
        string? encFileToDelete = null;
        try
        {
            // 1. Get the organization id from the token
            // 1a. Look in preconfigured tokens
            // 1b. Read from JWT
            var parsedToken = preconfiguredTokens.GetPreconfiguredToken(token)
                ?? jWTValidator.Validate(token);

            // 2. Generate a filename
            var uuid = Uuid7.String();
            var filename = $"{parsedToken.OrganizationId}/{uuid}.json.aes";

            // 4. Rudimentary validation of input
            tempFileToDelete = Path.GetTempFileName();
            using (var fs = File.OpenWrite(tempFileToDelete))
                await httpContextAccessor.HttpContext!.Request.Body.CopyToAsync(fs, ct);

            var length = new FileInfo(tempFileToDelete).Length;
            if (length == 0)
                throw new UserReportedException("Missing content", 400);

            if (length > MaxPayloadSize)
                throw new UserReportedException("Payload is too large", 413);

            try
            {
                using (var fs = File.OpenRead(tempFileToDelete))
                {
                    var js = await JsonSerializer.DeserializeAsync<JsonObject>(fs, cancellationToken: ct) ?? throw new InvalidOperationException("Failed to parse JSON");
                    var valid = js.TryGetPropertyValue("Data", out var dataPropNode)
                        && js.TryGetPropertyValue("Extra", out var extra);

                    if (!valid)
                        throw new UserReportedException("Payload is not valid JSON", 400);
                }
            }
            catch (Exception ex)
            {
                throw new UserReportedException("Payload is not valid JSON", statuscode: 400, exception: ex);
            }

            // 5. Encrypt with AESCrypt
            encFileToDelete = Path.GetTempFileName();
            var encHeaders = new KeyValuePair<string, byte[]>("key", Encoding.UTF8.GetBytes(parsedToken.KeyId));
            var options = new SharpAESCrypt.EncryptionOptions(InsertPlaceholder: false, AdditionalExtensions: [encHeaders]);

            using (var s1 = File.OpenRead(tempFileToDelete))
            using (var s2 = File.OpenWrite(encFileToDelete))
                await SharpAESCrypt.AESCrypt.EncryptAsync(parsedToken.EncryptionKey, s1, s2, options, ct);

            // 6. Store the payload with IKVPS
            var uploaded = false;
            try
            {
                using (var fs = File.OpenRead(encFileToDelete))
                    await storage.WriteAsync(filename, fs, ct);
                uploaded = true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to write encrypted file to storage, sending failed message to bus");
            }

            if (uploaded)
            {
                // 7. Publish a message to the bus
                await publishIngressMessage.PublishMessage(parsedToken.OrganizationId, filename, uuid.ToString()!, ct);
            }
            else
            {
                // Upload failed, queue for retry
                await busControl.Publish(new FailedEntryMessage
                (
                    OrganizationId: parsedToken.OrganizationId,
                    Filename: filename,
                    Uuid: uuid,
                    Data: await File.ReadAllBytesAsync(tempFileToDelete, ct)
                ), ct);
            }
        }
        finally
        {
            if (tempFileToDelete != null)
                try { File.Delete(tempFileToDelete); }
                catch { }

            if (encFileToDelete != null)
                try { File.Delete(encFileToDelete); }
                catch { }
        }
    }
}
