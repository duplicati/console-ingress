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
namespace DuplicatiIngress;

/// <summary>
/// Middleware to filter against most common security threats and crawlers.
/// This is a simple implementation and is meant to provide basic protection and
/// discourage automated attacks as the requests will be blocked with a 403 status code.
///
/// This in conjunction with the rate limiting options provides basic protection.
/// </summary>
public class SecurityMiddleware(RequestDelegate next, ILogger<SecurityMiddleware> logger)
{

    /// <summary>
    /// These are the file extensions that are blocked by default.
    /// </summary>
    private static readonly HashSet<string> _blockedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".php", ".cgi", ".asp", ".aspx", ".ashx", ".asmx", ".axd", ".config", ".env",
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".jar", ".jsp", ".jspx", ".war",
        ".pl", ".py", ".rb", ".htaccess", ".htpasswd", ".ini", ".cfg", ".xml", ".conf"
    };

    /// <summary>
    /// This is a comprehensive list of attack paterns to filter, this is not exhaustive
    /// it can be incremented with more patterns as needed.
    /// </summary>
    private static readonly HashSet<string> _blockedPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        // Path traversal
        "../../", "../", "..\\", "%2e%2e", "%252e", "..;", "%c0%ae",
        
        // XSS
        "<script", "javascript:", "onload=", "onerror=", "onmouseover=",
        "onfocus=", "onblur=", "alert(", "confirm(", "prompt(",
        "document.cookie", "document.domain", "document.write",
        
        // File inclusion/disclosure
        ".htaccess", "etc/passwd", "win.ini", "web.config", ".env",
        "wp-config", "config.php", "phpinfo", ".git/", ".svn/",
        
        // Command injection
        "; ls", "; dir", "|ls", "|dir", "&&ls", "&&dir", "||ls", "||dir",
        "`ls`", "`dir`", "$(ls)", "$(dir)", "&lt;!--#exec",
        
        // NoSQL injection
        "$where:", "$gt:", "$lt:", "$ne:", "$in:", "$regex:",
        
        // Template injection
        "{{", "${", "#{", "<%= ", "[% ", "<? ", "<%"
    };

    /// <inheritdoc />
    public async Task InvokeAsync(HttpContext context)
    {
        if (IsBlocked(context))
        {
            var remoteip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault() ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            logger.LogWarning("Blocked request from IP {IP} with path {Path} and user agent {UserAgent}",
                remoteip,
                context.Request.Path,
                context.Request.Headers.UserAgent.ToString());

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await next(context);
    }

    /// <summary>
    /// Returns a requests matches any of the blocked patterns or extensions.
    /// </summary>
    /// <param name="context">Context of the request</param>
    /// <returns>True if the request should be blocked</returns>
    private bool IsBlocked(HttpContext context)
    {
        var path = context.Request.Path.ToString().ToLowerInvariant();

        // Check file extensions
        if (_blockedExtensions.Any(x => path.EndsWith(x)))
            return true;

        // Check for suspicious patterns in path, query string, and headers
        var valuesToCheck = new[]
        {
            path,
            context.Request.QueryString.ToString().ToLowerInvariant(),
            context.Request.Headers["Referer"].ToString(),
            context.Request.Headers["Cookie"].ToString(),
            context.Request.Headers["X-Forwarded-For"].ToString(),
            context.Request.Headers["X-Forwarded-Host"].ToString()
        };

        return valuesToCheck.Any(value =>
            _blockedPatterns.Any(pattern => value.Contains(pattern, StringComparison.OrdinalIgnoreCase)));
    }
}

/// <summary>
/// Helper to register the middleware on app.
/// </summary>
public static class SecurityMiddlewareExtensions
{
    /// <summary>
    /// Use the security filter middleware
    /// </summary>
    /// <param name="builder">The application builder</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder UseSecurityFilter(this IApplicationBuilder builder)
        => builder.UseMiddleware<SecurityMiddleware>();
}