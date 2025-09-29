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
using DuplicatiIngress;
using MassTransit;
using MassTransit.SqlTransport.PostgreSql;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RobotsTxt;
using Serilog;
using Serilog.Core;
using Serilog.Events;

var builder = WebApplication.CreateBuilder(args);

var envConfig = builder.Configuration.GetRequiredSection("Environment").Get<EnvironmentConfig>()!;
builder.Services.AddSingleton(envConfig);

// Prepare logging
var envLogLevel = builder.Configuration.GetValue<string>("Serilog:MinimumLevel:Default");
var logLevelSwitch = new LoggingLevelSwitch(
    !string.IsNullOrWhiteSpace(envLogLevel)
        ? Enum.Parse<LogEventLevel>(envLogLevel)
        : LogEventLevel.Information);

var logConfiguration = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .Enrich.WithClientIp()
    .Enrich.WithCorrelationId(headerName: "X-Request-Id")
    .Enrich.WithRequestHeader("User-Agent")
    .MinimumLevel.ControlledBy(logLevelSwitch)
    .WriteTo.Console();

builder.Host.UseSerilog();

// Support the untracked local environment variables file for development
if (builder.Environment.IsDevelopment())
{
    // Load into environment variables as well
    var localEnvironmentVariables = new ConfigurationBuilder()
           .AddJsonFile("local.environmentvariables.json", optional: true, reloadOnChange: false)
           .Build().AsEnumerable().ToList();

    foreach (var (key, value) in localEnvironmentVariables)
        Environment.SetEnvironmentVariable(key, value);
}

builder.Configuration.AddEnvironmentVariables();

var serilogConfig = builder.Configuration.GetSection("Serilog").Get<SerilogConfig>();
if (!string.IsNullOrWhiteSpace(serilogConfig?.SourceToken))
{
    if (string.IsNullOrWhiteSpace(serilogConfig.Endpoint))
    {
        logConfiguration = logConfiguration.WriteTo.BetterStack(
            sourceToken: serilogConfig.SourceToken
        );
    }
    else
    {
        logConfiguration = logConfiguration.WriteTo.BetterStack(
            sourceToken: serilogConfig.SourceToken,
            betterStackEndpoint: serilogConfig.Endpoint
        );
    }
}

builder.Services.AddHttpContextAccessor();

// Load encryption keys
var encryptionKeys = builder.Configuration.GetSection("EncryptionKey")
    .GetChildren()
    .Select(c => new { KeyId = c.Key, KeyValue = c.Value })
    .Where(c => !string.IsNullOrWhiteSpace(c.KeyId) && !string.IsNullOrWhiteSpace(c.KeyValue))
    .ToDictionary(c => c.KeyId, c => c.KeyValue!, StringComparer.OrdinalIgnoreCase);

if (encryptionKeys.Count == 0)
    throw new InvalidOperationException("No encryption keys configured");

builder.Services.AddSingleton(new EncryptionKeyConfig(encryptionKeys));

var jwt = builder.Configuration.GetRequiredSection("Ingress:JWT").Get<JWTConfig>()!;
builder.Services.AddSingleton(jwt);

if (!envConfig.IsProd)
{
    if (envConfig.Storage.StartsWith("file://"))
    {
        var path = envConfig.Storage.Substring("file://".Length).Split('?')[0];
        if (!Directory.Exists(path))
            Directory.CreateDirectory(path);
    }
}

builder.Services.AddSingleton(KVPSButter.KVPSLoader.CreateIKVPS(envConfig.Storage));

Log.Logger = logConfiguration
    .Enrich.WithProperty("Hostname", envConfig.Hostname)
    .Enrich.WithProperty("MachineName", envConfig.MachineName)
    .Enrich.WithProperty("IsProd", envConfig.IsProd)
    .CreateLogger();

var preconfiguredTokenConfig = await PreconfiguredTokens.LoadFromStorage(builder.Configuration.GetSection("PreconfiguredTokens").Get<TokenRuleOverrideConfig>());

builder.Services
    .AddTransient<IngressHandler>()
    .AddSingleton(preconfiguredTokenConfig)
    .AddSingleton<IPreconfiguredTokens, PreconfiguredTokens>()
    .AddTransient<IJWTValidator, JWTValidator>()
    .AddSingleton<IEncryptionKeyProvider, EncryptionKeyProvider>()
    .AddTransient<IPublishIngressMessage, PublishIngressMessage>()
    .AddStaticRobotsTxt(services => services.DenyAll());

builder.Services.AddMassTransit(x =>
{
    x.AddConsumer<FailedUploadConsumer>(configure: context => { context.UseMessageRetry(r => r.Interval(10, 1000)); });

    var messagingConfig = builder.Configuration.GetSection("Messaging").Get<MessagingConfig>();
    if (builder.Environment.IsDevelopment() && string.IsNullOrWhiteSpace(messagingConfig?.ConnectionString))
    {
        x.UsingInMemory((context, cfg) => cfg.ConfigureEndpoints(context));
    }
    else
    {
        if (string.IsNullOrWhiteSpace(messagingConfig?.ConnectionString))
            throw new InvalidOperationException("Messaging configuration is missing");
        x.UsingPostgres((context, cfg) =>
        {
            cfg.Host(new PostgresSqlHostSettings(messagingConfig.ConnectionString));
            cfg.ConfigureEndpoints(context);
        });
    }
});


var app = builder.Build();
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor
});

app.UseSerilogRequestLogging(options =>
{
    options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
    {
        diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value);
        diagnosticContext.Set("HttpRequestType", httpContext.Request.Method);
        diagnosticContext.Set("HttpRequestUrl", $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.Path}{httpContext.Request.QueryString}");
        diagnosticContext.Set("HttpRequestId", httpContext.TraceIdentifier);
    };
});

app.UseSecurityFilter();

app.MapPost("/backupreports/{token}",
    async ([FromServices] IngressHandler handler, [FromRoute] string token, CancellationToken ct) =>
    {
        await handler.MapPost(token, ct);
    });

app.MapGet("/health", () => "OK");
app.MapGet("/", ctx =>
{
    if (string.IsNullOrWhiteSpace(envConfig.RedirectUrl))
        ctx.Response.StatusCode = 404;
    else
        ctx.Response.Redirect(envConfig.RedirectUrl);
    return Task.CompletedTask;
});

app.UseHttpsRedirection();
app.UseRobotsTxt();
app.UseExceptionHandler(new ExceptionHandlerOptions
{
    ExceptionHandler = context =>
    {
        var ex = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        if (ex is UserReportedException ure)
        {
            context.Response.StatusCode = ure.StatusCode;
            context.Response.ContentType = "text/plain";
            return context.Response.WriteAsync(ure.Message);
        }
        else if (ex is SecurityTokenValidationException)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "text/plain";
            return context.Response.WriteAsync("Invalid token");
        }
        else
        {
            context.Response.StatusCode = 500;
            context.Response.ContentType = "text/plain";
            return context.Response.WriteAsync("An error occurred while processing your request.");
        }
    }
});

try
{
    Log.Information("Starting application...");
    app.Run();
}
catch (Exception ex)
{
    Log.Error(ex, "Crashed while running application");
}
finally
{
    Log.Information("Terminating application...");
    Log.CloseAndFlush();
}