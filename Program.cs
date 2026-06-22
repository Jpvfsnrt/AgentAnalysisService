using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using AgentAnalysisService.Models;
using AgentAnalysisService.Services;

var builder = WebApplication.CreateBuilder(args);

// ─── Configuration ────────────────────────────────────────────────
var config = builder.Configuration;
var maxFileSizeMB = config.GetValue<int>("AnalysisService:MaxFileSizeMB", 200);
var maxConcurrent = config.GetValue<int>("AnalysisService:MaxConcurrentAnalyses", 4);
var cacheExpiration = TimeSpan.FromMinutes(
    config.GetValue<int>("AnalysisService:CacheExpirationMinutes", 30));

// ─── Services ─────────────────────────────────────────────────────
builder.Services.AddSingleton<AssemblyAnalyzer>();
builder.Services.AddSingleton<CSharpDecompilerWrapper>();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    options.SerializerOptions.WriteIndented = true;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
});

var app = builder.Build();

// ─── In-memory cache ──────────────────────────────────────────────
var cache = new ConcurrentDictionary<string, (AnalysisResponse Response, DateTime Expiry)>();
var semaphore = new SemaphoreSlim(maxConcurrent, maxConcurrent);

// ─── Middleware ───────────────────────────────────────────────────
app.UseMiddleware<ErrorHandlingMiddleware>();

// ═══════════════════════════════════════════════════════════════════
//  API Routes
// ═══════════════════════════════════════════════════════════════════

var api = app.MapGroup("/api");

// ── GET /api/health ───────────────────────────────────────────────
api.MapGet("/health", () => Results.Ok(new
{
    Status = "healthy",
    Version = "1.0.0",
    Timestamp = DateTime.UtcNow,
    CacheSize = cache.Count,
    MaxConcurrent = maxConcurrent
}));

// ── POST /api/analyze ─────────────────────────────────────────────
// Full assembly analysis: metadata, IL, C# decompilation, deps, sensitive API scan
api.MapPost("/analyze", async (AnalyzeRequest request, AssemblyAnalyzer analyzer) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
        return Results.BadRequest(new ErrorResponse { Error = "Path is required." });

    var cacheKey = $"analyze:{request.Path}:{request.DecompileAll}:{request.IncludeIL}:{request.ScanSensitive}:{request.IncludeDependencies}";

    // Check cache
    if (cache.TryGetValue(cacheKey, out var cached) && DateTime.UtcNow < cached.Expiry)
    {
        return Results.Ok(cached.Response);
    }

    // Limit concurrency
    await semaphore.WaitAsync();
    try
    {
        var response = await Task.Run(() => analyzer.Analyze(request.Path, request));
        cache[cacheKey] = (response, DateTime.UtcNow + cacheExpiration);
        return Results.Ok(response);
    }
    finally
    {
        semaphore.Release();
    }
});

// ── POST /api/analyze/upload ──────────────────────────────────────
// Upload a DLL file for analysis
api.MapPost("/analyze/upload", async (IFormFile file, AssemblyAnalyzer analyzer) =>
{
    if (file == null || file.Length == 0)
        return Results.BadRequest(new ErrorResponse { Error = "No file uploaded." });

    if (file.Length > maxFileSizeMB * 1024 * 1024)
        return Results.BadRequest(new ErrorResponse
            { Error = $"File too large. Maximum allowed: {maxFileSizeMB} MB." });

    var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
    if (ext != ".dll" && ext != ".exe" && ext != ".netmodule" && ext != ".winmd")
        return Results.BadRequest(new ErrorResponse
            { Error = $"Unsupported file extension: {ext}. Expected .dll, .exe, .netmodule, or .winmd." });

    // Save to temp location
    var tempPath = Path.Combine(Path.GetTempPath(), "dnspy_agent_", $"{Guid.NewGuid()}{ext}");
    Directory.CreateDirectory(Path.GetDirectoryName(tempPath)!);

    try
    {
        using (var stream = new FileStream(tempPath, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }

        var request = new AnalyzeRequest
        {
            Path = tempPath,
            IncludeIL = true,
            ScanSensitive = true,
            IncludeDependencies = true
        };

        var response = await Task.Run(() => analyzer.Analyze(tempPath, request));
        return Results.Ok(response);
    }
    finally
    {
        // Cleanup temp file
        if (File.Exists(tempPath))
        {
            try { File.Delete(tempPath); } catch { }
        }
    }
}).DisableAntiforgery();

// ── POST /api/decompile ──────────────────────────────────────────
// Decompile a specific type or member to C#
api.MapPost("/decompile", async (DecompileRequest request, AssemblyAnalyzer analyzer) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
        return Results.BadRequest(new ErrorResponse { Error = "Path is required." });

    try
    {
        var code = await Task.Run(() => analyzer.Decompile(request.Path, request.TypeName, request.MemberName));
        return Results.Ok(new
        {
            FilePath = request.Path,
            TypeName = request.TypeName,
            MemberName = request.MemberName,
            Code = code
        });
    }
    catch (FileNotFoundException ex)
    {
        return Results.NotFound(new ErrorResponse { Error = ex.Message });
    }
});

// ── POST /api/scan/sensitive ─────────────────────────────────────
// Scan only for sensitive APIs (faster than full analysis)
api.MapPost("/scan/sensitive", async (ScanRequest request, AssemblyAnalyzer analyzer) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
        return Results.BadRequest(new ErrorResponse { Error = "Path is required." });

    var cacheKey = $"scan:{request.Path}";
    if (cache.TryGetValue(cacheKey, out var cached) && DateTime.UtcNow < cached.Expiry)
    {
        return Results.Ok(new { FilePath = request.Path, SensitiveApis = cached.Response.SensitiveApis });
    }

    var fullRequest = new AnalyzeRequest
    {
        Path = request.Path,
        IncludeIL = false,
        ScanSensitive = true,
        IncludeDependencies = false,
        DecompileAll = false
    };

    var response = await Task.Run(() => analyzer.Analyze(request.Path, fullRequest));
    cache[cacheKey] = (response, DateTime.UtcNow + cacheExpiration);

    return Results.Ok(new
    {
        response.FilePath,
        response.FileName,
        response.SensitiveApis
    });
});

// ── POST /api/dependencies ───────────────────────────────────────
// Analyze dependencies and inheritance only
api.MapPost("/dependencies", async (DependenciesRequest request, AssemblyAnalyzer analyzer) =>
{
    if (string.IsNullOrWhiteSpace(request.Path))
        return Results.BadRequest(new ErrorResponse { Error = "Path is required." });

    var fullRequest = new AnalyzeRequest
    {
        Path = request.Path,
        IncludeIL = false,
        ScanSensitive = false,
        IncludeDependencies = true,
        DecompileAll = false
    };

    var response = await Task.Run(() => analyzer.Analyze(request.Path, fullRequest));
    return Results.Ok(new
    {
        response.FilePath,
        response.FileName,
        response.Assembly,
        response.References,
        response.Dependencies
    });
});

// ── GET /api/types/{fileHash} ────────────────────────────────────
// Get type list from a cached analysis
api.MapGet("/types/{fileHash}", (string fileHash) =>
{
    var entry = cache.Values.FirstOrDefault(v =>
        v.Response.FileHash.Equals(fileHash, StringComparison.OrdinalIgnoreCase));
    if (entry.Response == null)
        return Results.NotFound(new ErrorResponse
            { Error = "File hash not found in cache. Run POST /api/analyze first." });

    return Results.Ok(new
    {
        entry.Response.FilePath,
        entry.Response.FileHash,
        Types = entry.Response.Types.Select(t => new
        {
            t.FullName,
            t.Kind,
            t.Visibility,
            t.BaseType,
            MethodCount = t.Methods.Count,
            FieldCount = t.Fields.Count,
            t.IsStatic,
            t.IsAbstract
        })
    });
});

// ── DELETE /api/cache ────────────────────────────────────────────
// Clear all cached analyses
api.MapDelete("/cache", () =>
{
    var count = cache.Count;
    cache.Clear();
    return Results.Ok(new { Cleared = count, Message = $"Cleared {count} cached entries." });
});

// ── GET /api/cache ───────────────────────────────────────────────
// View cache entries
api.MapGet("/cache", () => Results.Ok(new
{
    Entries = cache.Values.Select(v => new
    {
        v.Response.FilePath,
        v.Response.FileHash,
        v.Response.FileSize,
        TypeCount = v.Response.Types.Count,
        v.Expiry
    })
}));

// ── Fallback 404 ──────────────────────────────────────────────────
app.MapGet("/", () => Results.Content(@"
<html>
<head><title>dnSpy Agent Analysis Service</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; color: #e0e0e0; background: #1e1e2e; }
  h1 { color: #89b4fa; } code { background: #313244; padding: 2px 6px; border-radius: 3px; }
  .endpoint { margin: 15px 0; padding: 10px 15px; background: #313244; border-radius: 6px; }
  .method { font-weight: bold; color: #a6e3a1; margin-right: 10px; }
  .path { color: #89b4fa; }
  .desc { color: #bac2de; margin-top: 5px; }
</style></head>
<body>
<h1>🔍 dnSpy Agent Analysis Service</h1>
<p>A headless <code>.NET</code> assembly analysis service for AI agents.</p>

<h2>Endpoints</h2>
<div class='endpoint'><span class='method'>POST</span><span class='path'>/api/analyze</span><div class='desc'>Full analysis: metadata, IL, decompilation, dependency graph, sensitive API scan</div></div>
<div class='endpoint'><span class='method'>POST</span><span class='path'>/api/analyze/upload</span><div class='desc'>Upload a DLL file for full analysis</div></div>
<div class='endpoint'><span class='method'>POST</span><span class='path'>/api/decompile</span><div class='desc'>Decompile a specific type/member to C#</div></div>
<div class='endpoint'><span class='method'>POST</span><span class='path'>/api/scan/sensitive</span><div class='desc'>Scan for crypto, network, file IO, reflection, process APIs</div></div>
<div class='endpoint'><span class='method'>POST</span><span class='path'>/api/dependencies</span><div class='desc'>Analyze assembly references and type inheritance</div></div>
<div class='endpoint'><span class='method'>GET</span><span class='path'>/api/types/{fileHash}</span><div class='desc'>Get type list from cached analysis</div></div>
<div class='endpoint'><span class='method'>GET</span><span class='path'>/api/health</span><div class='desc'>Service health check</div></div>
<div class='endpoint'><span class='method'>DELETE</span><span class='path'>/api/cache</span><div class='desc'>Clear analysis cache</div></div>
</body></html>
", "text/html"));

app.Run();

// ═══════════════════════════════════════════════════════════════════
//  Global Error Handling Middleware
// ═══════════════════════════════════════════════════════════════════

public sealed class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;

    public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "Bad request");
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new ErrorResponse
            {
                Error = ex.Message
            });
        }
        catch (FileNotFoundException ex)
        {
            _logger.LogWarning(ex, "File not found");
            context.Response.StatusCode = 404;
            await context.Response.WriteAsJsonAsync(new ErrorResponse
            {
                Error = ex.Message
            });
        }
        catch (BadImageFormatException ex)
        {
            _logger.LogWarning(ex, "Invalid file format");
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new ErrorResponse
            {
                Error = "Invalid or unsupported .NET assembly format.",
                Detail = ex.Message
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled error");
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new ErrorResponse
            {
                Error = "Internal server error.",
                Detail = ex.Message
            });
        }
    }
}
