using dnlib.DotNet;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.TypeSystem;
using DecompilerSettings = ICSharpCode.Decompiler.DecompilerSettings;
using MsLog = Microsoft.Extensions.Logging;

namespace AgentAnalysisService.Services;

/// <summary>
/// Wraps ICSharpCode.Decompiler for C# decompilation.
/// Uses the modern ILSpy 8.x API which works with assembly files directly.
/// </summary>
public class CSharpDecompilerWrapper
{
    private readonly MsLog.ILogger _logger;

    public CSharpDecompilerWrapper(MsLog.ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Decompile a specific type or the whole assembly.
    /// </summary>
    public string DecompileMember(ModuleDefMD module, string? typeName, string? memberName)
    {
        var tempFile = Path.GetTempFileName() + ".dll";
        try
        {
            module.Write(tempFile);

            var decompiler = new CSharpDecompiler(tempFile, new DecompilerSettings
            {
                ThrowOnAssemblyResolveErrors = false,
                UseDebugSymbols = false,
                RemoveDeadCode = false,
            });

            if (!string.IsNullOrEmpty(typeName))
            {
                var type = FindType(module, typeName);
                if (type == null)
                    return $"// Type not found: {typeName}";

                var fullName = type.FullName;

                if (!string.IsNullOrEmpty(memberName))
                {
                    var code = decompiler.DecompileTypeAsString(new FullTypeName(fullName));
                    return $"// Decompiled type: {fullName} | Requested member: {memberName}\n\n{code}";
                }

                return decompiler.DecompileTypeAsString(new FullTypeName(fullName));
            }

            return decompiler.DecompileWholeModuleAsString();
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    /// <summary>
    /// Decompile a specific type to C#.
    /// </summary>
    public string DecompileType(ModuleDefMD module, TypeDef type)
    {
        var tempFile = Path.GetTempFileName() + ".dll";
        try
        {
            module.Write(tempFile);

            var decompiler = new CSharpDecompiler(tempFile, new DecompilerSettings
            {
                ThrowOnAssemblyResolveErrors = false,
                UseDebugSymbols = false,
                RemoveDeadCode = false,
            });

            return decompiler.DecompileTypeAsString(new FullTypeName(type.FullName));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    /// <summary>
    /// Batch decompile multiple types.
    /// </summary>
    public async IAsyncEnumerable<KeyValuePair<string, string>> DecompileTypesAsync(
        string filePath, IEnumerable<string> typeFullNames)
    {
        await Task.Yield();

        var decompiler = new CSharpDecompiler(filePath, new DecompilerSettings
        {
            ThrowOnAssemblyResolveErrors = false,
            UseDebugSymbols = false,
            RemoveDeadCode = false,
        });

        foreach (var typeName in typeFullNames)
        {
            string code;
            try
            {
                code = decompiler.DecompileTypeAsString(new FullTypeName(typeName));
            }
            catch (Exception ex)
            {
                code = $"// Decompilation failed: {ex.Message}";
            }
            yield return new KeyValuePair<string, string>(typeName, code);
        }
    }

    private static TypeDef? FindType(ModuleDefMD module, string typeName)
    {
        foreach (var type in module.GetTypes())
        {
            if (type.FullName.Equals(typeName, StringComparison.OrdinalIgnoreCase))
                return type;
        }
        foreach (var type in module.GetTypes())
        {
            if (type.FullName.Contains(typeName, StringComparison.OrdinalIgnoreCase))
                return type;
        }
        return null;
    }
}
