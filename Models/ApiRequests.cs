using System.Text.Json.Serialization;

namespace AgentAnalysisService.Models;

// ========== Request Models ==========

public class AnalyzeRequest
{
    /// <summary>Absolute path to the target DLL/EXE file.</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>If true, decompile all method bodies to C#.</summary>
    public bool DecompileAll { get; set; } = false;

    /// <summary>Filter: only analyze types whose full name contains this string.</summary>
    public string? TypeFilter { get; set; }

    /// <summary>If true, include full IL disassembly of all method bodies.</summary>
    public bool IncludeIL { get; set; } = true;

    /// <summary>If true, run sensitive API scan.</summary>
    public bool ScanSensitive { get; set; } = true;

    /// <summary>If true, compute dependency graph.</summary>
    public bool IncludeDependencies { get; set; } = true;
}

public class DecompileRequest
{
    public string Path { get; set; } = string.Empty;
    public string? TypeName { get; set; }
    public string? MemberName { get; set; }
}

public class ScanRequest
{
    public string Path { get; set; } = string.Empty;
}

public class DependenciesRequest
{
    public string Path { get; set; } = string.Empty;
}
