using System.Text.Json.Serialization;

namespace AgentAnalysisService.Models;

// ========== Response Models ==========

public class AnalysisResponse
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FileHash { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public AssemblyInfo Assembly { get; set; } = new();
    public List<ModuleInfo> Modules { get; set; } = new();
    public List<TypeInfo> Types { get; set; } = new();
    public List<string> EntryPoints { get; set; } = new();
    public List<AssemblyReferenceInfo> References { get; set; } = new();
    public DependencyGraph? Dependencies { get; set; }
    public List<SensitiveApiHit>? SensitiveApis { get; set; }
    public AnalysisTiming Timing { get; set; } = new();
}

public class AssemblyInfo
{
    public string Name { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string? Culture { get; set; }
    public string? PublicKeyToken { get; set; }
    public string TargetRuntime { get; set; } = string.Empty;
    public bool IsExe { get; set; }
    public bool IsDll { get; set; }
    public string? Architecture { get; set; }
    public Dictionary<string, string> CustomAttributes { get; set; } = new();
}

public class ModuleInfo
{
    public string Name { get; set; } = string.Empty;
    public string FullyQualifiedName { get; set; } = string.Empty;
    public int TypeCount { get; set; }
    public int MethodCount { get; set; }
    public Guid Mvid { get; set; }
}

public class TypeInfo
{
    public string Name { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Namespace { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty; // class, struct, interface, enum, delegate
    public string Visibility { get; set; } = string.Empty; // public, internal, private, etc.
    public bool IsSealed { get; set; }
    public bool IsAbstract { get; set; }
    public bool IsStatic { get; set; }
    public bool IsNested { get; set; }
    public string? BaseType { get; set; }
    public List<string> Interfaces { get; set; } = new();
    public List<MethodInfo> Methods { get; set; } = new();
    public List<FieldInfo> Fields { get; set; } = new();
    public List<PropertyInfo> Properties { get; set; } = new();
    public List<EventInfo> Events { get; set; } = new();
    public List<string> NestedTypes { get; set; } = new();
    public List<string> CustomAttributes { get; set; } = new();
    public string? DecompiledCode { get; set; }
}

public class MethodInfo
{
    public string Name { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Visibility { get; set; } = string.Empty;
    public bool IsStatic { get; set; }
    public bool IsVirtual { get; set; }
    public bool IsConstructor { get; set; }
    public bool IsGetter { get; set; }
    public bool IsSetter { get; set; }
    public string ReturnType { get; set; } = string.Empty;
    public List<ParameterInfo> Parameters { get; set; } = new();
    public List<InstructionInfo>? ILInstructions { get; set; }
    public List<ExceptionClauseInfo>? ExceptionClauses { get; set; }
    public int? MaxStack { get; set; }
    public int? ILCodeSize { get; set; }
    public bool HasBody { get; set; }
    public string? DecompiledCode { get; set; }
    public List<string> CalledMethods { get; set; } = new();
    public List<string> CustomAttributes { get; set; } = new();
}

public class ParameterInfo
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public int Index { get; set; }
    public bool IsHidden { get; set; }
}

public class InstructionInfo
{
    public uint Offset { get; set; }
    public string OpCode { get; set; } = string.Empty;
    public string? Operand { get; set; }
    public string? Comment { get; set; }
}

public class ExceptionClauseInfo
{
    public string Kind { get; set; } = string.Empty;
    public uint TryStart { get; set; }
    public uint TryEnd { get; set; }
    public uint HandlerStart { get; set; }
    public uint HandlerEnd { get; set; }
    public string? CatchType { get; set; }
    public uint? FilterStart { get; set; }
}

public class FieldInfo
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Visibility { get; set; } = string.Empty;
    public bool IsStatic { get; set; }
    public bool IsLiteral { get; set; }
    public bool IsInitOnly { get; set; }
    public string? ConstantValue { get; set; }
    public string? FieldOffset { get; set; }
    public List<string> CustomAttributes { get; set; } = new();
}

public class PropertyInfo
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string? GetMethod { get; set; }
    public string? SetMethod { get; set; }
    public List<string> CustomAttributes { get; set; } = new();
}

public class EventInfo
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string? AddMethod { get; set; }
    public string? RemoveMethod { get; set; }
    public string? InvokeMethod { get; set; }
}

public class AssemblyReferenceInfo
{
    public string Name { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string? PublicKeyToken { get; set; }
    public string? Culture { get; set; }
    public bool IsNetCoreAssembly { get; set; }
}

public class DependencyGraph
{
    public List<AssemblyDependencyNode> AssemblyDependencies { get; set; } = new();
    public List<TypeInheritanceNode> InheritanceTree { get; set; } = new();
}

public class AssemblyDependencyNode
{
    public string Assembly { get; set; } = string.Empty;
    public List<string> ReferencedAssemblies { get; set; } = new();
}

public class TypeInheritanceNode
{
    public string Type { get; set; } = string.Empty;
    public string? BaseType { get; set; }
    public List<string> DerivedTypes { get; set; } = new();
    public List<string> Interfaces { get; set; } = new();
}

public class SensitiveApiHit
{
    public string Category { get; set; } = string.Empty; // Crypto, Network, FileIO, Reflection, Process, Registry
    public string ApiCall { get; set; } = string.Empty;
    public string CallingMethod { get; set; } = string.Empty;
    public string CallingType { get; set; } = string.Empty;
    public uint IL_Offset { get; set; }
    public string Severity { get; set; } = "Info"; // Info, Warning, Critical
}

public class AnalysisTiming
{
    public long LoadMs { get; set; }
    public long DecompileMs { get; set; }
    public long ScanMs { get; set; }
    public long TotalMs { get; set; }
}

// ========== Error Response ==========

public class ErrorResponse
{
    public string Error { get; set; } = string.Empty;
    public string? Detail { get; set; }
}
