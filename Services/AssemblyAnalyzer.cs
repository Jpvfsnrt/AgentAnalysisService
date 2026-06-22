using System.Diagnostics;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using AgentAnalysisService.Models;

namespace AgentAnalysisService.Services;

/// <summary>
/// Core assembly analysis engine using dnlib.
/// Loads and extracts all metadata from .NET assemblies without executing them.
/// </summary>
public class AssemblyAnalyzer
{
    private readonly ILogger<AssemblyAnalyzer> _logger;

    public AssemblyAnalyzer(ILogger<AssemblyAnalyzer> logger)
    {
        _logger = logger;
    }

    public AnalysisResponse Analyze(string filePath, AnalyzeRequest request)
    {
        var sw = Stopwatch.StartNew();
        var timing = new AnalysisTiming();

        ValidateFile(filePath);

        var loadSw = Stopwatch.StartNew();
        using var module = ModuleDefMD.Load(filePath, new ModuleCreationOptions());
        timing.LoadMs = loadSw.ElapsedMilliseconds;

        var response = new AnalysisResponse
        {
            FilePath = filePath,
            FileName = Path.GetFileName(filePath),
            FileSize = new FileInfo(filePath).Length,
            FileHash = ComputeHash(filePath)
        };

        response.Assembly = ExtractAssemblyInfo(module);
        response.Modules.Add(ExtractModuleInfo(module));

        if (request.IncludeDependencies)
            response.References = ExtractReferences(module);

        var allTypes = module.GetTypes();
        var typeInfos = new List<TypeInfo>();

        foreach (var type in allTypes)
        {
            if (IsCompilerGenerated(type)) continue;

            if (!string.IsNullOrEmpty(request.TypeFilter) &&
                !type.FullName.Contains(request.TypeFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            typeInfos.Add(ExtractTypeInfo(type, request));
        }

        response.Types = typeInfos;
        response.EntryPoints = FindEntryPoints(module);

        if (request.IncludeDependencies)
        {
            var depSw = Stopwatch.StartNew();
            response.Dependencies = new DependencyAnalyzer().Analyze(module, response.Types);
            timing.ScanMs = depSw.ElapsedMilliseconds;
        }

        if (request.ScanSensitive)
        {
            var scanSw = Stopwatch.StartNew();
            response.SensitiveApis = new SensitiveApiScanner().Scan(module, response.Types);
            timing.ScanMs += scanSw.ElapsedMilliseconds;
        }

        timing.TotalMs = sw.ElapsedMilliseconds;
        response.Timing = timing;
        return response;
    }

    public string Decompile(string filePath, string? typeName, string? memberName)
    {
        ValidateFile(filePath);
        using var module = ModuleDefMD.Load(filePath, new ModuleCreationOptions());
        var decompiler = new CSharpDecompilerWrapper(_logger);
        return decompiler.DecompileMember(module, typeName, memberName);
    }

    // ─── Validation ────────────────────────────────────────────────

    private static void ValidateFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path is required.");

        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File not found: {filePath}");

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext != ".dll" && ext != ".exe" && ext != ".netmodule" && ext != ".winmd")
            throw new ArgumentException($"Unsupported file extension: {ext}");

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > 200 * 1024 * 1024)
            throw new ArgumentException($"File too large: {fileInfo.Length} bytes. Max 200 MB.");
    }

    private static string ComputeHash(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    // ─── Assembly / Module info ────────────────────────────────────

    private static AssemblyInfo ExtractAssemblyInfo(ModuleDefMD module)
    {
        var asm = module.Assembly;
        var info = new AssemblyInfo();

        if (asm != null)
        {
            info.Name = asm.Name;
            info.FullName = asm.FullName;
            info.Version = asm.Version?.ToString();
            info.Culture = asm.Culture;
            info.PublicKeyToken = asm.PublicKeyToken?.ToString();
            info.CustomAttributes = ExtractCustomAttributes(asm);
        }

        info.TargetRuntime = module.RuntimeVersion;
        info.IsExe = module.Kind != ModuleKind.Dll;
        info.IsDll = module.Kind == ModuleKind.Dll;
        info.Architecture = GetArchitecture(module);
        return info;
    }

    private static ModuleInfo ExtractModuleInfo(ModuleDefMD module)
    {
        var types = module.GetTypes();
        return new ModuleInfo
        {
            Name = module.Name,
            FullyQualifiedName = module.Location,
            TypeCount = types.Count(),
            MethodCount = types.Sum(t => t.Methods.Count()),
            Mvid = module.Mvid ?? Guid.Empty
        };
    }

    private static List<AssemblyReferenceInfo> ExtractReferences(ModuleDefMD module)
    {
        return module.GetAssemblyRefs().Select(asmRef => new AssemblyReferenceInfo
        {
            Name = asmRef.Name,
            Version = asmRef.Version?.ToString(),
            PublicKeyToken = asmRef.PublicKeyOrToken?.Token?.ToString(),
            Culture = asmRef.Culture,
            IsNetCoreAssembly = IsNetCoreAssembly(asmRef)
        }).ToList();
    }

    // ─── Type info ─────────────────────────────────────────────────

    private static TypeInfo ExtractTypeInfo(TypeDef type, AnalyzeRequest request)
    {
        var info = new TypeInfo
        {
            Name = type.Name,
            FullName = type.FullName,
            Namespace = type.Namespace,
            Kind = GetTypeKind(type),
            Visibility = GetVisibility(type),
            IsSealed = type.IsSealed,
            IsAbstract = type.IsAbstract,
            IsStatic = type.IsAbstract && type.IsSealed,
            IsNested = type.IsNested,
            BaseType = type.BaseType?.FullName,
            CustomAttributes = ExtractCustomAttributeNames(type),
            Interfaces = type.Interfaces.Select(i => i.Interface.FullName).ToList(),
            NestedTypes = type.NestedTypes.Select(n => n.FullName).ToList()
        };

        foreach (var field in type.Fields)
            info.Fields.Add(ExtractFieldInfo(field));

        foreach (var method in type.Methods)
            info.Methods.Add(ExtractMethodInfo(method, request));

        foreach (var prop in type.Properties)
            info.Properties.Add(ExtractPropertyInfo(prop));

        foreach (var evt in type.Events)
            info.Events.Add(ExtractEventInfo(evt));

        return info;
    }

    // ─── Method info ───────────────────────────────────────────────

    private static MethodInfo ExtractMethodInfo(MethodDef method, AnalyzeRequest request)
    {
        var info = new MethodInfo
        {
            Name = method.Name,
            FullName = method.FullName,
            Visibility = GetVisibility(method),
            IsStatic = method.IsStatic,
            IsVirtual = method.IsVirtual,
            IsConstructor = method.IsConstructor,
            IsGetter = method.IsGetter,
            IsSetter = method.IsSetter,
            ReturnType = method.ReturnType.FullName,
            HasBody = method.HasBody,
            CustomAttributes = ExtractCustomAttributeNames(method),
            Parameters = method.Parameters.Select(p => new ParameterInfo
            {
                Name = p.Name,
                Type = p.Type.FullName,
                Index = (int)p.Index,
                IsHidden = p.IsHiddenThisParameter
            }).ToList()
        };

        if (method.HasBody && request.IncludeIL)
        {
            var body = method.Body;
            info.ILCodeSize = body.Instructions.Count;
            info.MaxStack = body.MaxStack;

            info.ILInstructions = body.Instructions.Select(instr => new InstructionInfo
            {
                Offset = instr.Offset,
                OpCode = instr.OpCode.Name,
                Operand = FormatOperand(instr.Operand),
                Comment = GetComment(instr)
            }).ToList();

            if (body.HasExceptionHandlers)
            {
                info.ExceptionClauses = body.ExceptionHandlers.Select(eh => new ExceptionClauseInfo
                {
                    Kind = eh.HandlerType.ToString(),
                    TryStart = eh.TryStart.Offset,
                    TryEnd = eh.TryEnd.Offset,
                    HandlerStart = eh.HandlerStart.Offset,
                    HandlerEnd = eh.HandlerEnd.Offset,
                    CatchType = eh.CatchType?.FullName,
                    FilterStart = eh.FilterStart?.Offset
                }).ToList();
            }

            info.CalledMethods = ExtractCalledMethods(body);
        }

        return info;
    }

    // ─── Field / Property / Event ──────────────────────────────────

    private static FieldInfo ExtractFieldInfo(FieldDef field)
    {
        return new FieldInfo
        {
            Name = field.Name,
            Type = field.FieldType.FullName,
            Visibility = GetVisibility(field),
            IsStatic = field.IsStatic,
            IsLiteral = field.IsLiteral,
            IsInitOnly = field.IsInitOnly,
            ConstantValue = field.Constant?.Value?.ToString(),
            FieldOffset = field.FieldOffset?.ToString(),
            CustomAttributes = ExtractCustomAttributeNames(field)
        };
    }

    private static PropertyInfo ExtractPropertyInfo(PropertyDef prop)
    {
        return new PropertyInfo
        {
            Name = prop.Name,
            Type = prop.PropertySig?.ToString() ?? "unknown",
            GetMethod = prop.GetMethod?.Name,
            SetMethod = prop.SetMethod?.Name,
            CustomAttributes = ExtractCustomAttributeNames(prop)
        };
    }

    private static EventInfo ExtractEventInfo(EventDef evt)
    {
        return new EventInfo
        {
            Name = evt.Name,
            Type = evt.EventType?.FullName ?? "unknown",
            AddMethod = evt.AddMethod?.Name,
            RemoveMethod = evt.RemoveMethod?.Name,
            InvokeMethod = evt.InvokeMethod?.Name
        };
    }

    // ─── Entry Points ──────────────────────────────────────────────

    private static List<string> FindEntryPoints(ModuleDefMD module)
    {
        var entries = new List<string>();

        if (module.ManagedEntryPoint is MethodDef epMethod)
            entries.Add(epMethod.FullName);

        if (module.NativeEntryPoint != 0)
            entries.Add($"[Native] AddressOfEntryPoint: 0x{module.NativeEntryPoint:X}");

        return entries;
    }

    // ─── IL formatting ─────────────────────────────────────────────

    private static string? FormatOperand(object? operand)
    {
        return operand switch
        {
            null => null,
            string s => $"\"{s}\"",
            TypeDef t => t.FullName,
            TypeRef tr => tr.FullName,
            MethodDef m => m.FullName,
            MemberRef mr => mr.FullName,
            FieldDef f => f.FullName,
            _ => operand.ToString()
        };
    }

    private static string? GetComment(Instruction instr)
    {
        return instr.OpCode.Code switch
        {
            Code.Ldc_I8 => instr.Operand is long l ? $"// {l}" : null,
            _ => null
        };
    }

    private static List<string> ExtractCalledMethods(CilBody body)
    {
        var calls = new HashSet<string>();
        foreach (var instr in body.Instructions)
        {
            if (instr.OpCode.Code == Code.Call ||
                instr.OpCode.Code == Code.Callvirt ||
                instr.OpCode.Code == Code.Newobj)
            {
                if (instr.Operand is IMethod method)
                    calls.Add(method.FullName);
                else if (instr.Operand is IMethodDefOrRef methodRef)
                    calls.Add(methodRef.FullName);
            }
        }
        return calls.ToList();
    }

    // ─── Visibility helpers ────────────────────────────────────────

    private static string GetVisibility(MethodDef m) => m.Access switch
    {
        MethodAttributes.Public => "public",
        MethodAttributes.Family => "protected",
        MethodAttributes.FamORAssem => "protected internal",
        MethodAttributes.Assembly => "internal",
        MethodAttributes.FamANDAssem => "private protected",
        MethodAttributes.Private => "private",
        _ => "internal"
    };

    private static string GetVisibility(FieldDef f) => f.Access switch
    {
        FieldAttributes.Public => "public",
        FieldAttributes.Family => "protected",
        FieldAttributes.FamORAssem => "protected internal",
        FieldAttributes.Assembly => "internal",
        FieldAttributes.FamANDAssem => "private protected",
        FieldAttributes.Private => "private",
        _ => "internal"
    };

    private static string GetVisibility(TypeDef t)
    {
        if (t.IsPublic || t.IsNestedPublic) return "public";
        if (t.IsNestedFamily) return "protected";
        if (t.IsNestedFamilyOrAssembly) return "protected internal";
        if (t.IsNestedAssembly || t.IsNotPublic) return "internal";
        if (t.IsNestedFamilyAndAssembly) return "private protected";
        if (t.IsNestedPrivate) return "private";
        return "internal";
    }

    // ─── Type classification ───────────────────────────────────────

    private static string GetTypeKind(TypeDef t)
    {
        if (t.IsEnum) return "enum";
        if (t.IsInterface) return "interface";
        if (t.IsValueType) return "struct";
        if (t.BaseType?.FullName == "System.MulticastDelegate") return "delegate";
        if (t.IsAbstract && t.IsSealed) return "static class";
        if (t.IsAbstract) return "abstract class";
        if (t.IsSealed) return "sealed class";
        return "class";
    }

    private static bool IsCompilerGenerated(TypeDef type)
    {
        return type.Name.StartsWith("<") ||
               type.Name.Contains("__") ||
               type.CustomAttributes.Any(a =>
                   a.AttributeType?.FullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute");
    }

    private static bool IsNetCoreAssembly(AssemblyRef asmRef)
    {
        return asmRef.Name == "netstandard" ||
               asmRef.Name == "System.Runtime" ||
               asmRef.Name.StartsWith("System.Private");
    }

    private static string? GetArchitecture(ModuleDefMD module)
    {
        return module.Metadata?.PEImage?.ImageNTHeaders?.FileHeader?.Machine switch
        {
            Machine.I386 => "x86",
            Machine.AMD64 => "x64",
            Machine.IA64 => "IA-64",
            Machine.ARM64 => "ARM64",
            Machine.ARMNT => "ARM",
            _ => "AnyCPU"
        };
    }

    // ─── Custom Attributes ─────────────────────────────────────────

    private static Dictionary<string, string> ExtractCustomAttributes(IHasCustomAttribute obj)
    {
        var attrs = new Dictionary<string, string>();
        foreach (var attr in obj.CustomAttributes)
        {
            var typeName = attr.AttributeType?.FullName ?? "unknown";
            var value = FormatAttributeValue(attr);
            attrs[typeName] = value;
        }
        return attrs;
    }

    private static List<string> ExtractCustomAttributeNames(IHasCustomAttribute obj)
    {
        return obj.CustomAttributes
            .Select(a => a.AttributeType?.FullName ?? "unknown")
            .ToList();
    }

    private static string FormatAttributeValue(CustomAttribute attr)
    {
        if (attr.ConstructorArguments.Count == 0)
            return "(default)";

        var args = string.Join(", ", attr.ConstructorArguments.Select(a => a.Value?.ToString() ?? "null"));
        if (attr.NamedArguments.Count > 0)
        {
            var named = string.Join(", ", attr.NamedArguments.Select(n => $"{n.Name}={n.Argument.Value}"));
            args += $", [{named}]";
        }
        return args;
    }
}
