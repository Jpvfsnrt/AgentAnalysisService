using dnlib.DotNet;
using dnlib.DotNet.Emit;
using AgentAnalysisService.Models;

namespace AgentAnalysisService.Services;

/// <summary>
/// Scans for potentially sensitive API calls in method bodies.
/// Categories: Crypto, Network, FileIO, Reflection, Process, Registry, Interop, etc.
/// </summary>
public class SensitiveApiScanner
{
    // Patterns: (Category, Severity, Full method/type name pattern)
    private static readonly (string Category, string Severity, string Pattern, string Description)[] _patterns =
    {
        // Crypto
        ("Crypto", "Critical", "System.Security.Cryptography.Aes", "AES encryption"),
        ("Crypto", "Critical", "System.Security.Cryptography.DES", "DES encryption (weak)"),
        ("Crypto", "Critical", "System.Security.Cryptography.RC2", "RC2 encryption (weak)"),
        ("Crypto", "Warning", "System.Security.Cryptography.MD5", "MD5 hash (deprecated)"),
        ("Crypto", "Critical", "System.Security.Cryptography.RijndaelManaged", "Rijndael encryption"),
        ("Crypto", "Critical", "System.Security.Cryptography.TripleDES", "TripleDES encryption"),
        ("Crypto", "Warning", "System.Security.Cryptography.RNGCryptoServiceProvider", "Random number generation"),
        ("Crypto", "Info", "System.Security.Cryptography.SHA", "SHA hashing"),
        ("Crypto", "Info", "System.Security.Cryptography.HMAC", "HMAC authentication"),
        ("Crypto", "Warning", "System.Convert.FromBase64String", "Base64 decoding (payload?)"),
        ("Crypto", "Warning", "System.Convert.ToBase64String", "Base64 encoding"),

        // Network
        ("Network", "Warning", "System.Net.WebClient", "WebClient (download/upload)"),
        ("Network", "Warning", "System.Net.Http.HttpClient", "HTTP client"),
        ("Network", "Warning", "System.Net.WebRequest", "Web request"),
        ("Network", "Critical", "System.Net.Sockets.TcpClient", "TCP socket"),
        ("Network", "Critical", "System.Net.Sockets.UdpClient", "UDP socket"),
        ("Network", "Critical", "System.Net.Sockets.Socket", "Raw socket"),
        ("Network", "Warning", "System.Net.Dns.GetHost", "DNS resolution"),
        ("Network", "Warning", "System.Net.NetworkInformation.Ping", "Ping / network probe"),
        ("Network", "Critical", "System.Net.HttpListener", "HTTP listener (server)"),
        ("Network", "Warning", "System.Net.FtpWebRequest", "FTP request"),

        // File/IO
        ("FileIO", "Warning", "System.IO.File.Read", "File read"),
        ("FileIO", "Warning", "System.IO.File.Write", "File write"),
        ("FileIO", "Critical", "System.IO.File.Delete", "File deletion"),
        ("FileIO", "Warning", "System.IO.File.Copy", "File copy"),
        ("FileIO", "Warning", "System.IO.File.Move", "File move"),
        ("FileIO", "Warning", "System.IO.FileStream", "File stream"),
        ("FileIO", "Critical", "System.IO.Directory.Delete", "Directory deletion"),
        ("FileIO", "Info", "System.IO.Directory.GetFiles", "Directory enumeration"),
        ("FileIO", "Info", "System.IO.Path.GetTempFileName", "Temp file creation"),
        ("FileIO", "Warning", "System.IO.FileSystemWatcher", "File system watcher"),

        // Reflection / Dynamic
        ("Reflection", "Critical", "System.Reflection.Assembly.Load", "Dynamic assembly load"),
        ("Reflection", "Warning", "System.Reflection.MethodInfo.Invoke", "Method invocation via reflection"),
        ("Reflection", "Warning", "System.Type.InvokeMember", "Member invocation via reflection"),
        ("Reflection", "Warning", "System.Activator.CreateInstance", "Dynamic type instantiation"),
        ("Reflection", "Critical", "System.Reflection.Emit", "IL emit (dynamic code gen)"),
        ("Reflection", "Warning", "System.Type.GetType", "Dynamic type resolution"),

        // Process
        ("Process", "Critical", "System.Diagnostics.Process.Start", "Process creation"),
        ("Process", "Warning", "System.Diagnostics.Process.Kill", "Process termination"),
        ("Process", "Warning", "System.Diagnostics.Process.GetProcesses", "Process enumeration"),
        ("Process", "Info", "System.Diagnostics.Process.GetCurrentProcess", "Current process info"),

        // Registry (Windows)
        ("Registry", "Warning", "Microsoft.Win32.Registry", "Registry access"),
        ("Registry", "Critical", "Microsoft.Win32.RegistryKey.SetValue", "Registry write"),

        // Interop / PInvoke
        ("Interop", "Critical", "System.Runtime.InteropServices.DllImportAttribute", "P/Invoke (native call)"),
        ("Interop", "Warning", "System.Runtime.InteropServices.Marshal", "Marshaling (unsafe)"),
        ("Interop", "Critical", "System.IntPtr", "Raw pointer usage"),

        // Threading / Synchronization
        ("Threading", "Warning", "System.Threading.Thread.Start", "Thread creation"),
        ("Threading", "Warning", "System.Threading.ThreadPool", "Thread pool usage"),
        ("Threading", "Info", "System.Threading.Mutex", "Mutex (named?)"),
        ("Threading", "Info", "System.Threading.Semaphore", "Semaphore"),
        ("Threading", "Warning", "System.Threading.Tasks.Task.Run", "Task spawning"),

        // Serialization
        ("Serialization", "Critical", "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "BinaryFormatter (vulnerable)"),
        ("Serialization", "Warning", "System.Xml.Serialization.XmlSerializer", "XML deserialization"),
        ("Serialization", "Warning", "Newtonsoft.Json", "JSON serialization"),
        ("Serialization", "Warning", "System.Text.Json.JsonSerializer.Deserialize", "System.Text.Json deserialization"),

        // Compression
        ("Compression", "Info", "System.IO.Compression.GZipStream", "GZip compression"),
        ("Compression", "Info", "System.IO.Compression.DeflateStream", "Deflate compression"),
        ("Compression", "Info", "System.IO.Compression.ZipFile", "ZIP file operations"),

        // System manipulation
        ("System", "Critical", "Microsoft.Win32.SystemEvents", "System event hook"),
        ("System", "Warning", "System.Environment.SetEnvironmentVariable", "Environment variable set"),
        ("System", "Warning", "System.Environment.GetEnvironmentVariable", "Environment variable read"),
        ("System", "Warning", "System.Environment.CommandLine", "Command line access"),
    };

    /// <summary>
    /// Scan the assembly for sensitive API calls and return hits.
    /// </summary>
    public List<SensitiveApiHit> Scan(ModuleDefMD module, List<TypeInfo> typeInfos)
    {
        var hits = new List<SensitiveApiHit>();

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;

                foreach (var instr in method.Body.Instructions)
                {
                    if (instr.OpCode.Code != Code.Call &&
                        instr.OpCode.Code != Code.Callvirt &&
                        instr.OpCode.Code != Code.Newobj)
                        continue;

                    var operand = instr.Operand;
                    string? calledMethod = null;

                    if (operand is IMethod imethod)
                        calledMethod = imethod.FullName;
                    else if (operand is IMethodDefOrRef methodRef)
                        calledMethod = methodRef.DeclaringType?.FullName + "." + methodRef.Name;

                    if (calledMethod == null) continue;

                    foreach (var pattern in _patterns)
                    {
                        if (calledMethod.StartsWith(pattern.Pattern, StringComparison.Ordinal))
                        {
                            hits.Add(new SensitiveApiHit
                            {
                                Category = pattern.Category,
                                ApiCall = calledMethod,
                                CallingMethod = method.FullName,
                                CallingType = type.FullName,
                                IL_Offset = instr.Offset,
                                Severity = pattern.Severity
                            });
                            break; // Only match first pattern per instruction
                        }
                    }
                }
            }
        }

        // Sort by severity then category
        return hits
            .OrderByDescending(h => h.Severity switch
            {
                "Critical" => 3,
                "Warning" => 2,
                "Info" => 1,
                _ => 0
            })
            .ThenBy(h => h.Category)
            .ToList();
    }
}
