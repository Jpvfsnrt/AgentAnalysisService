# dnSpy Agent Analysis Service

**Headless .NET Assembly Analysis API for AI Agents**

基于 dnSpy 内核的无 GUI 分析服务，提供 RESTful HTTP API，使 AI Agent 可以通过网络调用直接分析 .NET DLL/EXE 文件。

## 快速启动

```powershell
# 进入项目目录
cd AgentAnalysisService

# 编译并运行（开发模式）
dotnet run

# 或发布为独立可执行文件
dotnet publish -c Release -o ./publish
./publish/AgentAnalysisService.exe

# 自定义端口
dotnet run --urls "http://0.0.0.0:5099"
```

启动后访问 `http://localhost:5099` 查看 API 文档页。

## API 接口

### `POST /api/analyze` — 完整程序集分析

一次性完成：元数据提取 → IL 反汇编 → 依赖图 → 敏感 API 扫描

```json
// Request
{
  "path": "C:/target/TargetAssembly.dll",
  "includeIL": true,
  "scanSensitive": true,
  "includeDependencies": true,
  "decompileAll": false,
  "typeFilter": null
}

// Response (结构见下方)
```

响应体包含完整的结构化 JSON：

```jsonc
{
  "filePath": "C:/target/TargetAssembly.dll",
  "fileName": "TargetAssembly.dll",
  "fileHash": "a1b2c3...",
  "assembly": {
    "name": "TargetAssembly",
    "version": "1.0.0.0",
    "targetRuntime": "v4.0.30319",
    "isExe": false,
    "architecture": "AnyCPU"
  },
  "types": [
    {
      "fullName": "TargetAssembly.Services.CryptoHelper",
      "kind": "class",
      "visibility": "public",
      "baseType": "System.Object",
      "methods": [
        {
          "name": "Encrypt",
          "visibility": "public",
          "isStatic": true,
          "returnType": "System.Byte[]",
          "parameters": [
            { "name": "data", "type": "System.Byte[]", "index": 0 },
            { "name": "key", "type": "System.String", "index": 1 }
          ],
          "hasBody": true,
          "ilCodeSize": 245,
          "maxStack": 4,
          "ilInstructions": [
            { "offset": 0, "opCode": "ldarg.0", "operand": null },
            { "offset": 1, "opCode": "ldarg.1", "operand": null },
            { "offset": 2, "opCode": "call", "operand": "System.Text.Encoding::get_UTF8()" }
          ],
          "calledMethods": [
            "System.Text.Encoding.get_UTF8",
            "System.Security.Cryptography.Aes.Create"
          ],
          "customAttributes": []
        }
      ],
      "fields": [...],
      "properties": [...]
    }
  ],
  "entryPoints": ["TargetAssembly.Program.Main"],
  "references": [
    { "name": "mscorlib", "version": "4.0.0.0" },
    { "name": "System.Security.Cryptography", "version": "4.0.0.0" }
  ],
  "sensitiveApis": [
    {
      "category": "Crypto",
      "apiCall": "System.Security.Cryptography.Aes.Create",
      "callingMethod": "TargetAssembly.Services.CryptoHelper.Encrypt",
      "callingType": "TargetAssembly.Services.CryptoHelper",
      "il_Offset": 4,
      "severity": "Critical"
    }
  ],
  "dependencies": {
    "assemblyDependencies": [{ "assembly": "TargetAssembly", "referencedAssemblies": [...] }],
    "inheritanceTree": [{ "type": "...", "baseType": "...", "derivedTypes": [...], "interfaces": [...] }]
  },
  "timing": { "loadMs": 45, "scanMs": 12, "totalMs": 257 }
}
```

### `POST /api/analyze/upload` — 上传 DLL 文件分析

```bash
curl -F "file=@target.dll" http://localhost:5099/api/analyze/upload
```

### `POST /api/decompile` — 指定类型/方法反编译为 C#

```json
// Request
{
  "path": "C:/target/TargetAssembly.dll",
  "typeName": "CryptoHelper",
  "memberName": "Encrypt"
}

// Response
{
  "filePath": "...",
  "typeName": "CryptoHelper",
  "memberName": "Encrypt",
  "code": "public byte[] Encrypt(byte[] data, string key)\n{\n    using var aes = Aes.Create();\n    ...\n}"
}
```

### `POST /api/scan/sensitive` — 快速安全扫描

只扫描敏感 API 调用，不提取完整 IL。速度比 `/api/analyze` 快 3-5 倍。

```json
// Request
{ "path": "C:/target/TargetAssembly.dll" }

// Response
{ "filePath": "...", "sensitiveApis": [...] }
```

### `POST /api/dependencies` — 依赖关系分析

只分析程序集引用和类型继承。

### `GET /api/types/{fileHash}` — 查询缓存分析的类型列表

### `DELETE /api/cache` — 清空分析缓存

## Agent 调用示例

### Python Agent

```python
import requests

def analyze_dll(path: str) -> dict:
    """Full analysis of a .NET assembly."""
    resp = requests.post("http://localhost:5099/api/analyze", json={
        "path": path,
        "includeIL": True,
        "scanSensitive": True,
        "includeDependencies": True
    })
    return resp.json()

def decompile_member(path: str, type_name: str, member: str) -> str:
    """Decompile a specific type/member."""
    resp = requests.post("http://localhost:5099/api/decompile", json={
        "path": path,
        "typeName": type_name,
        "memberName": member
    })
    return resp.json()["code"]

# 使用
result = analyze_dll("malware_sample.dll")
for hit in result["sensitiveApis"]:
    if hit["severity"] == "Critical":
        print(f"CRITICAL: {hit['apiCall']} in {hit['callingMethod']}")
        code = decompile_member("malware_sample.dll", hit["callingType"], None)
        print(code)
```

### Node.js Agent

```javascript
async function analyze(path) {
  const resp = await fetch('http://localhost:5099/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, includeIL: true, scanSensitive: true, includeDependencies: true })
  });
  return resp.json();
}

async function scanOnly(path) {
  const resp = await fetch('http://localhost:5099/api/scan/sensitive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path })
  });
  return resp.json();
}
```

### 终端直调

```bash
# 完整分析
curl -X POST http://localhost:5099/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"path":"C:/malware.dll","includeIL":true,"scanSensitive":true,"includeDependencies":true}' | jq .

# 只做安全扫描
curl -X POST http://localhost:5099/api/scan/sensitive \
  -H "Content-Type: application/json" \
  -d '{"path":"C:/malware.dll"}' | jq '.sensitiveApis[] | select(.severity=="Critical")'

# 反编译特定类型
curl -X POST http://localhost:5099/api/decompile \
  -H "Content-Type: application/json" \
  -d '{"path":"C:/malware.dll","typeName":"EvilClass"}'
```

## 配置

编辑 `appsettings.json`：

```jsonc
{
  "AnalysisService": {
    "MaxFileSizeMB": 200,           // 最大文件大小
    "MaxConcurrentAnalyses": 4,     // 最大并发分析数
    "CacheExpirationMinutes": 30,   // 缓存过期时间
    "AllowedExtensions": [".dll", ".exe", ".netmodule", ".winmd"]
  }
}
```

## 架构

```
                     AI Agent (任意语言)
                           │
                      HTTP REST API
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         /api/analyze  /api/decompile  /api/scan
              │            │            │
              └────────────┼────────────┘
                           ▼
                 AssemblyAnalyzer
              ┌────────┬───┴───┬────────┐
              ▼        ▼       ▼        ▼
           dnlib   ILSpy   Sensitive  Dependency
         (元数据) (反编译)   Scanner   Analyzer
```

## 依赖

| 库 | 版本 | 用途 |
|---|---|---|
| **dnlib** | 3.6.0 | PE/CLI 解析，元数据读写，IL 反汇编 |
| **ICSharpCode.Decompiler** | 8.2.0 | IL → C# 反编译引擎 |
| ASP.NET Core | 8.0 | HTTP 服务框架 |

## 敏感 API 扫描规则

覆盖 **12 大类、50+ 条规则**：

| 类别 | 示例检测 |
|---|---|
| 🔐 **Crypto** | AES, DES, RC2, MD5, Rijndael, Base64 |
| 🌐 **Network** | WebClient, HttpClient, TcpClient, Socket, Dns |
| 📁 **FileIO** | File.Read/Write/Delete, FileStream, Directory |
| 🔍 **Reflection** | Assembly.Load, MethodInfo.Invoke, IL Emit |
| ⚙️ **Process** | Process.Start, Process.Kill |
| 📝 **Registry** | RegistryKey.SetValue |
| 🔗 **Interop** | DllImport, Marshal, IntPtr |
| 🧵 **Threading** | Thread.Start, Mutex, Task.Run |
| 📦 **Serialization** | BinaryFormatter, XmlSerializer, JsonSerializer |
| 📎 **Compression** | GZip, Deflate, ZipFile |
| 💻 **System** | Environment vars, SystemEvents |

每条规则带有 `Critical` / `Warning` / `Info` 严重级别标注。
