using dnlib.DotNet;
using AgentAnalysisService.Models;

namespace AgentAnalysisService.Services;

/// <summary>
/// Analyzes assembly dependencies, type inheritance chains, and method call graphs.
/// </summary>
public class DependencyAnalyzer
{
    /// <summary>
    /// Build a dependency graph from the assembly.
    /// </summary>
    public DependencyGraph Analyze(ModuleDefMD module, List<TypeInfo> typeInfos)
    {
        var graph = new DependencyGraph();

        // Assembly-level dependencies
        var asmNode = new AssemblyDependencyNode
        {
            Assembly = module.Assembly?.Name ?? module.Name,
            ReferencedAssemblies = module.GetAssemblyRefs()
                .Select(r => r.Name.String)
                .Distinct()
                .ToList()
        };
        graph.AssemblyDependencies.Add(asmNode);

        // Type inheritance tree
        var allTypes = module.GetTypes().ToList();
        var typeDict = allTypes.ToDictionary(t => t.FullName, t => t);

        foreach (var type in allTypes)
        {
            // Skip compiler-generated
            if (type.Name.StartsWith("<")) continue;

            var node = new TypeInheritanceNode
            {
                Type = type.FullName,
                BaseType = type.BaseType?.FullName,
                Interfaces = type.Interfaces.Select(i => i.Interface.FullName).ToList()
            };

            // Find derived types (types in same module that inherit from this one)
            foreach (var other in allTypes)
            {
                if (other.BaseType?.FullName == type.FullName)
                {
                    node.DerivedTypes.Add(other.FullName);
                }
            }

            graph.InheritanceTree.Add(node);
        }

        return graph;
    }
}
