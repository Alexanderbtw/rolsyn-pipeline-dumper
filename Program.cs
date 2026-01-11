using System.Reflection;
using System.Reflection.Emit;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

string sourcePath = Path.Combine(AppContext.BaseDirectory, "input.txt");
string source = File.Exists(sourcePath)
    ? File.ReadAllText(sourcePath)
    : """
      using System;
      internal static class Program
      {
          public static void Main()
          {
              int a = 0;
              int sum = a + 42;
              Console.WriteLine(sum);
          }
      }
      """;

DumpStage("Source Text", () => PrintSourceWithLineNumbers(source));

var parseOptions = new CSharpParseOptions(LanguageVersion.Preview, kind: SourceCodeKind.Regular);
SyntaxTree tree = CSharpSyntaxTree.ParseText(source, parseOptions);

Console.WriteLine("AST:");
PrintTree(tree.GetRoot());

DumpStage("Lexing (Tokens)", () => PrintTokens(tree));
DumpStage("Parse Diagnostics", () => PrintDiagnostics(tree.GetDiagnostics()));

CSharpCompilation compilation = CreateCompilation(tree);
DumpStage("Compilation Diagnostics", () => PrintDiagnostics(compilation.GetDiagnostics()));

SemanticModel model = compilation.GetSemanticModel(tree);

DumpStage(
    "Semantic Analysis",
    () =>
    {
        PrintBinaryExpressionSemantics(model, tree.GetRoot());
        PrintDeclaredSymbols(model, tree.GetRoot());
    });

DumpStage("IOperation Tree", () => PrintOperations(model, tree.GetRoot()));

DumpStage(
    "Control Flow Graph",
    () =>
    {
        if (!TryPrintFirstControlFlowGraph(compilation, tree.GetRoot(), out string reason))
            Console.WriteLine($"(skipped) {reason}");
    });

DumpStage("Emit + IL", () => EmitAndDisassemble(compilation));

static void PrintTree(SyntaxNode root)
{
    PrintNodeOrToken(root, "", true);
}

static void PrintNodeOrToken(SyntaxNodeOrToken nodeOrToken, string indent, bool isLast)
{
    string branch = isLast ? "└─" : "├─";
    Console.Write(indent);
    Console.Write(branch);

    if (nodeOrToken.IsNode)
    {
        SyntaxNode node = nodeOrToken.AsNode()!;
        Console.WriteLine(node.Kind());
    }
    else
    {
        SyntaxToken token = nodeOrToken.AsToken();
        string text = token.Text;
        Console.WriteLine($"{token.Kind()} {Escape(text)}");
    }

    string childIndent = indent + (isLast ? "  " : "│ ");
    ChildSyntaxList children = nodeOrToken.ChildNodesAndTokens();
    for (var i = 0; i < children.Count; i++)
    {
        PrintNodeOrToken(children[i], childIndent, i == children.Count - 1);
    }
}

static string Escape(string text)
{
    return $"\"{text.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";
}

static void DumpStage(string title, Action action)
{
    Console.WriteLine();
    Console.WriteLine(new string('=', title.Length + 4));
    Console.WriteLine($"= {title} =");
    Console.WriteLine(new string('=', title.Length + 4));
    action();
}

static void PrintSourceWithLineNumbers(string source)
{
    string[] lines = source.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
    for (var i = 0; i < lines.Length; i++)
        Console.WriteLine($"{i + 1,4}: {lines[i]}");
}

static void PrintDiagnostics(IEnumerable<Diagnostic> diagnostics)
{
    var any = false;
    foreach (Diagnostic diagnostic in diagnostics)
    {
        any = true;
        string where = diagnostic.Location.IsInSource
            ? diagnostic.Location.GetLineSpan().ToString()
            : "<no-source>";
        Console.WriteLine($"{diagnostic.Severity}: {diagnostic.Id} {where} {diagnostic.GetMessage()}");
    }

    if (!any)
        Console.WriteLine("(none)");
}

static CSharpCompilation CreateCompilation(SyntaxTree tree)
{
    IReadOnlyList<MetadataReference> references = GetTrustedPlatformAssemblyReferences();
    return CSharpCompilation.Create(
        "Temp",
        new[] { tree },
        references,
        new CSharpCompilationOptions(
                OutputKind.ConsoleApplication,
                optimizationLevel: OptimizationLevel.Debug)
            .WithUsings("System"));
}

static IReadOnlyList<MetadataReference> GetTrustedPlatformAssemblyReferences()
{
    var tpa = (string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES");
    if (string.IsNullOrWhiteSpace(tpa))
        return new[] { MetadataReference.CreateFromFile(typeof(object).Assembly.Location) };

    IEnumerable<string> paths = tpa.Split(Path.PathSeparator).Distinct(StringComparer.OrdinalIgnoreCase);
    return paths.Select(p => MetadataReference.CreateFromFile(p)).ToArray();
}

static void PrintDeclaredSymbols(SemanticModel model, SyntaxNode root)
{
    VariableDeclaratorSyntax[] declarators =
        root.DescendantNodes().OfType<VariableDeclaratorSyntax>().ToArray();
    if (declarators.Length == 0)
        return;

    Console.WriteLine();
    Console.WriteLine("Declared symbols:");
    foreach (VariableDeclaratorSyntax declarator in declarators)
    {
        if (model.GetDeclaredSymbol(declarator) is not ILocalSymbol symbol)
            continue;

        LinePosition? location = symbol.Locations.FirstOrDefault(l => l.IsInSource)?.GetLineSpan()
            .StartLinePosition;
        string at = location is null ? "" : $" @ L{location.Value.Line + 1}:{location.Value.Character + 1}";
        Console.WriteLine($"- {symbol.Name}: {FormatSymbol(symbol.Type)}{at}");
    }
}

static void PrintBinaryExpressionSemantics(SemanticModel model, SyntaxNode root)
{
    BinaryExpressionSyntax[] binaries = root.DescendantNodes().OfType<BinaryExpressionSyntax>()
        .ToArray();
    if (binaries.Length == 0)
    {
        Console.WriteLine("(no binary expressions)");
        return;
    }

    Console.WriteLine("Binary expressions:");
    foreach (BinaryExpressionSyntax binary in binaries)
    {
        ITypeSymbol? type = model.GetTypeInfo(binary).Type;
        ITypeSymbol? leftType = model.GetTypeInfo(binary.Left).Type;
        ITypeSymbol? rightType = model.GetTypeInfo(binary.Right).Type;
        ISymbol? symbol = model.GetSymbolInfo(binary).Symbol;
        Optional<object?> constant = model.GetConstantValue(binary);
        string at = FormatLocation(binary);

        Console.WriteLine($"- {binary.Kind()} `{binary}`{at}");
        Console.WriteLine($"  type: {FormatSymbol(type)}");
        Console.WriteLine($"  left: {FormatSymbol(leftType)}");
        Console.WriteLine($"  right: {FormatSymbol(rightType)}");
        if (symbol is not null)
            Console.WriteLine($"  operator: {FormatSymbol(symbol)}");
        if (constant.HasValue)
            Console.WriteLine($"  constant: {FormatConstant(constant.Value)}");
    }
}

static void PrintOperations(SemanticModel model, SyntaxNode root)
{
    StatementSyntax[] statements = root.DescendantNodes().OfType<StatementSyntax>().ToArray();
    if (statements.Length == 0)
    {
        Console.WriteLine("(none)");
        return;
    }

    foreach (StatementSyntax statement in statements)
    {
        IOperation? operation = model.GetOperation(statement);
        if (operation is null)
            continue;

        Console.WriteLine();
        Console.WriteLine($"Statement: {statement.Kind()} `{statement}`");
        PrintOperation(operation, "", true);
    }
}

static void PrintOperation(IOperation operation, string indent, bool isLast)
{
    string branch = isLast ? "└─" : "├─";
    Console.Write(indent);
    Console.Write(branch);

    string type = operation.Type is null ? "" : $" : {FormatSymbol(operation.Type)}";
    string constant = operation.ConstantValue.HasValue
        ? $" = {operation.ConstantValue.Value ?? "null"}"
        : "";
    string implicitFlag = operation.IsImplicit ? " (implicit)" : "";
    Console.WriteLine($"{operation.Kind}{implicitFlag}{type}{constant} [{operation.Syntax.Kind()}]");

    string childIndent = indent + (isLast ? "  " : "│ ");
    IOperation[] children = operation.ChildOperations.ToArray();
    for (var i = 0; i < children.Length; i++)
        PrintOperation(children[i], childIndent, i == children.Length - 1);
}

static bool TryPrintFirstControlFlowGraph(
    CSharpCompilation compilation,
    SyntaxNode root,
    out string reason)
{
    if (root.DescendantNodes().OfType<GlobalStatementSyntax>().Any())
    {
        reason = "top-level statements are not supported; provide a full program with a method body";
        return false;
    }

    try
    {
        MethodDeclarationSyntax? method = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
            .FirstOrDefault(m => m.Body is not null);
        if (method is not null)
        {
            SemanticModel model = compilation.GetSemanticModel(method.SyntaxTree);
            if (model.GetOperation(method) is IMethodBodyOperation methodBodyOperation)
            {
                reason = "";
                var cfg = ControlFlowGraph.Create(methodBodyOperation);
                PrintControlFlowGraph(cfg);
                return true;
            }

            if (method.Body is not null && model.GetOperation(method.Body) is IBlockOperation methodBlock)
            {
                reason = "";
                var cfg = ControlFlowGraph.Create(methodBlock);
                PrintControlFlowGraph(cfg);
                return true;
            }
        }
    }
    catch (Exception ex)
    {
        reason = $"failed to build CFG from method: {ex.GetType().Name}";
        return false;
    }

    reason = "no block-bodied method found";
    return false;
}

static void PrintControlFlowGraph(ControlFlowGraph cfg)
{
    Dictionary<int, List<int>> predecessors = BuildPredecessorMap(cfg);
    foreach (BasicBlock block in cfg.Blocks)
    {
        Console.WriteLine();
        Console.WriteLine($"Block B{block.Ordinal} ({block.Kind})");
        Console.WriteLine($"  predecessors: {FormatBlockList(predecessors[block.Ordinal])}");

        if (block.Operations.Length == 0)
        {
            Console.WriteLine("  operations: (none)");
        }
        else
        {
            Console.WriteLine("  operations:");
            foreach (IOperation operation in block.Operations)
                Console.WriteLine($"    - {FormatOperationSummary(operation)}");
        }

        if (block.BranchValue is not null)
            Console.WriteLine($"  branchValue: {FormatOperationSummary(block.BranchValue)}");

        if (block.ConditionKind != ControlFlowConditionKind.None)
            Console.WriteLine($"  condition: {block.ConditionKind}");

        PrintSuccessors(block);
    }
}

static void PrintSuccessors(BasicBlock block)
{
    if (block.FallThroughSuccessor is null && block.ConditionalSuccessor is null)
    {
        Console.WriteLine("  successors: (none)");
        return;
    }

    Console.WriteLine("  successors:");
    PrintSuccessor("fallthrough", block.FallThroughSuccessor);
    PrintSuccessor("conditional", block.ConditionalSuccessor);
}

static void PrintSuccessor(string label, ControlFlowBranch? branch)
{
    if (branch is null)
        return;

    string destination = branch.Destination is null ? "<null>" : $"B{branch.Destination.Ordinal}";
    Console.WriteLine($"    - {label} -> {destination}");
}

static Dictionary<int, List<int>> BuildPredecessorMap(ControlFlowGraph cfg)
{
    var map = new Dictionary<int, List<int>>();
    foreach (BasicBlock block in cfg.Blocks)
        map[block.Ordinal] = new List<int>();

    foreach (BasicBlock block in cfg.Blocks)
    {
        AddPredecessor(map, block.Ordinal, block.FallThroughSuccessor);
        AddPredecessor(map, block.Ordinal, block.ConditionalSuccessor);
    }

    return map;
}

static void AddPredecessor(
    Dictionary<int, List<int>> map,
    int sourceOrdinal,
    ControlFlowBranch? branch)
{
    if (branch?.Destination is null)
        return;

    map[branch.Destination.Ordinal].Add(sourceOrdinal);
}

static string FormatBlockList(List<int> ordinals)
{
    if (ordinals.Count == 0)
        return "(none)";

    ordinals.Sort();
    return string.Join(", ", ordinals.Select(o => $"B{o}"));
}

static string Indent(string text, string indent)
{
    string[] lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
    return string.Join(Environment.NewLine, lines.Where(l => l.Length > 0).Select(l => indent + l));
}

static string FormatSymbol(ISymbol? symbol)
{
    if (symbol is null)
        return "?";

    return symbol.ToDisplayString(
        new SymbolDisplayFormat(
            SymbolDisplayGlobalNamespaceStyle.Omitted,
            SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
            SymbolDisplayGenericsOptions.IncludeTypeParameters,
            miscellaneousOptions: SymbolDisplayMiscellaneousOptions.EscapeKeywordIdentifiers));
}

static string FormatOperationSummary(IOperation operation)
{
    string implicitFlag = operation.IsImplicit ? " (implicit)" : "";
    string type = operation.Type is null ? "" : $" : {FormatSymbol(operation.Type)}";
    string constant = operation.ConstantValue.HasValue
        ? $" = {FormatConstant(operation.ConstantValue.Value)}"
        : "";
    string syntax = FormatSyntaxSnippet(operation.Syntax);
    return $"{operation.Kind}{implicitFlag}{type}{constant} `{syntax}`";
}

static string FormatSyntaxSnippet(SyntaxNode? node)
{
    if (node is null)
        return "<no-syntax>";

    var text = node.ToString();
    text = string.Join(
        " ",
        text.Split(
            new[] { ' ', '\r', '\n', '\t' },
            StringSplitOptions.RemoveEmptyEntries));
    if (text.Length > 80)
        text = text.Substring(0, 77) + "...";
    return text;
}

static string FormatLocation(SyntaxNode node)
{
    FileLinePositionSpan span = node.GetLocation().GetLineSpan();
    LinePosition start = span.StartLinePosition;
    return $" @ L{start.Line + 1}:{start.Character + 1}";
}

static string FormatConstant(object? value)
{
    if (value is null)
        return "null";

    if (value is string s)
        return $"\"{s.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";

    return value.ToString() ?? "null";
}

static void EmitAndDisassemble(CSharpCompilation compilation)
{
    using var peStream = new MemoryStream();
    using var pdbStream = new MemoryStream();
    EmitResult emitResult = compilation.Emit(peStream, pdbStream);

    Console.WriteLine($"Emit success: {emitResult.Success}");
    PrintDiagnostics(emitResult.Diagnostics);
    if (!emitResult.Success)
        return;

    byte[] peBytes = peStream.ToArray();
    Console.WriteLine($"PE size: {peBytes.Length} bytes");

    Assembly assembly = Assembly.Load(peBytes);
    MethodInfo? entryPoint = assembly.EntryPoint;
    if (entryPoint is null)
    {
        Console.WriteLine("(no entry point)");
        return;
    }

    Console.WriteLine($"EntryPoint: {entryPoint.DeclaringType?.FullName}.{entryPoint.Name}");
    Dictionary<ushort, OpCode> opcodeMap = BuildOpCodeMap();
    DisassembleMethod(entryPoint, opcodeMap);
}

static void PrintTokens(SyntaxTree tree)
{
    SyntaxToken[] tokens = tree.GetRoot().DescendantTokens(descendIntoTrivia: true).ToArray();
    if (tokens.Length == 0)
    {
        Console.WriteLine("(none)");
        return;
    }

    for (var i = 0; i < tokens.Length; i++)
    {
        SyntaxToken token = tokens[i];
        string value = token.Value is null ? "" : $" value={token.Value}";
        Console.WriteLine($"{i + 1,4}: {token.Kind()} text={Escape(token.Text)}{value}");

        foreach (SyntaxTrivia trivia in token.LeadingTrivia)
            Console.WriteLine($"      lead: {trivia.Kind()} text={Escape(trivia.ToFullString())}");
        foreach (SyntaxTrivia trivia in token.TrailingTrivia)
            Console.WriteLine($"      trail: {trivia.Kind()} text={Escape(trivia.ToFullString())}");
    }
}

static void DisassembleMethod(MethodInfo method, Dictionary<ushort, OpCode> opcodeMap)
{
    MethodBody? body = method.GetMethodBody();
    if (body is null)
    {
        Console.WriteLine("(no method body)");
        return;
    }

    byte[]? il = body.GetILAsByteArray();
    if (il is null || il.Length == 0)
    {
        Console.WriteLine("(empty IL)");
        return;
    }

    Module module = method.Module;

    Console.WriteLine();
    Console.WriteLine("IL:");

    var offset = 0;
    while (offset < il.Length)
    {
        int startOffset = offset;
        byte opValue = il[offset++];
        ushort key = opValue;
        if (opValue == 0xFE)
        {
            key = (ushort)(0xFE00 | il[offset++]);
        }

        if (!opcodeMap.TryGetValue(key, out OpCode opcode))
        {
            Console.WriteLine($"{startOffset:X4}: <unknown 0x{key:X4}>");
            continue;
        }

        string operand = ReadOperand(opcode, il, ref offset, module, startOffset);
        Console.WriteLine($"{startOffset:X4}: {opcode.Name}{operand}");
    }
}

static string ReadOperand(OpCode opcode, byte[] il, ref int offset, Module module, int instructionOffset)
{
    try
    {
        return opcode.OperandType switch
        {
            OperandType.InlineNone => "",
            OperandType.ShortInlineI => $" {unchecked((sbyte)il[offset++])}",
            OperandType.InlineI => $" {BitConverter.ToInt32(ReadBytes(il, ref offset, 4))}",
            OperandType.InlineI8 => $" {BitConverter.ToInt64(ReadBytes(il, ref offset, 8))}",
            OperandType.ShortInlineR => $" {BitConverter.ToSingle(ReadBytes(il, ref offset, 4))}",
            OperandType.InlineR => $" {BitConverter.ToDouble(ReadBytes(il, ref offset, 8))}",
            OperandType.ShortInlineBrTarget => FormatBranchTarget(
                instructionOffset,
                (sbyte)il[offset++],
                true),
            OperandType.InlineBrTarget => FormatBranchTarget(
                instructionOffset,
                BitConverter.ToInt32(ReadBytes(il, ref offset, 4)),
                false),
            OperandType.InlineSwitch => ReadSwitchTargets(il, ref offset, instructionOffset),
            OperandType.ShortInlineVar => $" V_{il[offset++]}",
            OperandType.InlineVar => $" V_{BitConverter.ToUInt16(ReadBytes(il, ref offset, 2))}",
            OperandType.InlineString =>
                $" {ResolveString(module, BitConverter.ToInt32(ReadBytes(il, ref offset, 4)))}",
            OperandType.InlineField =>
                $" {ResolveMember(module, BitConverter.ToInt32(ReadBytes(il, ref offset, 4)))}",
            OperandType.InlineMethod =>
                $" {ResolveMember(module, BitConverter.ToInt32(ReadBytes(il, ref offset, 4)))}",
            OperandType.InlineType =>
                $" {ResolveMember(module, BitConverter.ToInt32(ReadBytes(il, ref offset, 4)))}",
            OperandType.InlineTok =>
                $" {ResolveMember(module, BitConverter.ToInt32(ReadBytes(il, ref offset, 4)))}",
            OperandType.InlineSig => $" sig(0x{BitConverter.ToInt32(ReadBytes(il, ref offset, 4)):X8})",
            _ => $" <operand {opcode.OperandType}>"
        };
    }
    catch (Exception ex)
    {
        return $" <operand-error {ex.GetType().Name}>";
    }
}

static byte[] ReadBytes(byte[] il, ref int offset, int count)
{
    var slice = new byte[count];
    Buffer.BlockCopy(il, offset, slice, 0, count);
    offset += count;
    return slice;
}

static string FormatBranchTarget(int instructionOffset, int delta, bool shortForm)
{
    int instructionSize = shortForm ? 2 : 5;
    int target = instructionOffset + instructionSize + delta;
    return $" -> IL_{target:X4}";
}

static string ReadSwitchTargets(byte[] il, ref int offset, int instructionOffset)
{
    var count = BitConverter.ToInt32(ReadBytes(il, ref offset, 4));
    var deltas = new int[count];
    for (var i = 0; i < count; i++)
        deltas[i] = BitConverter.ToInt32(ReadBytes(il, ref offset, 4));

    // For switch, base is end of the instruction (opcode + count + deltas)
    int baseOffset = instructionOffset + 1 + 4 + 4 * count;
    IEnumerable<string> targets = deltas.Select(d => $"IL_{baseOffset + d:X4}");
    return " (" + string.Join(", ", targets) + ")";
}

static string ResolveString(Module module, int metadataToken)
{
    try
    {
        string s = module.ResolveString(metadataToken);
        return $"\"{s.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";
    }
    catch
    {
        return $"str(0x{metadataToken:X8})";
    }
}

static string ResolveMember(Module module, int metadataToken)
{
    try
    {
        MemberInfo? member = module.ResolveMember(metadataToken);
        return member?.ToString() ?? $"token(0x{metadataToken:X8})";
    }
    catch
    {
        return $"token(0x{metadataToken:X8})";
    }
}

static Dictionary<ushort, OpCode> BuildOpCodeMap()
{
    var map = new Dictionary<ushort, OpCode>();
    foreach (FieldInfo field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
    {
        if (field.GetValue(null) is not OpCode opcode)
            continue;

        map[(ushort)opcode.Value] = opcode;
    }
    return map;
}
