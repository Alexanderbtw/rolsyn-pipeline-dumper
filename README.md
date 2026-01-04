# Rolsyn Pipeline Dumper

Small Roslyn playground that runs a C# snippet through key compiler stages and prints the results to stdout.

## What it does

- Reads `input.txt` from the build output directory; falls back to a small default program when missing.
- Parses the source with `LanguageVersion.Preview` and prints the syntax tree and tokens.
- Shows parse/compilation diagnostics and a semantic snapshot (type of the first binary expression, declared locals).
- Dumps `IOperation` trees and a control-flow graph (wrapping top-level statements when needed).
- Emits an in-memory assembly and disassembles the entry point IL.

## Requirements

- .NET 10 SDK, as specified by the `net10.0` target framework.

## Usage

Build and run with the default sample:

```bash
dotnet run
```

Provide your own input by placing `input.txt` next to the compiled executable (the `AppContext.BaseDirectory`):

```bash
dotnet build
cp input.txt bin/Debug/net10.0/input.txt
dotnet run --no-build
```

Output is printed to the console.
