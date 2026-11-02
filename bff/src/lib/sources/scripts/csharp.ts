// C# script sources (`.cs`): .NET 10 file-based apps, run as `dotnet run <file> -- <args>` (SCRIPT_DOTNET names
// another `dotnet`). The first run of a file compiles it, which takes seconds, so it is built once in the
// background when the source registers (engine.ts warm) and every later run reuses that build.
import type { ScriptRunner } from './engine';

const env = { DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1' };
const dotnet = () => process.env.SCRIPT_DOTNET || 'dotnet';

export const csharp: ScriptRunner = {
  name: 'C#',
  exts: ['.cs'],
  // `--` so a query that starts with a dash is the script's argument, never an option of dotnet's.
  command: (file, args) => ({ cmd: dotnet(), args: ['run', file, '--', ...args], env }),
  warm: (file) => ({ cmd: dotnet(), args: ['build', file], env }),
  // A run still checks the build is current, which costs more than starting an interpreter.
  timeoutMs: 60_000,
};
