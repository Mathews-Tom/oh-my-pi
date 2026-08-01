# Resource permissions

`permissions.*` answers a different question from the approval settings: not *may this tool run*, but *may it touch this path*. It is off by default.

| Axis | Setting | Question |
|---|---|---|
| Capability | `tools.approvalMode` | How much do I trust the agent overall? |
| Tool identity | `tools.approval.<tool>` | May this tool run at all? |
| Command | `bash.patterns` | May this command line run? |
| **Resource** | **`permissions.*`** | **May it touch this path?** |

See [Tool approval mode](./approval-mode.md) for the first two and [the bash tool](./tools/bash.md#bashpatterns-permission-policy) for the third.

## The one invariant

**`permissions.*` can only subtract, never grant.** A path this layer permits still faces `tools.approvalMode` and `tools.approval.<tool>` exactly as it does today. There is no value of any `permissions.*` key that auto-approves a call, and `permissions.allow.*` relaxes this layer's own rules and nothing else.

## Why it is not an approval mode

Subagents run with `tools.approvalMode: yolo` forced (`task/executor.ts`), because a headless subagent has no UI to confirm against. A path guard expressed as a fourth approval tier or a new mode would therefore be bypassed by spawning a `task`.

So this is not an approval tier. It is a hard check evaluated unconditionally in `ExtensionToolWrapper.execute` — the point every registry tool dispatch passes through — before the approval prompt is computed and independent of the active mode. A denied path fails the same way inside a subagent as it does in the main session. (One delegation seam is deliberately outside it; see [What this does not cover](#what-this-does-not-cover).)

## Profiles

```yaml
permissions:
  profile: strict
```

| Profile | Effect |
|---|---|
| `off` (default) | No enforcement. Short-circuits on one settings read, before any filesystem work. Behaviour is identical to having no permission layer at all. |
| `workspace` | Writes must land under `cwd` or a `workspace.additionalDirectories` root. Reads unrestricted. |
| `strict` | `workspace`, plus built-in deny rules for secrets, on both read and write. |

`strict` denies `**/.env`, `**/.env.*`, `**/id_rsa`, `**/id_ed25519`, `**/id_ecdsa`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/.aws/credentials`, `**/.ssh/**`, and `**/secrets.json`. It ships carve-outs for `**/.env.example` and `**/.env.sample`, so the common case needs no rule of your own.

Two defaults are deliberate:

- **Off by default.** A default-on path guard breaks every session that reads `~/.gitconfig` or `/etc/hosts`, which would be a breaking change rather than a feature.
- **Reads unconfined even under `strict`.** Reading `/var/log`, a sibling repository, or your global git config is routine. An escaping *write* is the destructive case, so that is what confinement covers by default. Set `permissions.confineReads: true` if you want the stricter reading.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `permissions.profile` | `off` \| `workspace` \| `strict` | `off` | Base profile. |
| `permissions.confineWrites` | boolean | profile-derived | Writes must land under a workspace root. |
| `permissions.confineReads` | boolean | `false` | Reads must land under a workspace root. |
| `permissions.deny.read` | glob list | `[]` | Merged onto the profile's rules. |
| `permissions.deny.write` | glob list | `[]` | Merged onto the profile's rules. |
| `permissions.allow.read` | glob list | `[]` | Carve-outs, evaluated first. |
| `permissions.allow.write` | glob list | `[]` | Carve-outs, evaluated first. |
| `permissions.opaqueToolScan` | `deny` \| `prompt` \| `off` | `deny` | What the literal scan does on a match. |

A profile's deny list is a floor. `permissions.deny.*` adds to it; the only way to punch a hole in it is `permissions.allow.*`.

```yaml
permissions:
  profile: strict
  allow:
    read:
      - "config/.env.ci"
  deny:
    write:
      - "**/migrations/**"
```

## Path globs are not command globs

These are two different dialects, on purpose:

- **Command patterns** (`bash.patterns`) match a command line. `*` matches anything, including `/`.
- **Path patterns** (`permissions.*`) are `Bun.Glob`. `*` does **not** cross `/`.

So a rule that must catch a secret at any depth is written `**/.env`, **never** `*.env`. `*.env` matches `prod.env` in the current directory and nothing nested; `**/.env` matches `.env`, `svc/.env`, and `/abs/path/.env`.

Regex is not supported. A rule such as `"^git push --force"` belongs to the command axis, not this one.

Each target is matched against three spellings — the workspace-relative path, the absolute path, and the basename — so a rule written either way behaves the way it reads.

## What is actually enforced

Tools split into two classes, and the split is the honest boundary of the feature.

**Class A — structured path tools.** `read`, `write`, `edit`, `glob`, `grep`, `ast_grep`, `ast_edit`, `lsp`, `debug`, `inspect_image`, `security_scan`. These declare which arguments are paths and whether each is read or written, so enforcement is sound. This is the real guardrail.

Resolution mirrors what the tool itself does, so the guard and the tool cannot disagree about which file is at stake. Both the target and its deepest existing ancestor are `realpath`-resolved, so a symlink pointing out of the workspace is caught rather than trusted; a *dangling* symlink is refused outright, because where it lands cannot be determined before the write follows it.

**Class B — opaque tools.** `bash`, `eval`, `browser`, `computer`, `hub`, and every MCP or extension tool. These take arbitrary code, and sound enforcement against arbitrary code is undecidable: `cat .env` can be written `$(echo Lmk|base64 -d)`, and no static scan catches that.

They get a best-effort literal scan instead. Shell arguments are tokenized the same way `bash.patterns` tokenizes them; other tools' string arguments are walked and split. A literal reference to a denied path is refused.

> **The Class B scan is defence against accidents and naive prompt injection. It is not a sandbox.** Do not configure a deny list and conclude that shell cannot reach those files. The real boundary for arbitrary code is `tools.approval.bash: deny`, which already exists and is untouched by this layer.

`permissions.opaqueToolScan: prompt` turns a scan hit into an interactive confirmation instead of a refusal. `off` disables the scan entirely and leaves only Class A enforcement.

Unknown MCP and extension tools are treated as Class B, not as pathless — a tool this codebase has never seen may well take a `path` argument.

## Workspace roots

Confinement measures against `cwd` plus `workspace.additionalDirectories`, read from the live session, so `/add-dir` and `/remove-dir` take effect immediately.

An isolated worktree subagent is created with `workspace.additionalDirectories` cleared and its own cwd, so its roots collapse to the worktree alone — it cannot write back into the parent checkout under `workspace` or `strict`.

## Exemptions

Internal URLs are not user filesystem targets and are never denied: `local://`, `vault://`, `xd://`, `memory://`, `skill://`, `artifact://`, `agent://`, `history://`, `issue://`, `pr://`, `rule://`, `security://`, `mcp://`, `omp://`, `ssh://`. `http(s)://` is likewise not a path. Denying these would break artifact and device routing without protecting a single file.

## Failure behaviour

Every denial names the exact rule that fired and the setting to change, and that text is surfaced to the model so it adapts instead of retrying the same call:

```
Reading ".env" is blocked by the resource permission rule "**/.env" (permissions.profile: strict).
To allow it: add "**/.env" to permissions.allow.read, or set permissions.profile: off.
```

Resolution failures fail closed. Once a profile is active, a path argument that cannot be resolved to an absolute location is denied rather than waved through — "we could not tell what this touches" is not a reason to allow it.

## What this does not cover

- **OS-level sandboxing.** No `seccomp`, `landlock`, or `sandbox-exec`. A process the agent spawns is bounded by your OS, not by this.
- **The TOCTOU window.** A symlink can be re-pointed between the check and the open. Closing that needs `O_NOFOLLOW` plumbed through every tool.
- **Anything a Class B tool does indirectly.** See above; that is the point of stating the boundary rather than implying the deny list covers shell.
- **Extension `ctx.invokeTool` delegation.** That call reaches the native tool directly, by design, so a wrapper extension inherits the approval its own call already cleared. It is not re-gated, so an installed extension that re-registers a built-in is inside the trust boundary. (The `xd://` device route *is* gated: it dispatches through the wrapped tool.)
- **Scan literals the tokenizer cannot see.** The Class B scan skips single-character tokens and anything starting with `-`, and caps how many literals one call contributes. All three are why it is called best-effort.
