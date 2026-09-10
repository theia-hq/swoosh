# swoosh (theia-hq product CLI)

This repo is the product surface of theia-hq. House canon lives versioned outside this repo; read it via your Read tool, do not guess:

- Working agreement (binding): `../notes/agents/AGENTS.md`
- Session handoff + current state: `../notes/ONBOARDING.md`
- Style contract: `./STYLE.md` (identical copy in every repo; source of truth for code voice)
- CLI surface spec: `../notes/CLI-DESIGN.md`
- Layering map: `../notes/LAYERS.md`

Non-negotiables (full text in the canon): green before commit AND after push; Cargo.lock shipping-form discipline (`git checkout Cargo.lock` before committing); `omiraculous@gmail.com`, no trailers, no em dashes; explicit paths, never `add -A`; one builder in this tree at a time; subagent work lands UNCOMMITTED.

Skills provide specialized instructions and workflows for specific tasks.
Use the skill tool to load a skill when a task matches its description.
<available_skills>
  <skill>
    <name>customize-opencode</name>
    <description>Use ONLY when the user is editing or creating opencode's own configuration: opencode.json, opencode.jsonc, files under .opencode/, or files under ~/.config/opencode/. Also use when creating or fixing opencode agents, subagents, skills, plugins, MCP servers, or permission rules. Do not use for the user's own application code, or for any project that is not configuring opencode itself.</description>
    <location>&lt;built-in&gt;</location>
  </skill>
  <skill>
    <name>git-surgeon</name>
    <description>Non-interactive hunk-level git staging, unstaging, discarding, undoing, fold, amend, squash, commit splitting, and commit reordering. Use when selectively staging, unstaging, discarding, reverting, squashing, splitting, or reordering individual diff hunks by ID instead of interactively.</description>
    <location>/Users/miraclx/.claude/skills/git-surgeon/SKILL.md</location>
  </skill>
</available_skills>
