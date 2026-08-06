# IP Whitelist Comments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow each whitelist line to carry an inline comment while keeping whitelist matching behavior unchanged.

**Architecture:** Keep the stored whitelist format human-friendly and backward compatible. Preserve the full line for editing and Redis sync, but strip the comment portion only when building the in-memory IP matcher so comments never affect request handling.

**Tech Stack:** Lua, OpenResty, plain HTML/JavaScript, existing admin backend routes.

---

### Task 1: Make whitelist parsing comment-aware

**Files:**
- Modify: `config.lua`
- Modify: `lib/constants.lua` only if a shared separator constant becomes useful

- [ ] **Step 1: Add a failing smoke check by reasoning about current behavior**

  Current code passes raw whitelist lines directly into `ipmatcher.new`, so a line like `1.2.3.4 office` would fail to load because the comment is treated as part of the IP.

- [ ] **Step 2: Implement comment stripping for matcher input**

  Add a helper that trims each line, keeps the full line for storage/display, and extracts only the first token before whitespace for IP matching.

- [ ] **Step 3: Keep Redis/file payloads human-readable**

  Preserve full whitelist lines when building the cluster payload so the UI can still show `IP comment` on reload.

- [ ] **Step 4: Verify the parser behavior by inspection**

  Confirm that the whitelist load path, Redis sync path, and file load path all share the same normalization rules.

### Task 2: Update the whitelist editor to explain the new format

**Files:**
- Modify: `admin/view/defense/ip-filter.html`
- Modify: `admin/lua/ip_filter.lua`

- [ ] **Step 1: Update the textarea hint**

  Replace the existing “one IP per line” hint with “one IP or CIDR per line, comment allowed after whitespace”.

- [ ] **Step 2: Relax the client-side save validation**

  Stop rejecting commas globally, and instead validate only that the IP/CIDR prefix is valid when a comment is present.

- [ ] **Step 3: Keep save/load round-tripping intact**

  Ensure the editor still loads the raw line text and saves it back unchanged.

- [ ] **Step 4: Verify the UI text and validation**

  Confirm the editor now accepts entries like `1.2.3.4 office` and `10.0.0.0/24 internal network`.

### Task 3: Verify the full flow

**Files:**
- No code changes expected

- [ ] **Step 1: Check the diff for accidental behavior changes**

  Verify the blacklist path and unrelated defenses still behave as before.

- [ ] **Step 2: Run any available local syntax or smoke checks**

  Use the strongest available local validation tool in this environment, or a targeted grep-based sanity check if no Lua runtime is installed.

- [ ] **Step 3: Summarize the resulting behavior**

  Document that comments are editable in the UI, preserved on disk/Redis, and ignored by the matcher.
