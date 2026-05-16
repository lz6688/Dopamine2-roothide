const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const repoRoot = path.resolve(__dirname, "..");
const systemwidePath = path.join(repoRoot, "BaseBin", "launchdhook", "src", "jbserver", "jbdomain_systemwide.c");
const roothidePath = path.join(repoRoot, "BaseBin", "launchdhook", "src", "jbserver", "jbdomain_roothide.c");
const machServerPath = path.join(repoRoot, "BaseBin", "launchdhook", "src", "jbserver", "jbserver_mach.c");

test("systemwide domain remains available to blacklisted processes for checkin and trust", () => {
  const source = fs.readFileSync(systemwidePath, "utf8");

  assert.match(
    source,
    /struct\s+jbserver_domain\s+gSystemwideDomain\s*=\s*\{[\s\S]*?\.permissionHandler\s*=\s*NULL\s*,/,
    "systemwide checkin/trust must not be blocked by roothide blacklist filtering",
  );
});

test("roothide domain only allows trust helpers for blacklisted processes", () => {
  const source = fs.readFileSync(roothidePath, "utf8");

  assert.match(
    source,
    /bool\s+roothide_domain_allowed\(audit_token_t\s+clientToken,\s*uint64_t\s+actionIdx\)/,
    "roothide permission should inspect the requested action",
  );
  assert.match(
    source,
    /case\s+JBS_ROOTHIDE_TRUST_LIBRARY_RECURSE\s*:/,
    "blacklisted processes need library trust for TweakLoader and plugin dylibs",
  );
  assert.match(
    source,
    /case\s+JBS_ROOTHIDE_TRUST_EXECUTABLE_RECURSE\s*:/,
    "blacklisted processes may need executable trust for child processes",
  );
  assert.match(
    source,
    /case\s+JBS_ROOTHIDE_DYLD_PATCH_ENABLED_GET\s*:/,
    "blacklisted processes need to read dyld patch mode while loading",
  );
});

test("mach checkin and trust path does not use roothide blacklist filtering", () => {
  const source = fs.readFileSync(machServerPath, "utf8");

  assert.doesNotMatch(
    source,
    /roothide_domain_allowed\(\s*\*auditToken/,
    "mach systemwide checkin/trust must not be blocked by roothide blacklist filtering",
  );
});
