const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const repoRoot = path.resolve(__dirname, "..");
const roothiderPath = path.join(repoRoot, "BaseBin", "launchdhook", "src", "roothider.m");

test("blacklisted apps do not enter the no-injection spawn branch", () => {
  const source = fs.readFileSync(roothiderPath, "utf8");
  const branchMatch = source.match(/if\s*\(\s*choicyBlocked\s*\|\|\s*roothideBlacklisted\s*\)/);
  const injectionBranchMatch = source.match(
    /if\s*\(\s*roothideBlacklisted\s*\)[\s\S]*?__posix_spawn_hook\s*\(\s*blacklistedPidp,\s*path,\s*desc,\s*argv,\s*envp\s*\)[\s\S]*?commitBlacklistProcessId\s*\(\s*blacklistedPidp\s*\)/,
  );

  assert.equal(
    branchMatch,
    null,
    "roothideBlacklisted must not bypass posix_spawn_hook_shared/systemhook injection",
  );
  assert.notEqual(
    injectionBranchMatch,
    null,
    "roothideBlacklisted should preserve blacklist pid tracking while using the injection spawn hook",
  );
});
