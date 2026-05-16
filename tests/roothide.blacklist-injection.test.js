const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const repoRoot = path.resolve(__dirname, "..");
const roothiderPath = path.join(repoRoot, "BaseBin", "launchdhook", "src", "roothider.m");
const spawnHookPath = path.join(repoRoot, "BaseBin", "launchdhook", "src", "spawn_hook.c");
const blacklistPath = path.join(repoRoot, "BaseBin", "libjailbreak", "src", "roothider", "blacklist.m");

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

test("blacklisted app spawns are detected through xpcproxy launch arguments", () => {
  const source = fs.readFileSync(blacklistPath, "utf8");

  assert.match(
    source,
    /bool\s+isBlacklistedSpawn\s*\(\s*const\s+char\s*\*\s*path\s*,\s*char\s*\*const\s+argv\[\]\s*\)/,
    "blacklist helper should classify launchd xpcproxy spawns, not only executable paths",
  );
  assert.match(
    source,
    /strcmp\s*\(\s*path\s*,\s*"\/usr\/libexec\/xpcproxy"\s*\)\s*==\s*0[\s\S]*?isBlacklistedApp\s*\(\s*argv\[1\]\s*\)/,
    "xpcproxy argv[1] should be treated as the launchd service or bundle identifier for blacklist checks",
  );
});

test("early boot xpcproxy spawns still pass through systemhook injection for blacklisted apps", () => {
  const roothiderSource = fs.readFileSync(roothiderPath, "utf8");
  const spawnHookSource = fs.readFileSync(spawnHookPath, "utf8");

  assert.match(
    roothiderSource,
    /bool\s+roothideBlacklisted\s*=\s*isBlacklistedSpawn\s*\(\s*path\s*,\s*argv\s*\)/,
    "launchd roothide prehook must classify blacklist status from spawn path and argv",
  );
  assert.match(
    spawnHookSource,
    /if\s*\(\s*gInEarlyBoot\s*\)[\s\S]*?isBlacklistedSpawn\s*\(\s*path\s*,\s*argv\s*\)[\s\S]*?posix_spawn_hook_shared/,
    "early boot xpcproxy handling must not bypass injection when the target spawn is blacklisted",
  );
});
