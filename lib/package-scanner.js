const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");
const { createFinding, dedupeFindings } = require("./findings");

const execFileAsync = promisify(execFile);
const MAX_TARBALL_BYTES = 25 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 100 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 5000;
const DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org/";
const SAFE_CHILD_ENV_KEYS = [
  "PATH",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "TERM",
  "SystemRoot",
  "ComSpec",
  "PATHEXT",
  "WINDIR",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS"
];

const dangerousPatternCatalog = [
  {
    id: "child_process",
    regex: /\b(?:exec|execSync|spawn|spawnSync|fork|execFile|execFileSync)\b/,
    gate: /\bchild_process\b/,
    severity: "high",
    cwe: "shell_injection",
    description: "Package uses child_process execution primitives.",
    remediation: "Review command construction carefully and ensure no user-controlled values reach shell or process execution sinks."
  },
  {
    id: "eval",
    regex: /\beval\s*\(/,
    severity: "high",
    cwe: "unsafe_eval",
    description: "Package uses eval().",
    remediation: "Remove dynamic evaluation or replace it with safe parsing and fixed dispatch."
  },
  {
    id: "function-constructor",
    regex: /\bnew Function\s*\(|\bFunction\s*\(/,
    severity: "high",
    cwe: "unsafe_eval",
    description: "Package constructs functions from dynamic strings.",
    remediation: "Avoid Function constructor usage on untrusted data."
  },
  {
    id: "fs-write-user-input",
    regex: /\b(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(([^)]*(?:req\.|request\.|input|argv|params|body|process\.env))/s,
    severity: "medium",
    cwe: "unsafe_file_write",
    description: "Package appears to write potentially user-influenced data to disk.",
    remediation: "Validate file paths and content before writing, and pin writes to an allowlisted directory."
  },
  {
    id: "permission-broadening",
    regex: /\b(?:chmod|chmodSync)\s*\(([^)]*0o?777|[^)]*['"]777['"])/,
    severity: "high",
    cwe: "permission_misconfiguration",
    description: "Package appears to set overly broad file permissions.",
    remediation: "Avoid world-writable file modes and prefer the minimum required permission bits."
  }
];

function normalizePackageSpecifier(packageName) {
  if (typeof packageName !== "string") {
    throw new Error("Package name must be a string.");
  }

  const spec = packageName.trim();
  if (!spec || spec.length > 214) {
    throw new Error("Package name must be a non-empty npm registry package spec.");
  }

  if (
    spec.startsWith(".") ||
    spec.startsWith("/") ||
    spec.startsWith("~") ||
    spec.includes("\\") ||
    /\s/.test(spec) ||
    /^(?:file|git\+|git:|https?:|ssh:|github:)/i.test(spec)
  ) {
    throw new Error("Only npm registry package names are allowed.");
  }

  let namePart = spec;
  let versionPart = "";
  if (spec.startsWith("@")) {
    const slashIndex = spec.indexOf("/");
    if (slashIndex <= 1) {
      throw new Error("Scoped package names must use the form @scope/name.");
    }
    const versionIndex = spec.indexOf("@", slashIndex + 1);
    if (versionIndex !== -1) {
      namePart = spec.slice(0, versionIndex);
      versionPart = spec.slice(versionIndex + 1);
    }
  } else {
    const versionIndex = spec.indexOf("@");
    if (versionIndex !== -1) {
      namePart = spec.slice(0, versionIndex);
      versionPart = spec.slice(versionIndex + 1);
    }
  }

  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(namePart)) {
    throw new Error("Only npm registry package names are allowed.");
  }

  if (versionPart && !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(versionPart)) {
    throw new Error("Only exact versions or dist-tags are allowed in package specs.");
  }

  return versionPart ? `${namePart}@${versionPart}` : namePart;
}

function buildBaseCommandEnvironment(overrides) {
  const env = {};

  for (const key of SAFE_CHILD_ENV_KEYS) {
    if (typeof process.env[key] === "string" && process.env[key]) {
      env[key] = process.env[key];
    }
  }

  for (const [key, value] of Object.entries(overrides || {})) {
    if (typeof value === "string" && value) {
      env[key] = value;
    }
  }

  return env;
}

function resolveNpmRegistry(rawRegistry) {
  const candidate = typeof rawRegistry === "string" ? rawRegistry.trim() : "";
  if (!candidate) {
    return DEFAULT_NPM_REGISTRY;
  }

  try {
    const parsed = new URL(candidate);
    const hostname = parsed.hostname.toLowerCase();
    if (parsed.protocol === "https:" || (parsed.protocol === "http:" && ["127.0.0.1", "::1", "localhost"].includes(hostname))) {
      return parsed.toString();
    }
  } catch (error) {
    return DEFAULT_NPM_REGISTRY;
  }

  return DEFAULT_NPM_REGISTRY;
}

async function buildNpmScanEnvironment(tempRoot) {
  const homeDir = path.join(tempRoot, "npm-home");
  const cacheDir = path.join(tempRoot, "npm-cache");
  const configDir = path.join(tempRoot, "npm-config");
  const userConfigPath = path.join(configDir, "user.npmrc");
  const globalConfigPath = path.join(configDir, "global.npmrc");
  const registry = resolveNpmRegistry(process.env.AGENT_SECURITY_NPM_REGISTRY);

  await fs.promises.mkdir(homeDir, { recursive: true, mode: 0o700 });
  await fs.promises.mkdir(cacheDir, { recursive: true, mode: 0o700 });
  await fs.promises.mkdir(configDir, { recursive: true, mode: 0o700 });
  await fs.promises.writeFile(userConfigPath, "", "utf8");
  await fs.promises.writeFile(globalConfigPath, "", "utf8");

  return buildBaseCommandEnvironment({
    HOME: homeDir,
    USERPROFILE: homeDir,
    XDG_CONFIG_HOME: configDir,
    XDG_CACHE_HOME: cacheDir,
    npm_config_userconfig: userConfigPath,
    NPM_CONFIG_USERCONFIG: userConfigPath,
    npm_config_globalconfig: globalConfigPath,
    NPM_CONFIG_GLOBALCONFIG: globalConfigPath,
    npm_config_cache: cacheDir,
    NPM_CONFIG_CACHE: cacheDir,
    npm_config_registry: registry,
    NPM_CONFIG_REGISTRY: registry,
    npm_config_ignore_scripts: "true",
    NPM_CONFIG_IGNORE_SCRIPTS: "true",
    npm_config_fund: "false",
    NPM_CONFIG_FUND: "false",
    npm_config_update_notifier: "false",
    NPM_CONFIG_UPDATE_NOTIFIER: "false"
  });
}

async function runCommand(command, args, options) {
  try {
    const result = await execFileAsync(command, args, {
      cwd: options && options.cwd ? options.cwd : undefined,
      env: buildBaseCommandEnvironment(options && options.env),
      timeout: options && options.timeout ? options.timeout : 120000,
      maxBuffer: options && options.maxBuffer ? options.maxBuffer : 10 * 1024 * 1024
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      code: 0
    };
  } catch (error) {
    if (options && options.allowFailure) {
      return {
        stdout: error.stdout || "",
        stderr: error.stderr || "",
        code: typeof error.code === "number" ? error.code : 1
      };
    }
    throw error;
  }
}

async function walkFiles(rootDir) {
  const results = [];
  const queue = [rootDir];

  while (queue.length) {
    const current = queue.pop();
    const entries = await fs.promises.readdir(current, { withFileTypes: true });

    for (const entry of entries) {
      const absolutePath = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") {
          continue;
        }
        queue.push(absolutePath);
      } else {
        results.push(absolutePath);
      }
    }
  }

  return results;
}

function parseTarEntries(tarListOutput) {
  const entries = [];
  const lines = String(tarListOutput || "").split(/\r?\n/).filter(Boolean);
  const tarEntryPattern = /^([\-dlhsbcp])\S*\s+\d+\/\d+\s+\d+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\s+(.*)$/;

  for (const line of lines) {
    const match = line.match(tarEntryPattern);
    if (!match) {
      throw new Error(`Unable to parse tar metadata entry: ${line}`);
    }

    const rawPath = match[2].replace(/ -> .+$/, "");
    entries.push({
      type: match[1],
      rawPath
    });
  }

  return entries;
}

function isSafeArchivePath(rawPath) {
  const normalized = path.posix.normalize(String(rawPath || ""));
  if (!normalized || normalized === "." || normalized.startsWith("/") || normalized.includes("\\")) {
    return false;
  }

  if (normalized === "package") {
    return true;
  }

  return normalized.startsWith("package/") && !normalized.includes("../");
}

async function validateTarballContents(tarballPath) {
  const listed = await runCommand("tar", ["-tvzf", tarballPath, "--full-time", "--numeric-owner"], {
    timeout: 120000,
    maxBuffer: 20 * 1024 * 1024,
    env: {
      LC_ALL: "C"
    }
  });
  const entries = parseTarEntries(listed.stdout);

  if (!entries.length) {
    throw new Error("Package tarball was empty.");
  }

  if (entries.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error(`Package tarball exceeds the safe file-count limit (${MAX_ARCHIVE_ENTRIES}).`);
  }

  for (const entry of entries) {
    if (!isSafeArchivePath(entry.rawPath)) {
      throw new Error(`Package tarball contains an unsafe path: ${entry.rawPath}`);
    }

    if (!["-", "d"].includes(entry.type)) {
      throw new Error(`Package tarball contains an unsupported archive entry: ${entry.rawPath}`);
    }
  }
}

function getLineNumber(text, index) {
  return text.slice(0, index).split("\n").length;
}

function parseAuditJson(auditJson) {
  const results = [];

  try {
    const parsed = JSON.parse(auditJson || "{}");

    if (parsed.vulnerabilities && typeof parsed.vulnerabilities === "object") {
      for (const [name, details] of Object.entries(parsed.vulnerabilities)) {
        const via = Array.isArray(details.via) ? details.via : [];
        const advisories = via.map((item) => typeof item === "string" ? { title: item } : item).filter(Boolean);
        results.push({
          package: name,
          severity: details.severity || "info",
          title: advisories[0] && advisories[0].title ? advisories[0].title : `npm audit reported a vulnerability in ${name}`,
          url: advisories[0] && advisories[0].url ? advisories[0].url : null,
          via: advisories
        });
      }
    }

    if (parsed.advisories && typeof parsed.advisories === "object") {
      for (const advisory of Object.values(parsed.advisories)) {
        results.push({
          package: advisory.module_name,
          severity: advisory.severity || "info",
          title: advisory.title,
          url: advisory.url || null,
          via: [advisory]
        });
      }
    }
  } catch (error) {
    return [];
  }

  return results;
}

async function scanSourceFiles(packageRoot, findings) {
  const dangerousPatterns = [];
  const permissionAnalysis = {
    executableFiles: [],
    worldWritableFiles: [],
    sensitivePackagedFiles: []
  };
  const files = await walkFiles(packageRoot);

  for (const filePath of files) {
    const relativePath = path.relative(packageRoot, filePath);
    const stats = await fs.promises.stat(filePath);
    const mode = stats.mode & 0o777;

    if ((mode & 0o111) && !/^bin[\\/]/.test(relativePath)) {
      permissionAnalysis.executableFiles.push({
        file: relativePath,
        mode: `0${mode.toString(8)}`
      });
    }

    if (mode & 0o002) {
      permissionAnalysis.worldWritableFiles.push({
        file: relativePath,
        mode: `0${mode.toString(8)}`
      });
    }

    if (/(^|\/)(\.env|\.npmrc|id_rsa|id_dsa|.*\.pem|.*\.key)$/i.test(relativePath)) {
      permissionAnalysis.sensitivePackagedFiles.push(relativePath);
    }

    if (!/\.(?:js|cjs|mjs|ts|tsx|json|sh)$/i.test(filePath) || stats.size > 1024 * 1024) {
      continue;
    }

    let text;
    try {
      text = await fs.promises.readFile(filePath, "utf8");
    } catch (error) {
      continue;
    }

    for (const pattern of dangerousPatternCatalog) {
      if (pattern.gate && !pattern.gate.test(text)) {
        continue;
      }

      const match = text.match(pattern.regex);
      if (!match || typeof match.index !== "number") {
        continue;
      }

      dangerousPatterns.push({
        id: pattern.id,
        file: relativePath,
        line: getLineNumber(text, match.index),
        description: pattern.description
      });

      findings.push(createFinding({
        source: "package-scanner",
        severity: pattern.severity,
        confidence: "medium",
        cwe: pattern.cwe,
        location: `${relativePath}:${getLineNumber(text, match.index)}`,
        description: `${pattern.description} (${relativePath}:${getLineNumber(text, match.index)}).`,
        remediation: pattern.remediation
      }));
    }
  }

  if (permissionAnalysis.worldWritableFiles.length) {
    findings.push(createFinding({
      source: "package-scanner",
      severity: "medium",
      confidence: "medium",
      cwe: "permission_misconfiguration",
      description: "Packaged files include world-writable permission bits.",
      remediation: "Ship package artifacts with the minimum required file permissions."
    }));
  }

  if (permissionAnalysis.sensitivePackagedFiles.length) {
    findings.push(createFinding({
      source: "package-scanner",
      severity: "high",
      confidence: "high",
      cwe: "secret_leakage",
      description: "Package tarball appears to include sensitive credential-like files.",
      remediation: "Exclude secrets, private keys, and environment files from the published npm package."
    }));
  }

  return {
    dangerousPatterns,
    permissionAnalysis
  };
}

async function scanPackage(packageName) {
  const findings = [];
  const normalizedPackageName = normalizePackageSpecifier(packageName);
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "mcp-package-scan-"));
  const extractRoot = path.join(tempRoot, "extract");
  await fs.promises.mkdir(extractRoot, { recursive: true });

  try {
    const npmEnv = await buildNpmScanEnvironment(tempRoot);
    const metadataResult = await runCommand("npm", [
      "view",
      normalizedPackageName,
      "name",
      "version",
      "description",
      "repository",
      "dist",
      "bin",
      "scripts",
      "--json"
    ], {
      cwd: tempRoot,
      timeout: 30000,
      env: npmEnv
    });
    const metadata = JSON.parse(metadataResult.stdout || "{}");

    await fs.promises.writeFile(
      path.join(tempRoot, "package.json"),
      JSON.stringify({ name: "agent-security-scan-temp", private: true }, null, 2),
      "utf8"
    );

    await runCommand("npm", ["install", "--ignore-scripts", "--package-lock-only", normalizedPackageName], {
      cwd: tempRoot,
      timeout: 120000,
      env: npmEnv
    });

    const auditResult = await runCommand("npm", ["audit", "--json"], {
      cwd: tempRoot,
      timeout: 120000,
      env: npmEnv,
      allowFailure: true
    });
    const dependencyVulns = parseAuditJson(auditResult.stdout);

    for (const vuln of dependencyVulns) {
      findings.push(createFinding({
        source: "package-scanner",
        severity: vuln.severity,
        confidence: "medium",
        cwe: "package_vulnerability",
        location: vuln.package,
        description: `${vuln.package}: ${vuln.title}`,
        remediation: "Upgrade or replace the vulnerable dependency and rerun npm audit until the issue is resolved.",
        metadata: {
          url: vuln.url
        }
      }));
    }

    const packResult = await runCommand("npm", ["pack", normalizedPackageName, "--json"], {
      cwd: tempRoot,
      timeout: 120000,
      env: npmEnv
    });
    const packInfo = JSON.parse(packResult.stdout || "[]");
    const primaryPackEntry = Array.isArray(packInfo) ? packInfo[0] : null;
    const tarballName = primaryPackEntry && primaryPackEntry.filename ? primaryPackEntry.filename : null;

    if (!tarballName) {
      throw new Error("npm pack did not return a tarball filename.");
    }

    if (
      (typeof primaryPackEntry.size === "number" && primaryPackEntry.size > MAX_TARBALL_BYTES) ||
      (typeof primaryPackEntry.unpackedSize === "number" && primaryPackEntry.unpackedSize > MAX_UNPACKED_BYTES)
    ) {
      throw new Error("Package tarball exceeds the safe scan size limits.");
    }

    await validateTarballContents(path.join(tempRoot, tarballName));
    await runCommand("tar", ["-xzf", path.join(tempRoot, tarballName), "-C", extractRoot], {
      cwd: tempRoot,
      timeout: 120000
    });

    const packageRoot = path.join(extractRoot, "package");
    const sourceScan = await scanSourceFiles(packageRoot, findings);
    const permissionAnalysis = {
      ...sourceScan.permissionAnalysis,
      installScripts: Object.fromEntries(
        Object.entries(metadata.scripts || {}).filter(([scriptName]) => /^(preinstall|install|postinstall|prepare)$/i.test(scriptName))
      )
    };

    if (Object.keys(permissionAnalysis.installScripts).length) {
      findings.push(createFinding({
        source: "package-scanner",
        severity: "medium",
        confidence: "high",
        cwe: "package_vulnerability",
        description: "Package defines install-time scripts that execute during dependency installation.",
        remediation: "Review install scripts closely and avoid automatic execution in high-trust environments."
      }));
    }

    return {
      package_metadata: metadata,
      dependency_vulns: dependencyVulns,
      dangerous_patterns: sourceScan.dangerousPatterns,
      permission_analysis: permissionAnalysis,
      findings: dedupeFindings(findings)
    };
  } catch (error) {
    findings.push(createFinding({
      source: "package-scanner",
      severity: "high",
      confidence: "high",
      cwe: "package_vulnerability",
      description: `Package scan failed for "${packageName}".`,
      remediation: "Verify npm access for the package and rerun the scan with a reachable registry."
    }));

    return {
      package_metadata: {},
      dependency_vulns: [],
      dangerous_patterns: [],
      permission_analysis: {},
      findings: dedupeFindings(findings)
    };
  } finally {
    await fs.promises.rm(tempRoot, { recursive: true, force: true });
  }
}

module.exports = {
  scanPackage,
  normalizePackageSpecifier,
  parseTarEntries,
  testOnly: {
    buildNpmScanEnvironment,
    buildBaseCommandEnvironment,
    resolveNpmRegistry
  }
};
