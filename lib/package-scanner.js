const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");
const { createFinding, dedupeFindings } = require("./findings");

const execFileAsync = promisify(execFile);

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

async function runCommand(command, args, options) {
  try {
    const result = await execFileAsync(command, args, {
      cwd: options && options.cwd ? options.cwd : undefined,
      env: options && options.env ? options.env : process.env,
      timeout: options && options.timeout ? options.timeout : 120000,
      maxBuffer: 10 * 1024 * 1024
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
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "mcp-package-scan-"));
  const extractRoot = path.join(tempRoot, "extract");
  await fs.promises.mkdir(extractRoot, { recursive: true });

  try {
    const metadataResult = await runCommand("npm", ["view", packageName, "--json"], {
      cwd: tempRoot,
      timeout: 30000
    });
    const metadata = JSON.parse(metadataResult.stdout || "{}");

    await fs.promises.writeFile(
      path.join(tempRoot, "package.json"),
      JSON.stringify({ name: "agent-security-scan-temp", private: true }, null, 2),
      "utf8"
    );

    await runCommand("npm", ["install", "--ignore-scripts", "--package-lock-only", packageName], {
      cwd: tempRoot,
      timeout: 120000
    });

    const auditResult = await runCommand("npm", ["audit", "--json"], {
      cwd: tempRoot,
      timeout: 120000,
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

    const packResult = await runCommand("npm", ["pack", packageName, "--json"], {
      cwd: tempRoot,
      timeout: 120000
    });
    const packInfo = JSON.parse(packResult.stdout || "[]");
    const tarballName = Array.isArray(packInfo) && packInfo[0] && packInfo[0].filename ? packInfo[0].filename : null;

    if (!tarballName) {
      throw new Error("npm pack did not return a tarball filename.");
    }

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
      description: `Package scan failed for "${packageName}": ${error.message}`,
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
  scanPackage
};
