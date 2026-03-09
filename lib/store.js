const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");

let uuidv4 = () => crypto.randomUUID();
try {
  uuidv4 = require("uuid").v4;
} catch (error) {
  uuidv4 = () => crypto.randomUUID();
}

function getDefaultStateDirectory() {
  if (process.platform === "win32") {
    const baseDir = process.env.LOCALAPPDATA || process.env.APPDATA;
    if (baseDir) {
      return path.join(baseDir, "mcp-server-agent-security");
    }
  }

  if (process.platform === "darwin" && process.env.HOME) {
    return path.join(process.env.HOME, "Library", "Application Support", "mcp-server-agent-security");
  }

  if (process.env.XDG_STATE_HOME) {
    return path.join(process.env.XDG_STATE_HOME, "mcp-server-agent-security");
  }

  if (process.env.HOME) {
    return path.join(process.env.HOME, ".local", "state", "mcp-server-agent-security");
  }

  return path.join(os.tmpdir(), "mcp-server-agent-security");
}

const dbPath = process.env.AGENT_SECURITY_DB_PATH
  ? path.resolve(process.env.AGENT_SECURITY_DB_PATH)
  : path.join(getDefaultStateDirectory(), "state.sqlite");
let db;

function ensureDatabase() {
  if (db) {
    return db;
  }

  fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  db = new Database(dbPath);
  try {
    fs.chmodSync(path.dirname(dbPath), 0o700);
    fs.chmodSync(dbPath, 0o600);
  } catch (error) {
    // Best-effort permission tightening only.
  }
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.exec(`
    CREATE TABLE IF NOT EXISTS audits (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      target TEXT,
      status TEXT NOT NULL,
      score INTEGER,
      grade TEXT,
      findings TEXT NOT NULL,
      created_at TEXT NOT NULL,
      completed_at TEXT
    )
  `);
  return db;
}

function serializeFindingsPayload(payload) {
  try {
    return JSON.stringify(payload || { findings: [] });
  } catch (error) {
    return JSON.stringify({
      findings: [],
      serializationError: "Failed to serialize findings payload."
    });
  }
}

function parseFindingsPayload(value) {
  try {
    return value ? JSON.parse(value) : { findings: [] };
  } catch (error) {
    return {
      findings: [],
      parseError: "Failed to parse findings payload."
    };
  }
}

function hydrateAudit(row) {
  if (!row) {
    return null;
  }

  const payload = parseFindingsPayload(row.findings);
  return {
    id: row.id,
    type: row.type,
    target: row.target,
    status: row.status,
    score: row.score,
    grade: row.grade,
    created_at: row.created_at,
    completed_at: row.completed_at,
    ...payload,
    findings: Array.isArray(payload.findings) ? payload.findings : []
  };
}

function createAudit(input) {
  const database = ensureDatabase();
  const audit = {
    id: input && input.id ? input.id : uuidv4(),
    type: input && input.type ? input.type : "unknown",
    target: input && input.target ? input.target : "",
    status: input && input.status ? input.status : "pending",
    score: typeof (input && input.score) === "number" ? input.score : null,
    grade: input && input.grade ? input.grade : null,
    findings: input && input.findings ? input.findings : { findings: [] },
    created_at: input && input.created_at ? input.created_at : new Date().toISOString(),
    completed_at: input && input.completed_at ? input.completed_at : null
  };

  database.prepare(`
    INSERT INTO audits (id, type, target, status, score, grade, findings, created_at, completed_at)
    VALUES (@id, @type, @target, @status, @score, @grade, @findings, @created_at, @completed_at)
  `).run({
    ...audit,
    findings: serializeFindingsPayload(audit.findings)
  });

  return getAudit(audit.id);
}

function updateAudit(id, updates) {
  const database = ensureDatabase();
  const existing = getAudit(id);

  if (!existing) {
    return null;
  }

  const patch = {
    type: updates && updates.type ? updates.type : existing.type,
    target: updates && Object.prototype.hasOwnProperty.call(updates, "target") ? updates.target : existing.target,
    status: updates && updates.status ? updates.status : existing.status,
    score: typeof (updates && updates.score) === "number" ? updates.score : existing.score,
    grade: updates && Object.prototype.hasOwnProperty.call(updates, "grade") ? updates.grade : existing.grade,
    findings: updates && Object.prototype.hasOwnProperty.call(updates, "findings")
      ? updates.findings
      : {
          findings: existing.findings,
          findingsSummary: existing.findingsSummary,
          executiveSummary: existing.executiveSummary,
          generatedAt: existing.generatedAt
        },
    completed_at: updates && Object.prototype.hasOwnProperty.call(updates, "completed_at")
      ? updates.completed_at
      : ["completed", "failed"].includes((updates && updates.status) || existing.status)
        ? new Date().toISOString()
        : existing.completed_at
  };

  database.prepare(`
    UPDATE audits
    SET type = @type,
        target = @target,
        status = @status,
        score = @score,
        grade = @grade,
        findings = @findings,
        completed_at = @completed_at
    WHERE id = @id
  `).run({
    id,
    ...patch,
    findings: serializeFindingsPayload(patch.findings)
  });

  return getAudit(id);
}

function getAudit(id) {
  const database = ensureDatabase();
  const row = database.prepare("SELECT * FROM audits WHERE id = ?").get(id);
  return hydrateAudit(row);
}

function listAudits(limit) {
  const database = ensureDatabase();
  const safeLimit = Number.isInteger(limit) && limit > 0 ? limit : 50;
  const rows = database.prepare("SELECT * FROM audits ORDER BY created_at DESC LIMIT ?").all(safeLimit);
  return rows.map(hydrateAudit);
}

module.exports = {
  createAudit,
  updateAudit,
  getAudit,
  listAudits,
  ensureDatabase
};
