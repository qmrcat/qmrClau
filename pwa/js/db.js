/**
 * db.js - qmrClau database structure utilities
 * Handles hierarchical group/entry tree, password generation, CSV, etc.
 */

// ===== UUID =====

function uuidv4() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

// ===== FACTORY FUNCTIONS =====

/**
 * Create a new entry object with a UUID.
 * @param {Object} fields  - { title, username, password, url, notes }
 */
export function makeEntry(fields = {}) {
  const now = new Date().toISOString();
  return {
    id:       uuidv4(),
    title:    fields.title    || '',
    username: fields.username || '',
    password: fields.password || '',
    url:      fields.url      || '',
    notes:    fields.notes    || '',
    created:  fields.created  || now,
    modified: fields.modified || now,
  };
}

/**
 * Create a new group object with a UUID.
 * @param {string} name
 * @param {Array}  entries
 * @param {Array}  children
 */
export function makeGroup(name, entries = [], children = []) {
  return {
    id:       uuidv4(),
    name:     name,
    entries:  entries,
    children: children,
  };
}

// ===== DATABASE CREATION =====

/**
 * Create an empty database matching Python's _new_db_data().
 */
export function createEmptyDB() {
  const now = new Date().toISOString();
  return {
    root: makeGroup('Arrel', [], [
      makeGroup('General'),
      makeGroup('Correu electrònic'),
      makeGroup('Xarxes socials'),
      makeGroup('Banca'),
    ]),
    meta: {
      created:  now,
      modified: now,
      version:  3,
    },
  };
}

// ===== MIGRATION =====

/**
 * Migrate v2 flat structure to v3 hierarchical structure.
 * Matches Python's _migrate_v2_to_v3().
 */
export function migrateV2toV3(data) {
  const oldGroups = data.groups || [];
  let children = oldGroups.map(g => makeGroup(g.name || 'Sense nom', g.entries || []));
  if (children.length === 0) {
    children = [makeGroup('General')];
  }
  return {
    root: makeGroup('Arrel', [], children),
    meta: data.meta || {},
  };
}

// ===== TREE TRAVERSAL =====

/**
 * Find a group by id in the tree. Returns the group node or null.
 */
export function findGroupById(root, id) {
  if (root.id === id) return root;
  for (const child of (root.children || [])) {
    const found = findGroupById(child, id);
    if (found) return found;
  }
  return null;
}

/**
 * Find the parent group of the node with the given id.
 */
export function findParentOf(root, id) {
  for (const child of (root.children || [])) {
    if (child.id === id) return root;
    const found = findParentOf(child, id);
    if (found) return found;
  }
  return null;
}

/**
 * Get the path from root to a group as array of names.
 * e.g. ['Arrel', 'Feina', 'Servidors']
 */
export function getGroupPath(root, id, _path = []) {
  const path = [..._path, root.name];
  if (root.id === id) return path;
  for (const child of (root.children || [])) {
    const result = getGroupPath(child, id, path);
    if (result) return result;
  }
  return null;
}

/**
 * Collect all entries in the subtree rooted at node.
 * Returns array of { entry, group, path } where path is array of names.
 */
export function collectAllEntries(node, _path = []) {
  const path = [..._path, node.name];
  const results = [];
  for (const entry of (node.entries || [])) {
    results.push({ entry, group: node, path });
  }
  for (const child of (node.children || [])) {
    results.push(...collectAllEntries(child, path));
  }
  return results;
}

/**
 * Remove an entry from anywhere in the tree.
 * Returns true if removed.
 */
export function removeEntryFromTree(root, entryId) {
  const entries = root.entries || [];
  const idx = entries.findIndex(e => e.id === entryId);
  if (idx !== -1) {
    entries.splice(idx, 1);
    return true;
  }
  for (const child of (root.children || [])) {
    if (removeEntryFromTree(child, entryId)) return true;
  }
  return false;
}

/**
 * Get all IDs in a subtree (group + all descendants).
 */
export function getDescendantIds(group) {
  const ids = new Set([group.id]);
  for (const child of (group.children || [])) {
    for (const id of getDescendantIds(child)) ids.add(id);
  }
  return ids;
}

// ===== PASSWORD GENERATOR =====

const UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER   = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS  = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

/**
 * Generate a cryptographically random password.
 * Matches Python's generate_password().
 */
export function generatePassword(len = 20, upper = true, lower = true, digits = true, symbols = true) {
  let chars = '';
  const required = [];

  if (upper)   { chars += UPPER;   required.push(_randomChar(UPPER)); }
  if (lower)   { chars += LOWER;   required.push(_randomChar(LOWER)); }
  if (digits)  { chars += DIGITS;  required.push(_randomChar(DIGITS)); }
  if (symbols) { chars += SYMBOLS; required.push(_randomChar(SYMBOLS)); }

  if (!chars) chars = UPPER + LOWER + DIGITS;

  const rest = Array.from({ length: Math.max(0, len - required.length) }, () => _randomChar(chars));
  const pwdArr = [...required, ...rest];

  // Fisher-Yates shuffle with crypto random
  for (let i = pwdArr.length - 1; i > 0; i--) {
    const j = _randomInt(i + 1);
    [pwdArr[i], pwdArr[j]] = [pwdArr[j], pwdArr[i]];
  }

  return pwdArr.join('');
}

function _randomInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

function _randomChar(str) {
  return str[_randomInt(str.length)];
}

// ===== PASSWORD STRENGTH =====

/**
 * Calculate password strength.
 * Matches Python's password_strength() exactly.
 * Returns { score: 0-100, label: string, color: string }
 */
export function passwordStrength(pwd) {
  if (!pwd) return { score: 0, label: 'Sense contrasenya', color: '#6c7086' };

  let score = 0;
  const l = pwd.length;

  if (l >= 8)  score += 15;
  if (l >= 12) score += 15;
  if (l >= 16) score += 10;
  if (l >= 20) score += 10;

  if (/[A-Z]/.test(pwd))                              score += 10;
  if (/[a-z]/.test(pwd))                              score += 10;
  if (/[0-9]/.test(pwd))                              score += 10;
  if (/[!@#$%^&*()\-_=+[\]{}|;:,.<>?/~`]/.test(pwd)) score += 10;

  const unique = new Set(pwd).size;
  if (unique > 6)  score += 5;
  if (unique > 10) score += 5;

  score = Math.min(100, score);

  let label, color;
  if (score < 30) {
    label = 'Molt feble'; color = '#ff6b6b';
  } else if (score < 50) {
    label = 'Feble'; color = '#ff6b6b';
  } else if (score < 70) {
    label = 'Acceptable'; color = '#ffe66d';
  } else if (score < 90) {
    label = 'Forta'; color = '#4ecdc4';
  } else {
    label = 'Molt forta'; color = '#4ecdc4';
  }

  return { score, label, color };
}

// ===== CSV EXPORT =====

/**
 * Export database to CSV string.
 * Matches Python's _collect_entries_for_export() — path starts with "Arrel".
 * Headers: Grup,Títol,Usuari,Contrasenya,URL,Notes
 */
export function exportToCSV(data) {
  const rows = [['Grup', 'Títol', 'Usuari', 'Contrasenya', 'URL', 'Notes']];
  _collectForExport(data.root, '', rows);
  return rows.map(row => row.map(_csvEscape).join(',')).join('\r\n');
}

function _collectForExport(group, parentPath, rows) {
  const path = parentPath ? `${parentPath}/${group.name}` : group.name;
  for (const entry of (group.entries || [])) {
    rows.push([
      path,
      entry.title    || '',
      entry.username || '',
      entry.password || '',
      entry.url      || '',
      entry.notes    || '',
    ]);
  }
  for (const child of (group.children || [])) {
    _collectForExport(child, path, rows);
  }
}

function _csvEscape(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

// ===== CSV IMPORT =====

/**
 * Import from CSV text into data.
 * Detects columns in Catalan and English.
 * Returns the count of imported entries.
 *
 * Matches Python's _find_or_create_group_path() — skips root name if it's
 * "arrel" or "root" as first path component.
 */
export function importFromCSV(data, csvText) {
  const rows = _parseCSV(csvText);
  if (rows.length < 2) return 0;

  const headers = rows[0];
  const col = _detectColumns(headers);

  if (col.title === -1) return -1; // signal: no title column

  const now = new Date().toISOString();
  let imported = 0;

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const title = (col.title >= 0 ? row[col.title] : '').trim();
    if (!title) continue;

    const groupPath = col.group >= 0 ? (row[col.group] || '') : '';
    const group = _findOrCreateGroupPath(data, groupPath);

    if (!group.entries) group.entries = [];
    group.entries.push(makeEntry({
      title,
      username: col.username >= 0 ? (row[col.username] || '').trim() : '',
      password: col.password >= 0 ? (row[col.password] || '')         : '',
      url:      col.url      >= 0 ? (row[col.url]      || '').trim() : '',
      notes:    col.notes    >= 0 ? (row[col.notes]    || '').trim() : '',
      created:  now,
      modified: now,
    }));
    imported++;
  }

  return imported;
}

function _detectColumns(headers) {
  const col = { group: -1, title: -1, username: -1, password: -1, url: -1, notes: -1 };
  for (let i = 0; i < headers.length; i++) {
    const k = headers[i].toLowerCase().trim();
    if      (['grup','group','folder','carpeta'].includes(k))              col.group    = i;
    else if (['títol','titol','title','name','nom'].includes(k))           col.title    = i;
    else if (['usuari','username','user','login'].includes(k))             col.username = i;
    else if (['contrasenya','password','pass'].includes(k))               col.password = i;
    else if (['url','website','web'].includes(k))                          col.url      = i;
    else if (['notes','nota','note','comentari'].includes(k))              col.notes    = i;
  }
  return col;
}

function _findOrCreateGroupPath(data, pathStr) {
  if (!pathStr || !pathStr.trim()) {
    const ch = data.root.children || [];
    return ch.length ? ch[0] : data.root;
  }

  const parts = pathStr.replace(/\\/g, '/').split('/').map(p => p.trim()).filter(Boolean);

  // Skip root node name (matches Python: if parts[0].lower() in ("arrel","root"))
  if (parts.length && ['arrel', 'root'].includes(parts[0].toLowerCase())) {
    parts.shift();
  }

  if (!parts.length) {
    const ch = data.root.children || [];
    return ch.length ? ch[0] : data.root;
  }

  let current = data.root;
  for (const part of parts) {
    let found = (current.children || []).find(c => c.name.toLowerCase() === part.toLowerCase());
    if (!found) {
      found = makeGroup(part);
      if (!current.children) current.children = [];
      current.children.push(found);
    }
    current = found;
  }
  return current;
}

/**
 * Simple CSV parser (handles quoted fields, CRLF and LF).
 * Returns array of rows, each row is array of strings.
 */
function _parseCSV(text) {
  const rows = [];
  // Remove BOM if present
  const t = text.startsWith('\uFEFF') ? text.slice(1) : text;
  const lines = t.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');

  for (const line of lines) {
    if (!line.trim()) continue;
    rows.push(_parseCSVRow(line));
  }
  return rows;
}

function _parseCSVRow(line) {
  const fields = [];
  let i = 0;
  while (i <= line.length) {
    if (i === line.length) { fields.push(''); break; }
    if (line[i] === '"') {
      // Quoted field
      let val = '';
      i++;
      while (i < line.length) {
        if (line[i] === '"') {
          if (line[i+1] === '"') { val += '"'; i += 2; }
          else { i++; break; }
        } else {
          val += line[i++];
        }
      }
      fields.push(val);
      if (i < line.length && line[i] === ',') i++;
    } else {
      // Unquoted field
      const end = line.indexOf(',', i);
      if (end === -1) {
        fields.push(line.slice(i));
        break;
      } else {
        fields.push(line.slice(i, end));
        i = end + 1;
      }
    }
  }
  return fields;
}
