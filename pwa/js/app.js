/**
 * app.js - qmrClau PWA Main Application
 */
import { encryptDB, decryptDB } from './crypto.js';
import {
  createEmptyDB, migrateV2toV3, findGroupById, findParentOf,
  getGroupPath, collectAllEntries, removeEntryFromTree,
  generatePassword, passwordStrength, exportToCSV, importFromCSV,
  makeEntry, makeGroup, getDescendantIds,
} from './db.js';

// ===== APPLICATION STATE =====

const state = {
  data:           null,
  password:       null,
  fileHandle:     null,
  fileName:       null,
  unsaved:        false,
  currentGroupId: null,
  expandedGroups: new Set(),
  searchQuery:    '',
  clipboardTimer: null,
  clipboardTimerEnd: null,
};

// ===== DOM REFS =====

const $ = id => document.getElementById(id);

// ===== INIT =====

document.addEventListener('DOMContentLoaded', () => {
  showWelcome();

  // Welcome buttons
  $('btn-create').addEventListener('click', createNewDB);
  $('btn-open').addEventListener('click', openFile);

  // Toolbar buttons
  $('btn-save').addEventListener('click', saveFile);
  $('btn-generator').addEventListener('click', () => dlgGenerator());
  $('btn-export').addEventListener('click', exportCSV);
  $('btn-import').addEventListener('click', importCSV);
  $('btn-lock').addEventListener('click', lockApp);
  $('btn-hamburger').addEventListener('click', toggleSidebar);
  $('sidebar-overlay').addEventListener('click', closeSidebar);

  // Search
  $('search-input').addEventListener('input', e => {
    state.searchQuery = e.target.value.trim();
    renderCurrentView();
  });
  $('search-input').addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      $('search-input').value = '';
      state.searchQuery = '';
      renderCurrentView();
    }
  });

  // Add entry button
  $('btn-add-entry').addEventListener('click', () => addEntry());

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey) {
      if (e.key === 's') { e.preventDefault(); saveFile(); }
      if (e.key === 'f') { e.preventDefault(); $('search-input').focus(); }
    }
  });

  window.addEventListener('beforeunload', e => {
    if (state.unsaved) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
});

// ===== SCREENS =====

function showWelcome() {
  $('screen-welcome').hidden = false;
  $('screen-main').hidden = true;
}

function showMain() {
  $('screen-welcome').hidden = true;
  $('screen-main').hidden = false;
  updateTitle();
  renderTree();
  renderCurrentView();
}

// ===== FILE I/O =====

async function openFile() {
  let file = null;
  let handle = null;

  if (window.showOpenFilePicker) {
    try {
      const [h] = await window.showOpenFilePicker({
        types: [{
          description: 'qmrClau Database',
          accept: { 'application/octet-stream': ['.vkdb'] },
        }],
        multiple: false,
      });
      handle = h;
      file = await h.getFile();
    } catch (e) {
      if (e.name === 'AbortError') return;
      // Fallback
      file = await pickFileViaInput('.vkdb');
    }
  } else {
    file = await pickFileViaInput('.vkdb');
  }

  if (!file) return;

  const password = await dlgPassword('Obre la base de dades', `Introdueix la contrasenya per a "${file.name}"`);
  if (password === null) return;

  try {
    const buffer = await file.arrayBuffer();
    const { data, ver } = await decryptDB(buffer, password);

    let dbData = data;
    // Migrate if needed
    if (ver <= 2 || ('groups' in dbData && Array.isArray(dbData.groups))) {
      dbData = migrateV2toV3(dbData);
      showToast('Base de dades migrada a la versió 3', 'success');
    }

    state.data           = dbData;
    state.password       = password;
    state.fileHandle     = handle;
    state.fileName       = file.name;
    state.unsaved        = false;
    state.currentGroupId = dbData.root.children[0]?.id ?? dbData.root.id;
    state.expandedGroups = new Set([dbData.root.id]);
    state.searchQuery    = '';

    showMain();
    showToast(`"${file.name}" obert correctament`, 'success');
  } catch (e) {
    await dlgAlert('Error en obrir: ' + e.message);
  }
}

async function createNewDB() {
  const fileName = await dlgText('Nova base de dades', 'Nom del fitxer (sense extensió)', 'meves-claus');
  if (!fileName) return;

  const password = await dlgPasswordCreate('Crea la contrasenya mestra');
  if (!password) return;

  const dbData   = createEmptyDB();
  const name     = fileName.endsWith('.vkdb') ? fileName : fileName + '.vkdb';

  state.data           = dbData;
  state.password       = password;
  state.fileHandle     = null;
  state.fileName       = name;
  state.unsaved        = true;
  state.currentGroupId = dbData.root.children[0]?.id ?? dbData.root.id;
  state.expandedGroups = new Set([dbData.root.id]);
  state.searchQuery    = '';

  showMain();

  // Try to save immediately
  await saveFile(true);
}

async function saveFile(silent = false) {
  if (!state.data) return;

  try {
    const encrypted = await encryptDB(state.data, state.password);
    const blob = new Blob([encrypted], { type: 'application/octet-stream' });

    if (state.fileHandle && state.fileHandle.createWritable) {
      // File System Access API
      try {
        const writable = await state.fileHandle.createWritable();
        await writable.write(blob);
        await writable.close();
        state.unsaved = false;
        updateTitle();
        if (!silent) showToast('Desat correctament', 'success');
        return;
      } catch (e) {
        // permission might have been revoked, fall through
      }
    }

    if (window.showSaveFilePicker) {
      try {
        const handle = await window.showSaveFilePicker({
          suggestedName: state.fileName || 'database.vkdb',
          types: [{
            description: 'qmrClau Database',
            accept: { 'application/octet-stream': ['.vkdb'] },
          }],
        });
        state.fileHandle = handle;
        state.fileName   = handle.name;
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
        state.unsaved = false;
        updateTitle();
        if (!silent) showToast('Desat correctament', 'success');
        return;
      } catch (e) {
        if (e.name === 'AbortError') return;
        // Fall through to download
      }
    }

    // Fallback: download
    _downloadBlob(blob, state.fileName || 'database.vkdb');
    state.unsaved = false;
    updateTitle();
    showToast('Fitxer descarregat', 'success');
  } catch (e) {
    await dlgAlert('Error en desar: ' + e.message);
  }
}

function _downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function pickFileViaInput(accept) {
  return new Promise(resolve => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.onchange = () => resolve(input.files[0] || null);
    input.oncancel = () => resolve(null);
    input.click();
  });
}

function lockApp() {
  if (state.unsaved) {
    dlgConfirm('Hi ha canvis no desats. Vols tancar igualment?').then(ok => {
      if (ok) _doLock();
    });
  } else {
    _doLock();
  }
}

function _doLock() {
  state.data           = null;
  state.password       = null;
  state.fileHandle     = null;
  state.fileName       = null;
  state.unsaved        = false;
  state.currentGroupId = null;
  state.expandedGroups = new Set();
  state.searchQuery    = '';
  if (state.clipboardTimer) { clearTimeout(state.clipboardTimer); state.clipboardTimer = null; }
  showWelcome();
}

// ===== TITLE / HEADER =====

function updateTitle() {
  const dot = $('btn-save');
  if (state.unsaved) {
    dot.classList.add('has-unsaved');
    document.title = '* qmrClau' + (state.fileName ? ` — ${state.fileName}` : '');
  } else {
    dot.classList.remove('has-unsaved');
    document.title = 'qmrClau' + (state.fileName ? ` — ${state.fileName}` : '');
  }

  const fn = $('sidebar-filename');
  if (fn) fn.textContent = state.fileName || '';
}

function markUnsaved() {
  state.unsaved = true;
  updateTitle();
  // Update meta
  if (state.data?.meta) {
    state.data.meta.modified = new Date().toISOString();
  }
}

// ===== SIDEBAR MOBILE =====

function toggleSidebar() {
  const sidebar = $('sidebar');
  const overlay = $('sidebar-overlay');
  if (sidebar.classList.contains('open')) {
    closeSidebar();
  } else {
    sidebar.classList.add('open');
    overlay.classList.remove('hidden');
  }
}

function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('sidebar-overlay').classList.add('hidden');
}

// ===== GROUP TREE =====

function renderTree() {
  if (!state.data) return;
  const container = $('tree-container');
  container.innerHTML = '';
  _renderTreeNode(state.data.root, container, 0);
}

function _renderTreeNode(group, container, depth) {
  const hasChildren = (group.children || []).length > 0;
  const isExpanded  = state.expandedGroups.has(group.id);
  const isSelected  = group.id === state.currentGroupId;
  const isRoot      = depth === 0;

  const nodeEl = document.createElement('div');
  nodeEl.className = 'tree-node';

  const rowEl = document.createElement('div');
  rowEl.className = 'tree-row' + (isSelected ? ' selected' : '');
  rowEl.dataset.groupId = group.id;

  // Indentation
  if (depth > 0) {
    rowEl.style.paddingLeft = (depth * 16 + 8) + 'px';
  }

  // Toggle arrow
  const toggle = document.createElement('span');
  toggle.className = 'tree-toggle';
  toggle.textContent = hasChildren ? (isExpanded ? '▼' : '▶') : '';
  rowEl.appendChild(toggle);

  // Icon
  const icon = document.createElement('span');
  icon.className = 'tree-icon';
  icon.textContent = isRoot ? '🗄️' : '📁';
  rowEl.appendChild(icon);

  // Name
  const nameEl = document.createElement('span');
  nameEl.className = 'tree-name';
  nameEl.textContent = group.name;
  rowEl.appendChild(nameEl);

  // Count badge
  const count = _countEntries(group);
  if (count > 0) {
    const countEl = document.createElement('span');
    countEl.className = 'tree-count';
    countEl.textContent = count;
    rowEl.appendChild(countEl);
  }

  // Action buttons
  const actionsEl = document.createElement('div');
  actionsEl.className = 'tree-actions';

  // Add subgroup
  const addBtn = document.createElement('button');
  addBtn.className = 'tree-action-btn';
  addBtn.title = 'Afegeix subgrup';
  addBtn.textContent = '+';
  addBtn.addEventListener('click', e => { e.stopPropagation(); addSubgroup(group.id); });
  actionsEl.appendChild(addBtn);

  // Rename (not root)
  if (!isRoot) {
    const renameBtn = document.createElement('button');
    renameBtn.className = 'tree-action-btn';
    renameBtn.title = 'Reanomena';
    renameBtn.textContent = '✏️';
    renameBtn.addEventListener('click', e => { e.stopPropagation(); renameGroup(group.id); });
    actionsEl.appendChild(renameBtn);

    // Delete
    const delBtn = document.createElement('button');
    delBtn.className = 'tree-action-btn';
    delBtn.title = 'Esborra';
    delBtn.textContent = '🗑️';
    delBtn.addEventListener('click', e => { e.stopPropagation(); deleteGroup(group.id); });
    actionsEl.appendChild(delBtn);
  }

  rowEl.appendChild(actionsEl);

  // Click: select group
  rowEl.addEventListener('click', () => {
    if (hasChildren) {
      if (isExpanded) state.expandedGroups.delete(group.id);
      else state.expandedGroups.add(group.id);
    }
    state.currentGroupId = group.id;
    state.searchQuery    = '';
    $('search-input').value = '';
    renderTree();
    renderCurrentView();
    closeSidebar();
  });

  nodeEl.appendChild(rowEl);

  // Children
  if (hasChildren) {
    const childrenEl = document.createElement('div');
    childrenEl.className = 'tree-children' + (isExpanded ? '' : ' collapsed');
    for (const child of (group.children || [])) {
      _renderTreeNode(child, childrenEl, depth + 1);
    }
    nodeEl.appendChild(childrenEl);
  }

  container.appendChild(nodeEl);
}

function _countEntries(group) {
  let n = (group.entries || []).length;
  for (const c of (group.children || [])) n += _countEntries(c);
  return n;
}

// ===== GROUP ACTIONS =====

async function addSubgroup(parentId) {
  const name = await dlgText('Nou subgrup', 'Nom del nou subgrup', '');
  if (!name) return;
  const parent = findGroupById(state.data.root, parentId);
  if (!parent) return;
  if (!parent.children) parent.children = [];
  const newGroup = makeGroup(name);
  parent.children.push(newGroup);
  state.expandedGroups.add(parentId);
  state.currentGroupId = newGroup.id;
  markUnsaved();
  renderTree();
  renderCurrentView();
}

async function renameGroup(groupId) {
  const group = findGroupById(state.data.root, groupId);
  if (!group) return;
  const name = await dlgText('Reanomena el grup', 'Nou nom', group.name);
  if (!name || name === group.name) return;
  group.name = name;
  markUnsaved();
  renderTree();
  renderCurrentView();
}

async function deleteGroup(groupId) {
  const group = findGroupById(state.data.root, groupId);
  if (!group) return;
  const count = _countEntries(group);
  const msg = count > 0
    ? `Vols esborrar el grup "${group.name}" i les seves ${count} entrades?`
    : `Vols esborrar el grup "${group.name}"?`;

  const ok = await dlgConfirm(msg);
  if (!ok) return;

  const parent = findParentOf(state.data.root, groupId);
  if (!parent) return;
  parent.children = parent.children.filter(c => c.id !== groupId);

  if (state.currentGroupId === groupId || _isDescendant(group, state.currentGroupId)) {
    state.currentGroupId = parent.id;
  }

  markUnsaved();
  renderTree();
  renderCurrentView();
}

function _isDescendant(group, id) {
  if (group.id === id) return true;
  return (group.children || []).some(c => _isDescendant(c, id));
}

// ===== CURRENT VIEW =====

function renderCurrentView() {
  if (state.searchQuery) {
    renderSearch();
  } else {
    renderEntries(state.currentGroupId);
  }
}

// ===== BREADCRUMB =====

function updateBreadcrumb(groupId) {
  const bc = $('breadcrumb');
  if (!groupId || !state.data) { bc.innerHTML = ''; return; }
  const path = getGroupPath(state.data.root, groupId);
  if (!path) { bc.innerHTML = ''; return; }
  bc.innerHTML = path.map((name, i) =>
    i < path.length - 1
      ? `<span style="color:var(--text-dim)">${_esc(name)}</span> <span style="color:var(--text-dim)">›</span> `
      : `<span>${_esc(name)}</span>`
  ).join('');
}

// ===== ENTRIES =====

function renderEntries(groupId) {
  const grid     = $('entries-grid');
  const header   = $('entries-header-title');
  const countEl  = $('entries-count');
  const addBtn   = $('btn-add-entry');

  grid.innerHTML = '';
  grid.style.gridTemplateColumns = '';
  updateBreadcrumb(groupId);

  if (!groupId || !state.data) {
    header.textContent = 'Selecciona un grup';
    countEl.textContent = '';
    addBtn.hidden = true;
    return;
  }

  const group = findGroupById(state.data.root, groupId);
  if (!group) {
    header.textContent = 'Grup no trobat';
    countEl.textContent = '';
    addBtn.hidden = true;
    return;
  }

  header.textContent = group.name;
  addBtn.hidden = false;
  addBtn.dataset.groupId = groupId;

  const entries = group.entries || [];
  countEl.textContent = entries.length ? `${entries.length} entrada${entries.length !== 1 ? 'es' : ''}` : '';

  if (entries.length === 0) {
    grid.innerHTML = `
      <div class="empty-state" style="grid-column:1/-1">
        <div class="empty-state-icon">🔑</div>
        <div class="empty-state-text">Cap entrada en aquest grup</div>
        <div class="empty-state-hint">Fes clic a "+ Afegeix entrada" per crear-ne una</div>
      </div>`;
    return;
  }

  for (const entry of entries) {
    grid.appendChild(_buildEntryCard(entry, groupId));
  }
}

function _buildEntryCard(entry, groupId) {
  const card = document.createElement('div');
  card.className = 'entry-card';
  card.tabIndex = 0;

  let metaHTML = '';
  if (entry.username) metaHTML += `<div class="entry-meta-line"><span>👤</span>${_esc(entry.username)}</div>`;
  if (entry.url)      metaHTML += `<div class="entry-meta-line"><span>🌐</span>${_esc(entry.url)}</div>`;
  if (entry.notes) {
    const preview = entry.notes.length > 60 ? entry.notes.slice(0, 60) + '…' : entry.notes;
    metaHTML += `<div class="entry-meta-line"><span>📝</span>${_esc(preview)}</div>`;
  }

  card.innerHTML = `
    <div class="entry-title">${_esc(entry.title || '(Sense títol)')}</div>
    <div class="entry-meta">${metaHTML || '<div class="entry-meta-line" style="color:var(--text-dim);font-style:italic">Sense detalls</div>'}</div>
    <div class="entry-actions">
      <button class="entry-btn btn-copy" title="Copia la contrasenya">📋 Copia</button>
      <button class="entry-btn btn-edit" title="Edita">✏️ Edita</button>
      <button class="entry-btn btn-move" title="Mou a un altre grup">📦 Mou</button>
      <button class="entry-btn btn-del danger" title="Esborra">🗑️ Esborra</button>
    </div>`;

  // Double-click to edit
  card.addEventListener('dblclick', () => editEntry(entry.id, groupId));
  card.addEventListener('keydown', e => { if (e.key === 'Enter') editEntry(entry.id, groupId); });

  card.querySelector('.btn-copy').addEventListener('click', e => {
    e.stopPropagation();
    copyPassword(entry.id, entry.password, card);
  });
  card.querySelector('.btn-edit').addEventListener('click', e => {
    e.stopPropagation();
    editEntry(entry.id, groupId);
  });
  card.querySelector('.btn-move').addEventListener('click', e => {
    e.stopPropagation();
    moveEntry(entry.id);
  });
  card.querySelector('.btn-del').addEventListener('click', e => {
    e.stopPropagation();
    deleteEntry(entry.id, groupId);
  });

  return card;
}

// ===== ENTRY ACTIONS =====

async function addEntry() {
  const groupId = state.currentGroupId;
  if (!groupId) return;
  const group = findGroupById(state.data.root, groupId);
  if (!group) return;

  const entry = await dlgEntry(null);
  if (!entry) return;

  if (!group.entries) group.entries = [];
  group.entries.push(entry);
  markUnsaved();
  renderTree();
  renderEntries(groupId);
}

async function editEntry(entryId, groupId) {
  const group = findGroupById(state.data.root, groupId);
  if (!group) return;
  const entry = (group.entries || []).find(e => e.id === entryId);
  if (!entry) return;

  const updated = await dlgEntry(entry);
  if (!updated) return;

  Object.assign(entry, updated, { id: entry.id, created: entry.created, modified: new Date().toISOString() });
  markUnsaved();
  renderTree();
  renderEntries(groupId);
}

async function deleteEntry(entryId, groupId) {
  const ok = await dlgConfirm('Vols esborrar aquesta entrada?');
  if (!ok) return;

  const group = findGroupById(state.data.root, groupId);
  if (!group) return;
  group.entries = (group.entries || []).filter(e => e.id !== entryId);
  markUnsaved();
  renderTree();
  renderEntries(groupId);
}

async function moveEntry(entryId) {
  // Find source group
  const allEntries = collectAllEntries(state.data.root);
  const found = allEntries.find(x => x.entry.id === entryId);
  if (!found) return;

  const destGroupId = await dlgMoveEntry(entryId, found.group.id);
  if (!destGroupId || destGroupId === found.group.id) return;

  const destGroup = findGroupById(state.data.root, destGroupId);
  if (!destGroup) return;

  // Remove from source
  found.group.entries = (found.group.entries || []).filter(e => e.id !== entryId);
  // Add to dest
  if (!destGroup.entries) destGroup.entries = [];
  destGroup.entries.push(found.entry);

  markUnsaved();
  renderTree();
  renderCurrentView();
  showToast('Entrada moguda', 'success');
}

// ===== CLIPBOARD =====

function copyPassword(entryId, password, cardEl) {
  if (!password) { showToast('Aquesta entrada no té contrasenya', 'warning'); return; }

  navigator.clipboard.writeText(password).then(() => {
    // Clear previous timer
    if (state.clipboardTimer) {
      clearTimeout(state.clipboardTimer);
      state.clipboardTimer = null;
      // Remove old timer UI
      document.querySelectorAll('.clipboard-timer').forEach(el => el.remove());
    }

    showToast('Contrasenya copiada (15 s)', 'success');

    // Show countdown in card
    const timerEl = document.createElement('div');
    timerEl.className = 'clipboard-timer';
    const actionsEl = cardEl?.querySelector('.entry-actions');
    if (actionsEl) actionsEl.after(timerEl);

    const endTime = Date.now() + 15000;
    state.clipboardTimerEnd = endTime;

    const tick = () => {
      const rem = Math.ceil((endTime - Date.now()) / 1000);
      if (rem <= 0) {
        timerEl.remove();
        navigator.clipboard.writeText('').catch(() => {});
        showToast('Porta-retalls esborrat', 'warning');
        return;
      }
      timerEl.textContent = `⏱️ Porta-retalls s'esborrarà en ${rem}s`;
      state.clipboardTimer = setTimeout(tick, 500);
    };
    tick();
  }).catch(() => {
    showToast("No s'ha pogut copiar al porta-retalls", 'danger');
  });
}

// ===== SEARCH =====

function renderSearch() {
  const grid    = $('entries-grid');
  const header  = $('entries-header-title');
  const countEl = $('entries-count');
  const addBtn  = $('btn-add-entry');

  grid.innerHTML = '';
  addBtn.hidden = true;
  updateBreadcrumb(null);

  const q = state.searchQuery.toLowerCase();
  const all = collectAllEntries(state.data.root);
  const results = all.filter(({ entry }) =>
    (entry.title    || '').toLowerCase().includes(q) ||
    (entry.username || '').toLowerCase().includes(q) ||
    (entry.url      || '').toLowerCase().includes(q) ||
    (entry.notes    || '').toLowerCase().includes(q)
  );

  header.textContent  = `Cerca: "${state.searchQuery}"`;
  countEl.textContent = `${results.length} resultat${results.length !== 1 ? 's' : ''}`;

  if (results.length === 0) {
    grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">
      <div class="empty-state-icon">🔍</div>
      <div class="empty-state-text">Cap resultat per a "${_esc(state.searchQuery)}"</div>
    </div>`;
    return;
  }

  // Show as full-width list
  grid.style.gridTemplateColumns = '1fr';

  for (const { entry, group, path } of results) {
    const card = document.createElement('div');
    card.className = 'search-result-card';

    const pathStr = path.join(' › ');
    let metaLine = '';
    if (entry.username) metaLine += `👤 ${_esc(entry.username)}  `;
    if (entry.url)      metaLine += `🌐 ${_esc(entry.url)}`;

    card.innerHTML = `
      <div class="search-result-path">${_esc(pathStr)}</div>
      <div class="entry-title">${_esc(entry.title || '(Sense títol)')}</div>
      ${metaLine ? `<div class="entry-meta-line">${metaLine}</div>` : ''}
      <div class="entry-actions" style="margin-top:8px">
        <button class="entry-btn btn-copy">📋 Copia</button>
        <button class="entry-btn btn-edit">✏️ Edita</button>
        <button class="entry-btn btn-goto">📂 Navega</button>
        <button class="entry-btn btn-del danger">🗑️ Esborra</button>
      </div>`;

    card.querySelector('.btn-copy').addEventListener('click', e => {
      e.stopPropagation(); copyPassword(entry.id, entry.password, card);
    });
    card.querySelector('.btn-edit').addEventListener('click', e => {
      e.stopPropagation(); editEntry(entry.id, group.id);
    });
    card.querySelector('.btn-goto').addEventListener('click', () => {
      state.searchQuery = '';
      $('search-input').value = '';
      state.currentGroupId = group.id;
      state.expandedGroups.add(group.id);
      // Expand ancestors
      _expandPathTo(state.data.root, group.id);
      renderTree();
      renderEntries(group.id);
    });
    card.querySelector('.btn-del').addEventListener('click', async e => {
      e.stopPropagation();
      const ok = await dlgConfirm('Vols esborrar aquesta entrada?');
      if (!ok) return;
      group.entries = (group.entries || []).filter(e2 => e2.id !== entry.id);
      markUnsaved();
      renderTree();
      renderSearch();
    });

    grid.appendChild(card);
  }
}

function _expandPathTo(root, targetId, _path = [root]) {
  if (root.id === targetId) {
    _path.forEach(g => state.expandedGroups.add(g.id));
    return true;
  }
  for (const child of (root.children || [])) {
    if (_expandPathTo(child, targetId, [..._path, child])) return true;
  }
  return false;
}

// ===== CSV EXPORT =====

async function exportCSV() {
  if (!state.data) return;

  const ok = await dlgConfirm(
    'El fitxer CSV es desarà sense xifrar.\n' +
    'Les contrasenyes seran visibles en text pla.\n\nVols continuar?'
  );
  if (!ok) return;

  const pwd = await dlgPassword('Confirma la contrasenya mestra', 'Introdueix la contrasenya per continuar');
  if (pwd === null) return;
  if (pwd !== state.password) {
    await dlgAlert('Contrasenya incorrecta');
    return;
  }

  const csv = exportToCSV(state.data);
  // Add BOM for Excel compatibility
  const bom  = '\uFEFF';
  const blob = new Blob([bom + csv], { type: 'text/csv;charset=utf-8' });
  const name = (state.fileName || 'database').replace(/\.vkdb$/, '') + '.csv';
  _downloadBlob(blob, name);
  showToast('CSV exportat', 'success');
}

// ===== CSV IMPORT =====

async function importCSV() {
  if (!state.data) return;

  const pwd = await dlgPassword('Confirma la contrasenya mestra', 'Introdueix la contrasenya per continuar');
  if (pwd === null) return;
  if (pwd !== state.password) {
    await dlgAlert('Contrasenya incorrecta');
    return;
  }

  const file = await pickFileViaInput('.csv');
  if (!file) return;

  const text = await file.text();
  const count = importFromCSV(state.data, text);

  if (count === -1) {
    await dlgAlert('No s\'ha trobat la columna de títol al CSV.\nLa capçalera ha de contenir: Títol, Title o Name.');
    return;
  }
  if (count === 0) {
    await dlgAlert('No s\'ha trobat cap entrada vàlida al fitxer.');
    return;
  }

  markUnsaved();
  renderTree();
  renderCurrentView();
  showToast(`${count} entrades importades`, 'success');
}

// ===== TOAST =====

let _toastTimer = null;

function showToast(msg, type = '') {
  const t = $('toast');
  t.textContent = msg;
  t.className   = 'toast' + (type ? ' ' + type : '');
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { t.classList.add('hidden'); }, 3000);
}

// ===== MODAL INFRASTRUCTURE =====

function _showModal(content) {
  const overlay = $('modal-overlay');
  const box     = $('modal-box');
  box.innerHTML = '';
  box.appendChild(content);
  overlay.classList.remove('hidden');

  // Focus first focusable element
  requestAnimationFrame(() => {
    const first = box.querySelector('input, button, textarea, select, [tabindex]');
    if (first) first.focus();
  });
}

function _hideModal() {
  const overlay = $('modal-overlay');
  overlay.classList.add('hidden');
  $('modal-box').innerHTML = '';
}

/**
 * Base dialog builder. Returns a Promise.
 * @param {string} title
 * @param {HTMLElement} bodyEl
 * @param {Array<{label,class,value,default}>} buttons
 * @param {function(HTMLElement):void} setup  - called once after DOM inserted
 */
function _dialog(title, bodyEl, buttons, setup) {
  return new Promise(resolve => {
    const wrap = document.createElement('div');
    wrap.innerHTML = `<div class="modal-title">${_esc(title)}</div>`;

    const bodyWrap = document.createElement('div');
    bodyWrap.className = 'modal-body';
    bodyWrap.appendChild(bodyEl);
    wrap.appendChild(bodyWrap);

    const footer = document.createElement('div');
    footer.className = 'modal-footer';

    let resolved = false;
    const done = val => {
      if (resolved) return;
      resolved = true;
      _hideModal();
      resolve(val);
    };

    for (const btn of buttons) {
      const el = document.createElement('button');
      el.className = 'btn ' + (btn.cls || 'btn-secondary');
      el.textContent = btn.label;
      el.addEventListener('click', () => done(btn.value));
      footer.appendChild(el);
    }
    wrap.appendChild(footer);

    // Keyboard
    wrap.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        done(buttons.find(b => b.isCancel)?.value ?? null);
      }
      if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'BUTTON') {
        e.preventDefault();
        const def = buttons.find(b => b.isDefault);
        if (def) done(def.value);
      }
    });

    _showModal(wrap);
    if (setup) setup(wrap, done);
  });
}

// ===== DIALOGS =====

/**
 * Single password dialog.
 * Returns password string or null if cancelled.
 */
function dlgPassword(title, description = '') {
  return new Promise(resolve => {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">${_esc(title)}</div>
      <div class="modal-body">
        ${description ? `<div class="text-dim" style="font-size:.85rem;margin-bottom:4px">${_esc(description)}</div>` : ''}
        <div class="form-group">
          <label class="form-label">Contrasenya</label>
          <div class="pwd-wrap">
            <input type="password" id="dlg-pwd" class="form-input" autocomplete="current-password" placeholder="Contrasenya…">
            <button type="button" class="pwd-toggle" id="dlg-pwd-toggle">👁️ Mostra</button>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="dlg-cancel">Cancel·la</button>
        <button class="btn btn-primary" id="dlg-ok">Accepta</button>
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    wrap.querySelector('#dlg-ok').addEventListener('click', () => done(wrap.querySelector('#dlg-pwd').value));
    wrap.querySelector('#dlg-cancel').addEventListener('click', () => done(null));
    wrap.querySelector('#dlg-pwd-toggle').addEventListener('click', () => {
      const inp = wrap.querySelector('#dlg-pwd');
      const btn = wrap.querySelector('#dlg-pwd-toggle');
      if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈 Amaga'; }
      else                         { inp.type = 'password'; btn.textContent = '👁️ Mostra'; }
    });
    wrap.addEventListener('keydown', e => {
      if (e.key === 'Escape') done(null);
      if (e.key === 'Enter' && e.target.id === 'dlg-pwd') done(wrap.querySelector('#dlg-pwd').value);
    });

    _showModal(wrap);
    requestAnimationFrame(() => wrap.querySelector('#dlg-pwd').focus());
  });
}

/**
 * Password creation dialog (with confirmation and strength bar).
 * Returns password string or null.
 */
function dlgPasswordCreate(title) {
  return new Promise(resolve => {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">${_esc(title)}</div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Contrasenya</label>
          <div class="pwd-wrap">
            <input type="password" id="dlg-pwd1" class="form-input" autocomplete="new-password" placeholder="Contrasenya…">
            <button type="button" class="pwd-toggle" id="dlg-t1">👁️ Mostra</button>
          </div>
          <div class="strength-bar-wrap"><div class="strength-bar" id="sb1" style="width:0%"></div></div>
          <div class="strength-label" id="sl1" style="color:var(--text-dim)"></div>
        </div>
        <div class="form-group">
          <label class="form-label">Confirma la contrasenya</label>
          <div class="pwd-wrap">
            <input type="password" id="dlg-pwd2" class="form-input" autocomplete="new-password" placeholder="Repeteix…">
            <button type="button" class="pwd-toggle" id="dlg-t2">👁️ Mostra</button>
          </div>
          <div id="dlg-match" style="font-size:.75rem;margin-top:2px"></div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="dlg-cancel">Cancel·la</button>
        <button class="btn btn-primary" id="dlg-ok">Crea</button>
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    const inp1 = wrap.querySelector('#dlg-pwd1');
    const inp2 = wrap.querySelector('#dlg-pwd2');
    const sb1  = wrap.querySelector('#sb1');
    const sl1  = wrap.querySelector('#sl1');
    const matchEl = wrap.querySelector('#dlg-match');

    inp1.addEventListener('input', () => {
      const st = passwordStrength(inp1.value);
      sb1.style.width = st.score + '%';
      sb1.style.background = st.color;
      sl1.textContent = inp1.value ? st.label : '';
      sl1.style.color = st.color;
      checkMatch();
    });
    inp2.addEventListener('input', checkMatch);

    function checkMatch() {
      if (!inp2.value) { matchEl.textContent = ''; return; }
      if (inp1.value === inp2.value) {
        matchEl.textContent = '✓ Les contrasenyes coincideixen';
        matchEl.style.color = 'var(--success)';
      } else {
        matchEl.textContent = '✗ Les contrasenyes no coincideixen';
        matchEl.style.color = 'var(--danger)';
      }
    }

    _makeToggle(wrap, '#dlg-pwd1', '#dlg-t1');
    _makeToggle(wrap, '#dlg-pwd2', '#dlg-t2');

    wrap.querySelector('#dlg-ok').addEventListener('click', () => {
      if (!inp1.value) { inp1.focus(); return; }
      if (inp1.value !== inp2.value) {
        matchEl.textContent = '✗ Les contrasenyes no coincideixen';
        matchEl.style.color = 'var(--danger)';
        inp2.focus();
        return;
      }
      done(inp1.value);
    });
    wrap.querySelector('#dlg-cancel').addEventListener('click', () => done(null));
    wrap.addEventListener('keydown', e => { if (e.key === 'Escape') done(null); });

    _showModal(wrap);
    requestAnimationFrame(() => inp1.focus());
  });
}

/**
 * Single text input dialog.
 * Returns string or null.
 */
function dlgText(title, label, defaultValue = '') {
  return new Promise(resolve => {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">${_esc(title)}</div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">${_esc(label)}</label>
          <input type="text" id="dlg-text" class="form-input" value="${_esc(defaultValue)}" placeholder="${_esc(label)}">
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="dlg-cancel">Cancel·la</button>
        <button class="btn btn-primary" id="dlg-ok">Accepta</button>
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    const inp = wrap.querySelector('#dlg-text');
    wrap.querySelector('#dlg-ok').addEventListener('click', () => {
      const v = inp.value.trim();
      if (!v) { inp.focus(); return; }
      done(v);
    });
    wrap.querySelector('#dlg-cancel').addEventListener('click', () => done(null));
    wrap.addEventListener('keydown', e => {
      if (e.key === 'Escape') done(null);
      if (e.key === 'Enter') {
        const v = inp.value.trim();
        if (v) done(v);
      }
    });

    _showModal(wrap);
    requestAnimationFrame(() => { inp.focus(); inp.select(); });
  });
}

/**
 * Full entry editor dialog.
 * @param {Object|null} entry  - existing entry to edit, or null for new
 * Returns filled entry object or null.
 */
function dlgEntry(entry) {
  return new Promise(resolve => {
    const isNew = !entry;
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">${isNew ? 'Nova entrada' : 'Edita entrada'}</div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">Títol *</label>
          <input type="text" id="de-title" class="form-input" value="${_esc(entry?.title || '')}" placeholder="Títol de l'entrada">
        </div>
        <div class="form-group">
          <label class="form-label">Usuari</label>
          <input type="text" id="de-user" class="form-input" value="${_esc(entry?.username || '')}" placeholder="Nom d'usuari o correu">
        </div>
        <div class="form-group">
          <label class="form-label">Contrasenya</label>
          <div class="pwd-wrap">
            <input type="password" id="de-pwd" class="form-input" value="${_esc(entry?.password || '')}" placeholder="Contrasenya" autocomplete="new-password">
            <button type="button" class="pwd-gen-btn" id="de-gen-btn" title="Obre el generador">⚡</button>
            <button type="button" class="pwd-toggle" id="de-pwd-toggle">👁️ Mostra</button>
          </div>
          <div class="strength-bar-wrap"><div class="strength-bar" id="de-sb" style="width:0%"></div></div>
          <div class="strength-label" id="de-sl" style="color:var(--text-dim)"></div>
        </div>
        <div class="form-group">
          <label class="form-label">URL</label>
          <input type="url" id="de-url" class="form-input" value="${_esc(entry?.url || '')}" placeholder="https://exemple.com">
        </div>
        <div class="form-group">
          <label class="form-label">Notes</label>
          <textarea id="de-notes" class="form-input form-textarea" placeholder="Notes…">${_esc(entry?.notes || '')}</textarea>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="de-cancel">Cancel·la</button>
        <button class="btn btn-primary" id="de-ok">${isNew ? 'Crea' : 'Desa'}</button>
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    const pwdInp = wrap.querySelector('#de-pwd');
    const sb     = wrap.querySelector('#de-sb');
    const sl     = wrap.querySelector('#de-sl');

    const updateStrength = () => {
      const st = passwordStrength(pwdInp.value);
      sb.style.width      = st.score + '%';
      sb.style.background = st.color;
      sl.textContent      = pwdInp.value ? st.label : '';
      sl.style.color      = st.color;
    };

    // Initial strength
    if (entry?.password) updateStrength();

    pwdInp.addEventListener('input', updateStrength);

    _makeToggle(wrap, '#de-pwd', '#de-pwd-toggle');

    // Quick generator button
    wrap.querySelector('#de-gen-btn').addEventListener('click', async () => {
      const pwd = await dlgGenerator(null, true); // returns password string on Use
      if (pwd) {
        pwdInp.value = pwd;
        updateStrength();
      }
    });

    wrap.querySelector('#de-ok').addEventListener('click', () => {
      const title = wrap.querySelector('#de-title').value.trim();
      if (!title) { wrap.querySelector('#de-title').focus(); return; }
      done(makeEntry({
        title,
        username: wrap.querySelector('#de-user').value.trim(),
        password: pwdInp.value,
        url:      wrap.querySelector('#de-url').value.trim(),
        notes:    wrap.querySelector('#de-notes').value.trim(),
      }));
    });
    wrap.querySelector('#de-cancel').addEventListener('click', () => done(null));
    wrap.addEventListener('keydown', e => { if (e.key === 'Escape') done(null); });

    _showModal(wrap);
    requestAnimationFrame(() => wrap.querySelector('#de-title').focus());
  });
}

/**
 * Password generator dialog.
 * @param {function|null} onSelectCallback  (unused, kept for compatibility)
 * @param {boolean} returnValue  - if true, Use button resolves with password string
 * Returns password string (if returnValue) or null.
 */
function dlgGenerator(onSelectCallback = null, returnValue = false) {
  return new Promise(resolve => {
    let currentPwd = generatePassword(20, true, true, true, true);

    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">⚡ Generador de contrasenyes</div>
      <div class="modal-body">
        <div class="generator-controls">
          <div class="gen-length-row">
            <label class="form-label">Longitud</label>
            <input type="range" id="gen-len" min="6" max="64" value="20">
            <span class="gen-length-val" id="gen-len-val">20</span>
          </div>
          <div class="gen-checkboxes">
            <label class="gen-checkbox"><input type="checkbox" id="gen-upper" checked> Majúscules (A-Z)</label>
            <label class="gen-checkbox"><input type="checkbox" id="gen-lower" checked> Minúscules (a-z)</label>
            <label class="gen-checkbox"><input type="checkbox" id="gen-digits" checked> Xifres (0-9)</label>
            <label class="gen-checkbox"><input type="checkbox" id="gen-syms" checked> Símbols (!@#…)</label>
          </div>
          <div class="gen-output-row">
            <div class="gen-output" id="gen-output" style="word-break:break-all">${_esc(currentPwd)}</div>
            <button class="btn btn-icon" id="gen-regen" title="Genera de nou">🎲</button>
          </div>
          <div class="strength-bar-wrap"><div class="strength-bar" id="gen-sb" style="width:0%"></div></div>
          <div class="strength-label" id="gen-sl"></div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="gen-close">Tanca</button>
        <button class="btn btn-icon" id="gen-copy">📋 Copia</button>
        ${returnValue ? '<button class="btn btn-success" id="gen-use">✅ Usa</button>' : ''}
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    const output = wrap.querySelector('#gen-output');
    const sb     = wrap.querySelector('#gen-sb');
    const sl     = wrap.querySelector('#gen-sl');
    const lenSlider = wrap.querySelector('#gen-len');
    const lenVal    = wrap.querySelector('#gen-len-val');

    const updateStrength = () => {
      const st = passwordStrength(currentPwd);
      sb.style.width      = st.score + '%';
      sb.style.background = st.color;
      sl.textContent      = st.label;
      sl.style.color      = st.color;
    };

    const regen = () => {
      const len    = parseInt(lenSlider.value);
      const upper  = wrap.querySelector('#gen-upper').checked;
      const lower  = wrap.querySelector('#gen-lower').checked;
      const digits = wrap.querySelector('#gen-digits').checked;
      const syms   = wrap.querySelector('#gen-syms').checked;
      currentPwd = generatePassword(len, upper, lower, digits, syms);
      output.textContent = currentPwd;
      updateStrength();
    };

    lenSlider.addEventListener('input', () => { lenVal.textContent = lenSlider.value; regen(); });
    wrap.querySelector('#gen-upper').addEventListener('change', regen);
    wrap.querySelector('#gen-lower').addEventListener('change', regen);
    wrap.querySelector('#gen-digits').addEventListener('change', regen);
    wrap.querySelector('#gen-syms').addEventListener('change', regen);
    wrap.querySelector('#gen-regen').addEventListener('click', regen);

    wrap.querySelector('#gen-copy').addEventListener('click', () => {
      navigator.clipboard.writeText(currentPwd).then(() => showToast('Contrasenya copiada', 'success'));
    });

    wrap.querySelector('#gen-close').addEventListener('click', () => done(null));
    if (returnValue) {
      wrap.querySelector('#gen-use').addEventListener('click', () => done(currentPwd));
    }

    wrap.addEventListener('keydown', e => { if (e.key === 'Escape') done(null); });

    updateStrength();
    _showModal(wrap);
  });
}

/**
 * Move entry dialog — tree picker.
 * @param {string} entryId
 * @param {string} currentGroupId
 * Returns destination group id or null.
 */
function dlgMoveEntry(entryId, currentGroupId) {
  return new Promise(resolve => {
    let selectedId = null;

    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">📦 Mou entrada a…</div>
      <div class="modal-body">
        <div class="text-dim" style="font-size:.85rem;margin-bottom:8px">Selecciona el grup de destinació:</div>
        <div class="move-tree" id="move-tree"></div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="mv-cancel">Cancel·la</button>
        <button class="btn btn-primary" id="mv-ok" disabled>Mou</button>
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    const treeEl = wrap.querySelector('#move-tree');
    const okBtn  = wrap.querySelector('#mv-ok');

    const renderNode = (group, depth, container) => {
      const el = document.createElement('div');
      el.className = 'move-tree-node' + (group.id === currentGroupId ? ' selected' : '');
      el.style.paddingLeft = (depth * 16 + 8) + 'px';
      el.textContent = (depth === 0 ? '🗄️ ' : '📁 ') + group.name;
      el.dataset.id = group.id;
      el.addEventListener('click', () => {
        treeEl.querySelectorAll('.move-tree-node').forEach(n => n.classList.remove('selected'));
        el.classList.add('selected');
        selectedId = group.id;
        okBtn.disabled = false;
      });
      container.appendChild(el);
      for (const child of (group.children || [])) renderNode(child, depth + 1, container);
    };

    renderNode(state.data.root, 0, treeEl);

    okBtn.addEventListener('click', () => { if (selectedId) done(selectedId); });
    wrap.querySelector('#mv-cancel').addEventListener('click', () => done(null));
    wrap.addEventListener('keydown', e => { if (e.key === 'Escape') done(null); });

    _showModal(wrap);
  });
}

/**
 * Confirm dialog. Returns true/false.
 */
function dlgConfirm(message) {
  return new Promise(resolve => {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">Confirmació</div>
      <div class="modal-body">
        <div class="dlg-confirm-msg">${_esc(message).replace(/\n/g, '<br>')}</div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="conf-no">No</button>
        <button class="btn btn-primary" id="conf-yes">Sí</button>
      </div>`;

    let resolved = false;
    const done = val => { if (!resolved) { resolved = true; _hideModal(); resolve(val); } };

    wrap.querySelector('#conf-yes').addEventListener('click', () => done(true));
    wrap.querySelector('#conf-no').addEventListener('click',  () => done(false));
    wrap.addEventListener('keydown', e => {
      if (e.key === 'Escape') done(false);
      if (e.key === 'Enter')  done(true);
    });

    _showModal(wrap);
    requestAnimationFrame(() => wrap.querySelector('#conf-yes').focus());
  });
}

/**
 * Alert dialog. Returns undefined.
 */
function dlgAlert(message) {
  return new Promise(resolve => {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal-title">Informació</div>
      <div class="modal-body">
        <div class="dlg-confirm-msg">${_esc(message).replace(/\n/g, '<br>')}</div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-primary" id="alert-ok">D'acord</button>
      </div>`;

    let resolved = false;
    const done = () => { if (!resolved) { resolved = true; _hideModal(); resolve(); } };

    wrap.querySelector('#alert-ok').addEventListener('click', done);
    wrap.addEventListener('keydown', e => { if (e.key === 'Escape' || e.key === 'Enter') done(); });

    _showModal(wrap);
    requestAnimationFrame(() => wrap.querySelector('#alert-ok').focus());
  });
}

// ===== HELPERS =====

function _esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function _makeToggle(wrap, inputSel, btnSel) {
  const inp = wrap.querySelector(inputSel);
  const btn = wrap.querySelector(btnSel);
  if (!inp || !btn) return;
  btn.addEventListener('click', () => {
    if (inp.type === 'password') { inp.type = 'text';     btn.textContent = '🙈 Amaga'; }
    else                         { inp.type = 'password'; btn.textContent = '👁️ Mostra'; }
  });
}
