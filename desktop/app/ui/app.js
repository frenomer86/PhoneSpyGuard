// Phone Spy Guard desktop UI. Plain JavaScript, no framework, no network.
// Every piece of text that came from the PC is inserted with textContent,
// never as HTML, since program and extension names are attacker-controlled.
"use strict";

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const listen = (ev, fn) => window.__TAURI__.event.listen(ev, fn);

// The same confidence wording as the phone app.
const LABELS = {
  CONFIRMED: "Confirmed spying",
  VERY_LIKELY: "Very likely spying",
  POSSIBLE: "Possible — worth a look",
  UNLIKELY: "Unlikely",
};

const KIND_NAMES = {
  product: "Known product",
  program: "Installed program",
  process: "Running program",
  autostart: "Starts with Windows",
  extension: "Browser extension",
  setting: "Setting",
  camera_mic: "Camera / microphone",
  network: "Stalkerware server contact",
  file: "Stalkerware installer file",
  // Counted in "Everything checked" but matched, not scored one by one.
  dns_name: "Recent web address",
  connection: "Open connection",
  apk_file: "Phone app file (.apk)",
};

const AUTOSTART_PLACES = {
  run_key: "Run key",
  startup_folder: "Start-up folder",
  service: "Service",
  scheduled_task: "Scheduled task",
  wmi: "WMI trigger",
  ifeo: "Program replacement (IFEO)",
  winlogon: "Sign-in shell",
  appinit: "Loaded into every program (AppInit)",
  appcert: "Loaded into every program (AppCert)",
  lsa: "Password and sign-in system (LSA)",
  winlogon_notify: "Sign-in add-in",
  boot_execute: "Runs before Windows starts",
  silent_exit: "Runs when a program closes",
  cmd_autorun: "Runs in every Command Prompt",
  com_hijack: "Replaces a Windows component",
  print_monitor: "Print system add-in",
  netsh: "Network tool add-in",
  shell_extension: "Explorer add-in",
  bho: "Internet Explorer add-in",
  active_setup: "Runs at next sign-in (Active Setup)",
  terminal_server: "Runs in Remote Desktop sessions",
};

// Rule step ids -> what the owner does, and a Windows page to open for it.
const STEPS = {
  read_safety_guidance: ["Read the Safety tab before removing anything someone else may notice."],
  export_evidence: ["Export the evidence timeline first and keep a copy somewhere safe.", "timeline"],
  uninstall_program: ["Uninstall it from Settings > Apps.", "apps"],
  change_passwords: ["From a different, trusted device, change the passwords for email, banking and social accounts, and turn on two-step sign-in."],
  call_bank: ["If anyone ever connected to this PC with it, call your bank on the number printed on your card."],
  review_app: ["Check whether you or someone you trust installed it. If not, remove it.", "apps"],
  disable_autostart: ["Turn it off in Settings > Apps > Startup, or in Task Scheduler for a scheduled task.", "startup"],
  remove_wmi_subscription: ["A technician can remove the WMI subscription; export the evidence first."],
  remove_ifeo_debugger: ["A technician can remove the Image File Execution Options 'Debugger' entry; export the evidence first."],
  review_extension: ["Open the browser's extensions page and remove it if you don't use it."],
  remove_extension: ["Remove it from the browser's extensions page, then sign out of every site and back in."],
  remove_browser_policy: ["Ask whoever manages this PC. On a personal PC, the browser policy was added by a program or person."],
  remove_root_cert: ["Remove the certificate in 'Manage user certificates' > Trusted Root Certification Authorities.", "certificates"],
  reset_proxy: ["Turn the proxy off in Settings > Network & internet > Proxy.", "proxy"],
  reset_dns: ["Set DNS back to automatic in your network adapter settings.", "network"],
  review_hosts: ["Look at C:\\Windows\\System32\\drivers\\etc\\hosts and remove lines you don't recognise."],
  reset_hosts: ["Remove the lines for these sites from C:\\Windows\\System32\\drivers\\etc\\hosts (Notepad, run as administrator)."],
  disable_rdp: ["Turn Remote Desktop off unless you use it.", "remote_desktop"],
  review_admins: ["Check every administrator account. Remove or downgrade any you don't recognise.", "accounts"],
  review_accounts: ["Check every account on this PC. Turn off or remove any you don't recognise, and change your own password from a device you trust.", "accounts"],
  disable_auto_logon: ["Turn off automatic sign-in: in Settings > Accounts > Sign-in options, require sign-in, then change your password.", "signin"],
  turn_on_defender: ["Turn real-time protection back on in Windows Security.", "defender"],
  remove_exclusion: ["Remove exclusions you didn't add in Windows Security > Virus & threat protection settings.", "defender"],
  block_camera_mic: ["Turn off camera or microphone access for that program.", "camera"],
  check_phone: ["Check your phone too. Stalkerware like this is installed on phones and controlled from a website, so run Phone Spy Guard on your phone, or ask an advocate to help you check it."],
  keep_installer_file: ["Don't open or delete the file yet: it is evidence of what was downloaded and when. Leave it where it is until you have spoken to an advocate or the police."],
  remove_hook: ["A technician can remove this entry safely once the evidence is exported; removing the wrong one can stop Windows from starting."],
};

const PAGE_LABELS = {
  apps: "Open Apps",
  startup: "Open Startup apps",
  defender: "Open Windows Security",
  remote_desktop: "Open Remote Desktop",
  proxy: "Open Proxy settings",
  network: "Open Network settings",
  camera: "Open Camera privacy",
  microphone: "Open Microphone privacy",
  accounts: "Open Other users",
  certificates: "Open certificates",
  timeline: "Go to timeline",
};

let status = null;
let report = null;
let trusted = new Set();
let changes = [];

// --- tiny DOM helper --------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const $ = (id) => document.getElementById(id);

function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 5000);
}

function when(ms) {
  if (!ms) return "never";
  const d = new Date(ms);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function ago(ms) {
  if (!ms) return "";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

// --- tabs --------------------------------------------------------------------

function showTab(name) {
  for (const b of document.querySelectorAll(".tabs button")) {
    b.setAttribute("aria-selected", String(b.dataset.tab === name));
  }
  for (const s of document.querySelectorAll(".tab")) s.hidden = s.id !== `tab-${name}`;
  window.scrollTo(0, 0);
  if (name === "timeline") loadTimeline();
}

// --- status ------------------------------------------------------------------

async function loadStatus() {
  status = await invoke("get_status");
  trusted = new Set(status.trusted || []);
  const name = status.discreet ? "Device Check" : "Phone Spy Guard";
  $("brandName").textContent = name;
  $("brandIcon").src = status.discreet ? "gear.svg" : "shield.svg";
  document.title = name;
  $("lockToggle").checked = status.appLock;
  $("discreetToggle").checked = status.discreet;
  $("trustedList").replaceChildren(...(status.trustedDetails.length
    ? status.trustedDetails.map((t) => h("div", { class: "trusted-row" },
        `${t.title} (answered ${when(t.answeredMillis)}) `,
        h("button", { class: "btn outlined sm", onclick: () => answer({ id: t.id, title: t.title }, false) }, "Undo")))
    : ["Nothing yet. When you say you set something up, it appears here, and stops counting if that program or setting changes."]));
  $("topStatus").textContent = [
    status.watchEnabled ? `Watching for changes every ${status.watchIntervalMinutes} minutes.` : "The change watch is off.",
    status.rules.verified ? `Detection rules v${status.rules.version}, signatures verified.` : "Detection rules could not be verified.",
    status.lastRunMillis ? `Last checked ${when(status.lastRunMillis)} (${ago(status.lastRunMillis)}).` : "This PC has not been checked yet.",
  ].join(" ");
  const err = $("rulesError");
  const problems = [status.rules.error, status.evidenceError, status.headError].filter(Boolean);
  err.hidden = problems.length === 0;
  err.textContent = problems.join(" ");
  $("btnCheck").disabled = !status.rules.verified;
  $("btnDeep").disabled = !status.rules.verified || !status.isWindows;
  $("watchToggle").checked = status.watchEnabled;
  $("signInToggle").checked = status.startAtSignIn;
  $("signInToggle").disabled = !status.isWindows;
  $("rulesInfo").textContent = status.rules.verified
    ? `Version ${status.rules.version}, ${status.rules.ruleCount} rules and ${status.rules.productCount} known products, ${status.rules.source}, valid until ${status.rules.expires}. Verified signatures from ${status.rules.signedBy.join(", ")}. Fingerprint (SHA-256): ${status.rules.sha256}`
    : `No verified rules: ${status.rules.error || "unknown error"}`;
  const ru = status.ruleUpdates;
  $("autoRulesToggle").checked = ru.automatic;
  $("autoRulesToggle").disabled = !ru.server;
  $("btnCheckRules").disabled = !ru.server;
  $("ruleUpdateInfo").textContent = [
    ru.server ? `Update server: ${ru.server}.` : "This build has no update server; install rule files instead.",
    ru.lastCheckMillis ? `Last looked ${when(ru.lastCheckMillis)}: ${ru.lastResult}` : "",
  ].filter(Boolean).join(" ");
  $("dataInfo").textContent = `Timeline, baseline and answers are kept encrypted to your Windows account in ${status.dataDir}. The evidence-signing key (${status.keyId}) and the record of the timeline's length are kept in Windows Credential Manager and never leave this PC. A program running as you could still read them, so keep checkpoints off this PC.`;
}

// --- checking ----------------------------------------------------------------

const DEEP_PHASES = {
  prompt: "Windows is asking for administrator rights. Choose Yes in its prompt to continue. If you don't see the prompt, look for a flashing shield in the taskbar. Meanwhile the normal check is running.",
  running: "Checking with administrator rights… this can take a few minutes.",
};

async function runCheck(deep) {
  for (const b of [$("btnCheck"), $("btnDeep")]) b.disabled = true;
  $("progress").hidden = false;
  $("btnCancelDeep").hidden = !deep;
  $("btnCancelDeep").disabled = false;
  $("progressText").textContent = deep
    ? DEEP_PHASES.prompt
    : "Checking this PC… this usually takes a minute or two.";
  try {
    const result = await invoke("check_now", { deep });
    applyResult(result);
    const deepGap = deep && (result.report.gaps || []).find((g) => g.area === "Deep check");
    if (deepGap) toast(deepGap.reason);
    else if (result.alerts.length) toast(`${result.alerts.length} new item(s) written to the evidence timeline.`);
  } catch (e) {
    toast(String(e));
  } finally {
    $("progress").hidden = true;
    $("btnCancelDeep").hidden = true;
    await loadStatus();
  }
}

function applyResult(result) {
  report = result.report;
  changes = result.changes || [];
  trusted = new Set(result.trusted || []);
  renderResults();
  renderCamMic();
}

// --- results -------------------------------------------------------------------

function renderResults() {
  const root = $("results");
  root.replaceChildren();
  $("lastRun").textContent = "";
  $("guidance").hidden = true;
  if (!report) return;

  const findings = report.findings;
  const counts = { CONFIRMED: 0, VERY_LIKELY: 0, POSSIBLE: 0, UNLIKELY: 0 };
  for (const f of findings) counts[f.evaluation.verdict.confidence]++;
  const concerning = findings.filter((f) => f.evaluation.verdict.confidence !== "UNLIKELY");

  $("lastRun").textContent = `Checked ${findings.length} ${findings.length === 1 ? "item" : "items"} on ${report.computer || "this PC"}.`;

  // As on the phone: the safety guidance comes before any finding.
  if (concerning.length) {
    const brief = status && status.safetyNoteSeen;
    $("guidance").hidden = brief;
    if (brief) {
      root.append(h("article", { class: "card" },
        h("h3", {}, "Before you remove anything"),
        h("p", {}, "Removing it can destroy the proof. Export the evidence first."),
        h("div", { class: "card-actions" },
          h("button", { class: "btn outlined", onclick: () => showTab("safety") }, "Read the safety guidance"),
          h("button", { class: "btn outlined", onclick: () => showTab("timeline") }, "Go to Evidence"))));
    }
    root.append(h("div", { class: "summary" },
      ["CONFIRMED", "VERY_LIKELY", "POSSIBLE"].filter((c) => counts[c]).map((c) =>
        h("span", { class: `chip ${c}` }, `${counts[c]} × ${LABELS[c]}`))));
    for (const f of concerning) root.append(card(f));
  } else {
    root.append(h("p", { class: "lead" }, report.gaps.length
      ? "Nothing stood out in the parts that could be checked. Some parts could not be checked; see below."
      : "Nothing stood out in this check."));
  }

  if (changes.length) {
    root.append(h("h2", {}, "Changed since the last check"));
    root.append(h("ul", { class: "plain" }, changes.map((c) =>
      h("li", {}, changeLine(c)))));
  }

  if (report.gaps.length) {
    root.append(h("h2", {}, "Not checked this time"));
    root.append(h("ul", { class: "plain" }, report.gaps.map((g) =>
      h("li", {}, h("strong", {}, g.area), ": ", g.reason,
        g.needsDeepCheck ? " Run the deep check to include it." : ""))));
  }

  const quiet = findings.filter((f) => f.evaluation.verdict.confidence === "UNLIKELY");
  const byKind = Object.entries(report.checked).map(([k, n]) => `${n} ${(KIND_NAMES[k] || k).toLowerCase()}`).join(", ");
  root.append(h("h2", {}, "Everything checked"));
  root.append(h("p", { class: "small muted" },
    `${byKind}. Rules v${report.bundleVersion}. Took ${Math.max(1, Math.round((report.finishedMillis - report.startedMillis) / 1000))} s.`));
  const search = h("input", { type: "search", placeholder: "Filter by name or path", "aria-label": "Filter checked items" });
  const list = h("div", {});
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const shown = quiet.filter((f) => !q || `${f.subject.title} ${f.subject.detail}`.toLowerCase().includes(q)).slice(0, 200);
    list.replaceChildren(...shown.map((f) => card(f, true)));
  };
  search.addEventListener("input", draw);
  const det = h("details", {}, h("summary", {}, `Show the ${quiet.length} ${quiet.length === 1 ? "item" : "items"} where nothing stood out`), search, list);
  det.addEventListener("toggle", () => det.open && draw(), { once: true });
  root.append(det);
}

function changeLine(c) {
  const verbs = { added: "Added", removed: "Removed", modified: "Changed", device_used: "Used" };
  return [h("strong", {}, verbs[c.kind] || c.kind), ` ${KIND_NAMES[c.subjectKind] || ""}: ${c.title}`, c.detail ? ` (${c.detail})` : ""];
}

function card(f, compact = false) {
  const v = f.evaluation.verdict;
  const s = f.subject;
  const c = v.confidence;
  const isTrusted = trusted.has(s.id);
  const where = s.facts["pc.autostart_location"];

  const el = h("article", { class: "card" },
    h("div", { class: "finding-head" },
      h("span", { class: `badge ${c}` }, LABELS[c]),
      h("span", { class: "kind" }, KIND_NAMES[s.kind] + (where ? ` · ${AUTOSTART_PLACES[where] || where}` : "")),
    ),
    h("h3", {}, s.title),
    s.detail ? h("div", { class: "detail" }, s.detail) : null,
  );

  const concerning = v.signals.filter((x) => x.contribution !== "INNOCENT");
  const explained = new Set(v.explained || []);
  if (concerning.length || v.innocentExplanations.length) {
    el.append(h("ul", { class: "bullets" },
      concerning.map((x) => h("li", { class: explained.has(x.ruleId) ? "explained" : null }, x.title)),
      v.innocentExplanations.map((x) => h("li", { class: "innocent" }, `Explained by: ${x.title}`)),
    ));
  }
  if (s.facts["pc.owner_trust_stale"]) {
    el.append(h("p", { class: "stale-note" }, "You said earlier that you set this up, but it has changed since (a different file, place, publisher or setting), so that answer no longer counts."));
  }

  if (!compact) {
    for (const p of f.explain) el.append(h("p", {}, p));
    if (f.removal) el.append(h("p", { class: "removal" }, h("strong", {}, "How to remove it: "), f.removal));
    if (f.steps.length) {
      el.append(h("strong", {}, "What to do"));
      // Safety and evidence come before anything that removes or changes.
      const first = ["read_safety_guidance", "export_evidence"];
      const steps = [...first.filter((x) => f.steps.includes(x)), ...f.steps.filter((x) => !first.includes(x))];
      el.append(h("ol", { class: "steps" }, steps.map((id) => {
        const [text, page] = STEPS[id] || [id.replaceAll("_", " ")];
        return h("li", {}, text, page ? h("button", { class: "btn text sm", onclick: () => openPage(page) }, PAGE_LABELS[page] || "Open") : null);
      })));
    }
  }

  const ev = Object.entries(s.evidence || {}).filter(([, val]) => val);
  const facts = Object.entries(s.facts || {}).filter(([k]) => k !== "pc.kind");
  el.append(h("details", {},
    h("summary", {}, "Evidence"),
    h("dl", { class: "evidence" },
      ev.flatMap(([k, val]) => [h("dt", {}, k), h("dd", {}, String(val))]),
      facts.flatMap(([k, val]) => [h("dt", {}, k), h("dd", {}, Array.isArray(val) ? val.join(", ") || "(none)" : String(val))]),
    ),
  ));

  if (c !== "UNLIKELY" || isTrusted) {
    const foot = h("div", { class: "card-actions" });
    if (isTrusted) {
      foot.append(h("span", { class: "trusted-note" }, "You said you set this up."),
        h("button", { class: "btn outlined sm", onclick: () => answer(s, false) }, "Undo"));
    } else if (c === "CONFIRMED") {
      // A known monitoring product is never explained away (review H5).
      foot.append(h("button", { class: "btn outlined sm", onclick: () => answer(s, false) }, "I didn't install this"));
    } else {
      foot.append(
        h("button", { class: "btn outlined sm", title: "Windows will ask for your PIN, fingerprint, face or password", onclick: () => answer(s, true) }, s.kind === "network" ? "That was me" : "I set this up"),
        h("button", { class: "btn outlined sm", onclick: () => answer(s, false) }, "I didn't do this"),
      );
    }
    el.append(foot);
  }
  return el;
}

async function answer(subject, iDidThis) {
  try {
    await invoke("answer", { subjectId: subject.id, title: subject.title, iDidThis });
    if (iDidThis) trusted.add(subject.id); else trusted.delete(subject.id);
    toast(iDidThis
      ? "Noted in the timeline. From the next check it counts as yours, for as long as it stays exactly the same."
      : "Noted in the timeline that you did not set this up.");
    renderResults();
    loadStatus();
  } catch (e) {
    toast(String(e));
  }
}

async function openPage(page) {
  if (page === "timeline") return showTab("timeline");
  try {
    await invoke("open_windows_page", { page });
  } catch (e) {
    toast(String(e));
  }
}

// --- camera & mic --------------------------------------------------------------

function renderCamMic() {
  const root = $("cammic");
  $("cammicSection").hidden = !report;
  const rows = (report && report.cameraMic) || [];
  if (report && report.gaps.some((g) => g.area === "Whole check")) {
    root.replaceChildren(h("div", { class: "empty" }, "Not checked this time."));
    return;
  }
  if (!rows.length) {
    root.replaceChildren(h("div", { class: "empty" }, "No program has used the camera or microphone, as far as Windows recorded."));
    return;
  }
  const verdicts = new Map(report.findings.map((f) => [f.subject.id, f.evaluation.verdict.confidence]));
  root.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Program", "Device", "Last used", "Publisher signature", "Rating"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((s) => {
      const f = s.facts;
      const c = verdicts.get(s.id) || "UNLIKELY";
      return h("tr", {},
        h("td", {}, s.title.replace(/ used the (camera|microphone)$/, ""), h("div", { class: "detail" }, s.detail)),
        h("td", {}, f["pc.device"] === "webcam" ? "Camera" : "Microphone"),
        h("td", {}, f["pc.in_use_now"] ? "In use now" : `${when(f["pc.last_used_millis"])}`),
        h("td", {}, f["pc.packaged_app"] ? "Store app" : (f["pc.signature"] || "unknown") + (f["pc.signer"] ? ` (${f["pc.signer"]})` : "")),
        h("td", {}, h("span", { class: `badge ${c}` }, LABELS[c])),
      );
    })),
  )));
}

// --- timeline -------------------------------------------------------------------

async function loadTimeline() {
  let t;
  try { t = await invoke("get_timeline"); } catch (e) { return; }
  const problem = status && status.evidenceError;
  const ok = t.check.status === "INTACT" && !problem;
  $("chainStatus").replaceChildren(h("div", { class: `chain ${ok ? "ok" : "bad"}` },
    h("strong", {}, t.check.status !== "INTACT"
      ? `Chain broken at entry ${t.check.atSeq}: ${t.check.reason}. `
      : problem ? `${problem} ` : "Chain intact. "),
    `${t.entries.length} ${t.entries.length === 1 ? "entry" : "entries"}, signed by key ${t.keyId}.`,
    problem ? h("div", {},
      "Nothing new is added to a damaged timeline. Export it as it is for your records, then you can keep it aside and start a new timeline that begins by recording this problem. ",
      h("button", { class: "btn outlined sm", onclick: startNewTimeline }, "Keep it aside and start a new timeline")) : null,
  ), ...(t.warnings || []).map((w) => h("div", { class: "notice error" }, w)));
  $("btnCheckpoint").disabled = Boolean(problem);
  const root = $("timeline");
  if (!t.entries.length) {
    root.replaceChildren(h("div", { class: "empty" }, "Nothing recorded yet. Findings, changes and your answers appear here."));
    return;
  }
  root.replaceChildren(h("div", { class: "timeline" }, ...[...t.entries].reverse().map((e) => {
    const details = Object.entries(e.details || {});
    return h("div", { class: "entry" },
      h("div", {}, when(e.timestampMillis)),
      h("div", { class: "type" }, e.type.replace("_", " ")),
      h("div", {}, e.summary,
        details.length ? h("details", {}, h("summary", {}, "Details"),
          h("dl", { class: "evidence" }, details.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]),
            h("dt", {}, "entry hash"), h("dd", {}, e.entryHash))) : null),
    );
  })));
}

async function startNewTimeline() {
  try {
    await invoke("start_new_timeline");
    toast("The old timeline was kept aside and a new one started.");
    await loadStatus();
    loadTimeline();
  } catch (e) { toast(String(e)); }
}

// --- quick exit and app lock --------------------------------------------------------

function clearScreen() {
  // Nothing sensitive stays in the page behind a quick exit.
  report = null;
  changes = [];
  $("results").replaceChildren();
  $("lastRun").textContent = "";
  $("guidance").hidden = true;
  $("cammic").replaceChildren();
  $("cammicSection").hidden = true;
  $("timeline").replaceChildren();
  $("chainStatus").replaceChildren();
  $("checkpointBox").hidden = true;
  $("checkpointText").value = "";
  $("noteText").value = "";
  showTab("check");
}

async function quickExit() {
  clearScreen();
  try { await invoke("quick_exit"); } catch (e) { /* the window is hidden either way */ }
  await showLockIfNeeded();
}

async function showLockIfNeeded() {
  let locked = false;
  try { locked = await invoke("is_locked"); } catch (e) { locked = false; }
  $("lockScreen").hidden = !locked;
  return locked;
}

async function unlockApp() {
  try {
    await invoke("unlock");
    $("lockScreen").hidden = true;
    await loadAll();
  } catch (e) { toast(String(e)); }
}

async function loadAll() {
  await loadStatus();
  const last = await invoke("get_last_report");
  if (last) {
    report = last;
    renderResults();
    renderCamMic();
  }
}

// --- wiring -----------------------------------------------------------------------

function wire() {
  for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => showTab(b.dataset.tab));
  for (const b of document.querySelectorAll("[data-goto]")) b.addEventListener("click", () => showTab(b.dataset.goto));
  for (const b of document.querySelectorAll("[data-quick-exit]")) b.addEventListener("click", quickExit);
  $("btnCheck").addEventListener("click", () => runCheck(false));
  $("btnDeep").addEventListener("click", () => runCheck(true));
  $("btnCancelDeep").addEventListener("click", () => {
    $("btnCancelDeep").disabled = true;
    $("progressText").textContent = "Stopping the deep check and finishing the normal check…";
    invoke("cancel_deep_check");
  });
  $("btnSafetyOk").addEventListener("click", async () => {
    try { await invoke("safety_note_seen"); await loadStatus(); renderResults(); } catch (e) { toast(String(e)); }
  });
  $("btnExport").addEventListener("click", async () => {
    try {
      const path = await invoke("export_timeline");
      toast(`Saved to ${path}`);
      loadTimeline();
    } catch (e) { toast(String(e)); }
  });
  $("noteForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = $("noteText").value;
    try {
      await invoke("add_note", { text });
      $("noteText").value = "";
      loadTimeline();
    } catch (e) { toast(String(e)); }
  });
  $("watchToggle").addEventListener("change", async (ev) => {
    try { await invoke("set_watch", { enabled: ev.target.checked }); } catch (e) { toast(String(e)); }
    loadStatus();
  });
  $("signInToggle").addEventListener("change", async (ev) => {
    try { await invoke("set_start_at_sign_in", { enabled: ev.target.checked }); } catch (e) { toast(String(e)); }
    loadStatus();
  });
  $("btnQuickExit").addEventListener("click", quickExit);
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") quickExit(); });
  $("btnUnlock").addEventListener("click", unlockApp);
  $("btnLockExit").addEventListener("click", quickExit);
  window.addEventListener("focus", async () => {
    if (await showLockIfNeeded()) clearScreen();
  });
  $("btnCheckpoint").addEventListener("click", async () => {
    try {
      $("checkpointText").value = await invoke("make_checkpoint");
      $("checkpointBox").hidden = false;
      loadTimeline();
    } catch (e) { toast(String(e)); }
  });
  $("btnCopyCheckpoint").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("checkpointText").value);
      toast("Copied. Paste it into an email to yourself or a message to someone you trust.");
    } catch (e) {
      $("checkpointText").select();
      toast("Select the text and copy it with Ctrl+C.");
    }
  });
  $("btnCloseCheckpoint").addEventListener("click", () => {
    $("checkpointBox").hidden = true;
    $("checkpointText").value = "";
  });
  $("lockToggle").addEventListener("change", async (ev) => {
    try { await invoke("set_app_lock", { enabled: ev.target.checked }); } catch (e) { toast(String(e)); }
    loadStatus();
  });
  $("discreetToggle").addEventListener("change", async (ev) => {
    try { await invoke("set_discreet", { enabled: ev.target.checked }); } catch (e) { toast(String(e)); }
    loadStatus();
  });
  $("autoRulesToggle").addEventListener("change", async (ev) => {
    try { await invoke("set_auto_rule_updates", { enabled: ev.target.checked }); } catch (e) { toast(String(e)); }
    loadStatus();
  });
  $("btnCheckRules").addEventListener("click", async () => {
    $("btnCheckRules").disabled = true;
    try { toast(await invoke("check_rule_updates")); } catch (e) { toast(String(e)); }
    loadStatus();
  });
  $("btnRulesFile").addEventListener("click", () => $("rulesFiles").click());
  $("rulesFiles").addEventListener("change", async (ev) => {
    const files = [...ev.target.files];
    ev.target.value = "";
    const sig = files.find((f) => f.name.endsWith(".sig.json"));
    const bundle = files.find((f) => f !== sig && f.name.endsWith(".json"));
    if (!sig || !bundle) {
      toast("Choose both files: the rules (.json) and their signatures (.sig.json).");
      return;
    }
    try {
      toast(await invoke("install_rules_from_file", { bundle: await bundle.text(), signature: await sig.text() }));
    } catch (e) { toast(String(e)); }
    loadStatus();
  });
  listen("deep-phase", (ev) => {
    if (!$("progress").hidden && !$("btnCancelDeep").disabled && DEEP_PHASES[ev.payload]) {
      $("progressText").textContent = DEEP_PHASES[ev.payload];
    }
  });
  listen("rules-updated", () => { if ($("lockScreen").hidden) loadStatus(); });
  listen("locked", () => {
    clearScreen();
    $("lockScreen").hidden = false;
  });
  listen("check-finished", (ev) => {
    if (!$("lockScreen").hidden) return;
    applyResult(ev.payload);
    loadStatus();
  });
}

async function start() {
  wire();
  if (await showLockIfNeeded()) {
    // The window keeps the right name and icon while locked; nothing else shows.
    try {
      const s = await invoke("get_status");
      const n = s.discreet ? "Device Check" : "Phone Spy Guard";
      $("brandName").textContent = n;
      $("brandIcon").src = s.discreet ? "gear.svg" : "shield.svg";
      document.title = n;
    } catch (e) { /* stay generic */ }
    return;
  }
  await loadAll();
}

start().catch((e) => toast(String(e)));
