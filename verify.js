// HMN verify page: checks a certificate entirely in the visitor's browser.
// Kept in its own file so the page's Content-Security-Policy can forbid inline
// scripts: certificate fields come from whoever published them, and even if one
// slipped past esc() it could not run code on hmn.audio.
const API = "https://sczucnlruwppyxzvhypq.supabase.co/functions/v1";
// The log's public key, pinned here so a tampered server can't swap in its own.
const LOG_PUBKEY = "0818b6cae322d69a94dcea4453f95fd82c0ea0e0d0e9726d5a9ee215d26b3011";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const enc = new TextEncoder();
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
const sha = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const cat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const day = (ms) => new Date(ms).toLocaleString([], { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const date = (s) => new Date(s * 1000).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
// every number shown comes through here, so a certificate can't smuggle HTML in a number field
const num = (n) => (Number.isFinite(Number(n)) ? Number(n) : 0).toLocaleString();

async function ed25519(pubHex, sigHex, msg) {
  try {
    const key = await crypto.subtle.importKey("raw", unhex(pubHex), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, unhex(sigHex), msg);
  } catch { return null; } // this browser can't check Ed25519
}
const CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function shortId(d) {
  let bits = 0n; for (const b of d.slice(0, 5)) bits = (bits << 8n) | BigInt(b);
  let s = ""; for (let i = 7; i >= 0; i--) s += CROCK[Number((bits >> BigInt(i * 5)) & 31n)];
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}
const node = (l, r) => sha(cat(new Uint8Array([1]), l, r));
async function included(leaf, index, size, proof, root) {
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await node(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else r = await node(r, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && hex(r) === hex(root);
}
function strengthOf(c) {
  if (c.kind === "archive") return c.depth === "Built step by step" ? 3 : c.depth === "Audio only" ? 1 : 2;
  if (c.audio_witnessed === false) return 2;
  return c.depth === "Verified Pro" || c.depth === "Verified+" ? 5 : 4;
}

function card(c, id) {
  const arch = c.kind === "archive", ev = c.evidence || {}, n = strengthOf(c);
  const bars = Array.from({ length: 5 }, (_, i) => `<i class="${i < n ? "on" : ""}"></i>`).join("");
  const mins = ev.hands_on_minutes || 0, hands = mins >= 60 ? `${Math.floor(mins / 60)}h ${mins % 60}m` : `${mins}m`;
  const tiles = arch
    ? [[num(ev.versions), ev.versions === 1 ? "version found" : "versions found"], [date(ev.first_seen), "earliest file date"], [date(ev.last_seen), "last saved"], [new Date(ev.registered_ms).toLocaleDateString(), "registered with HMN"]]
    : [[num(ev.saves), "witnessed saves"], [hands, "hands-on time"], [num(ev.recorded_takes), "recorded takes"], [num(ev.midi_notes_played), "notes played"],
       ...(ev.minutes_heard ? [[`${ev.minutes_heard}m`, "of the DAW heard"]] : []), [new Date(ev.first_save_ms).toLocaleDateString(), "first save"]];
  return `<svg class="seal" viewBox="0 0 40 40" aria-hidden="true"><use href="#seal"/></svg>
    <p class="eyebrow">${arch ? "Archive certificate" : "Certificate of human creation"}</p>
    <div class="cid">${esc(id)}</div>
    ${c.project?.name ? `<h2>${esc(c.project.name)}</h2>` : `<h2 class="private">Name kept private</h2>`}
    <div class="line">${esc(c.tier)} · <span class="badge ${arch ? "arch" : ""}">${esc(c.depth)}</span> · ${esc(c.project?.daw)}${c.pre_ai_candidate ? ` · <span class="badge arch">Pre-AI candidate</span>` : ""}</div>
    <div class="strength" style="--fill:${arch ? "var(--archive)" : "var(--live)"}"><span class="sbar">${bars}</span><span class="s-num">${n}<small>/5</small></span>
      <span class="s-label">Proof strength · ${arch ? "Back catalog" : "HMN watched"}</span></div>
    <div class="grid">${tiles.map(([b, s]) => `<div><b>${esc(b)}</b><span>${esc(s)}</span></div>`).join("")}</div>
    ${c.audio_witnessed === false ? `<p class="note" style="color:var(--amber)">HMN witnessed this project, but not this audio being exported from it. The link is the creator's claim.</p>` : ""}
    ${ev.snapshots_matching_final ? `<p class="note">The final audio was heard taking shape in the DAW ${num(ev.snapshots_matching_final)} times while it was being made.</p>` : ""}
    ${arch ? `<p class="note">${esc(c.note)}</p>` : ""}
    ${c.project?.name_sealed ? `<p class="note">The creator keeps this beat's name private. The certificate holds only a sealed fingerprint of the name (<code>${esc(String(c.project.name_sealed).slice(0, 16))}…</code>), so the name can be revealed and checked later, but can't be read or guessed from this page.</p>` : ""}`;
}

async function verify(id) {
  $("#result").hidden = false;
  $("#lookup").hidden = true;
  let v;
  try {
    const res = await fetch(`${API}/verify?id=${encodeURIComponent(id)}`);
    v = await res.json();
    if (!res.ok) throw new Error(v.error || "not found");
  } catch (e) {
    $("#verdict").className = "verdict bad";
    $("#v-title").textContent = "No certificate found";
    $("#v-sub").textContent = `${id}: ${e.message}. Check the ID and try again.`;
    $("#card").hidden = true;
    $("#checks").innerHTML = "";
    return;
  }
  const c = JSON.parse(v.certificate.canonical);
  $("#card").innerHTML = card(c, v.certificate.id);
  document.title = `HMN · ${c.project?.name || id}`; // older certificates showed the name

  const checks = [];
  const add = (state, title, detail) => checks.push({ state, title, detail });

  // 1. the certificate's ID and signature match its exact contents
  const digest = await sha(enc.encode(v.certificate.canonical));
  const idOk = (c.kind === "archive" ? "A-" : "") + shortId(digest) === v.certificate.id;
  add(idOk ? "ok" : "bad", "ID matches the certificate's contents", idOk ? "Change a single character of the certificate and its ID would change." : "The contents don't match this ID.");
  const sigOk = await ed25519(c.ledger.device_pubkey, v.certificate.signature, digest);
  add(sigOk === null ? "wait" : sigOk ? "ok" : "bad", "Signed by the creator's machine",
    sigOk === null ? "This browser can't check Ed25519 signatures. Try a current Safari, Chrome or Firefox." : `Device key <code>${esc(String(c.ledger.device_pubkey).slice(0, 24))}…</code>`);

  // 2. the trail entries are in the public log (Merkle inclusion)
  const root = unhex(v.log.proof_root);
  let proven = 0;
  for (const e of v.events) {
    const data = `${c.ledger.device_pubkey}|${e.device_seq}|${e.event_hash}|${e.prev_hash}|${e.kind}|${e.client_ts_ms}|${e.server_ts_ms}|${e.sig}`;
    const leaf = await sha(cat(new Uint8Array([0]), enc.encode(data)));
    if (hex(leaf) === e.leaf_hash && (await included(leaf, e.idx, v.log.proof_tree_size, e.proof.map(unhex), root))) proven++;
  }
  const times = v.events.map((e) => e.server_ts_ms).sort((a, b) => a - b);
  const span = times.length ? (times.length > 1 ? `logged between ${day(times[0])} and ${day(times.at(-1))}` : `logged ${day(times[0])}`) : "";
  const allIn = proven === v.cited_total && proven > 0;
  add(allIn ? "ok" : proven ? "wait" : "bad", `${num(proven)} of ${num(v.cited_total)} trail entries proven in HMN's public log`,
    `Each entry was recomputed and traced to the log's root (Merkle inclusion), ${span}.`);

  // 3. the log's head is signed by HMN's log key
  const headOk = v.log.log_pubkey !== LOG_PUBKEY ? false : await ed25519(LOG_PUBKEY, v.log.head.sig, enc.encode(`hmn-tree-head|${v.log.head.size}|${v.log.head.root}|${v.log.head.ts_ms}`));
  add(headOk ? "ok" : headOk === null ? "wait" : "bad", "The public log's state is signed", `${num(v.log.head.size)} entries as of ${day(v.log.head.ts_ms)} · log key <code>${esc(v.log.log_pubkey.slice(0, 24))}…</code>`);

  // 4. Bitcoin anchor
  const a = v.log.anchor;
  if (a && a.status === "complete") {
    add("ok", `Anchored to Bitcoin block #${num(a.bitcoin_height)}`,
      `${a.block_time ? esc(new Date(a.block_time).toLocaleString()) + " · " : ""}<a href="https://mempool.space/block/${Number(a.bitcoin_height)}" target="_blank" rel="noopener">see the block</a> · <a href="#" id="ots">download the proof (.ots)</a>`);
  } else if (a) {
    add("wait", "Bitcoin stamp pending", `Stamped ${esc(a.day)}; Bitcoin confirms it within about a day. <a href="#" id="ots">Download the proof (.ots)</a>`);
  } else {
    add("wait", "Waiting for today's Bitcoin stamp", "The public log is stamped onto Bitcoin once a day.");
  }

  $("#checks").innerHTML = checks.map((k) => `<li class="${k.state}"><span class="mark">${k.state === "ok" ? "✓" : k.state === "bad" ? "✕" : "…"}</span><div><b>${k.title}</b><small>${k.detail}</small></div></li>`).join("");
  const otsLink = $("#ots");
  if (otsLink && a?.ots_file) otsLink.addEventListener("click", (ev) => {
    ev.preventDefault();
    const bytes = Uint8Array.from(atob(a.ots_file), (ch) => ch.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    Object.assign(document.createElement("a"), { href: url, download: `hmn-log-${a.day}.ots` }).click();
  });

  const bad = checks.some((k) => k.state === "bad");
  $("#verdict").className = `verdict ${bad ? "bad" : "ok"}`;
  $("#v-title").textContent = bad ? "Could not verify" : "Verified";
  $("#v-sub").textContent = bad
    ? "Something about this certificate doesn't check out. Details below."
    : c.kind === "archive"
      ? "This beat was registered with HMN; its record is in the public log and can't be changed."
      : "HMN witnessed this music being made. The certificate and its trail check out.";
}

// Drop a file: find certificates for exactly this file by its SHA-256, computed
// here. The file itself is never sent anywhere.
async function lookupFile(file) {
  const out = $("#drop-out");
  out.textContent = `Fingerprinting ${file.name}…`;
  let digest;
  try {
    digest = hex(await sha(await file.arrayBuffer()));
  } catch {
    out.textContent = "That file couldn't be read. Try a smaller file, or check it's downloaded to this computer.";
    return;
  }
  out.textContent = "Looking it up…";
  let r;
  try {
    const res = await fetch(`${API}/verify?sha=${digest}`);
    r = await res.json();
    if (!res.ok) throw new Error(r.error || "lookup failed");
  } catch (e) {
    out.textContent = `Couldn't look it up: ${e.message}`;
    return;
  }
  const certs = r.certificates || [];
  if (certs.length === 1) {
    location.search = `?c=${encodeURIComponent(certs[0].id)}`;
    return;
  }
  if (!certs.length) {
    out.textContent = "No published HMN certificate is for this exact file. A converted or re-exported copy (an MP3, a new mix) has a different fingerprint; ask the creator for the certificate link.";
    return;
  }
  out.innerHTML = `This exact file has ${certs.length} published certificates:<ul>${certs.map((c) =>
    `<li><a href="?c=${encodeURIComponent(c.id)}">${esc(c.id)}</a> · ${c.kind === "archive" ? "back catalog" : "HMN watched"}</li>`).join("")}</ul>`;
}
const drop = $("#drop");
$("#file").addEventListener("change", (e) => e.target.files[0] && lookupFile(e.target.files[0]));
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer.files[0]) lookupFile(e.dataTransfer.files[0]);
});

const params = new URLSearchParams(location.search);
const id = (params.get("c") || location.hash.slice(1) || "").toUpperCase();
if (/^(A-)?[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(id)) verify(id);
else $("#lookup").hidden = false;
$("#form").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("#cid").value.trim().toUpperCase();
  location.search = `?c=${encodeURIComponent(v)}`;
});
