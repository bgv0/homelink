"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
let state = null;
let busy = false;
let settingsLoaded = false;

// ---------- helpers ----------

function toast(msg, isError = false) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.toggle("error", isError);
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), isError ? 7000 : 3000);
}

function bytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

/** Run an action with buttons disabled; show errors as a toast. */
async function act(button, fn) {
  if (busy) return;
  busy = true;
  const label = button && button.textContent;
  if (button) { button.disabled = true; }
  try {
    await fn();
  } catch (e) {
    toast(String(e), true);
  } finally {
    busy = false;
    if (button) { button.disabled = false; button.textContent = label; }
    await refresh();
  }
}

/** In-app confirm (window.confirm isn't reliable in every webview). */
function ask(text) {
  return new Promise((resolve) => {
    const d = $("confirm-dialog");
    $("confirm-text").textContent = text;
    const done = (v) => {
      d.close();
      $("confirm-yes").onclick = $("confirm-no").onclick = d.oncancel = null;
      resolve(v);
    };
    $("confirm-yes").onclick = () => done(true);
    $("confirm-no").onclick = () => done(false);
    d.oncancel = (ev) => { ev.preventDefault(); done(false); };
    d.showModal();
  });
}

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}

// ---------- tabs ----------

function showTab(name) {
  for (const b of document.querySelectorAll(".tabs button")) {
    b.setAttribute("aria-selected", String(b.dataset.tab === name));
  }
  $("panel-share").hidden = name !== "share";
  $("panel-connect").hidden = name !== "connect";
  try { localStorage.setItem("tab", name); } catch (_) {}
}

for (const b of document.querySelectorAll(".tabs button")) {
  b.addEventListener("click", () => showTab(b.dataset.tab));
}

// ---------- rendering ----------

function render() {
  if (!state) return;
  const s = state.sharing;

  // Share hero
  $("share-title").textContent = s ? "Sharing" : "Not sharing";
  $("share-sub").textContent = s
    ? `Paired devices can use this computer's internet. This device: ${state.device}`
    : "Let your other devices use this computer's internet connection.";
  $("share-toggle").textContent = s ? "Stop sharing" : "Start sharing";
  $("share-toggle").classList.toggle("primary", !s);
  $("share-toggle").closest(".hero").classList.toggle("on", !!s);
  $("share-status").hidden = !s;
  if (s) {
    $("share-address").textContent = s.address ? `${s.address} : ${s.port} (UDP)` : `Unknown (UDP port ${s.port})`;
    const r = $("share-router");
    r.textContent = s.router;
    r.className = s.router_ok === true ? "ok" : s.router_ok === false ? "warn" : "";
    $("share-traffic").textContent = `↑ ${bytes(s.down)} sent to devices · ↓ ${bytes(s.up)} from devices`;
  }

  // Devices
  const dl = $("device-list");
  dl.replaceChildren(
    ...state.devices.map((d) =>
      el("li", {},
        el("span", { class: `dot ${d.online ? "on" : ""}`, title: d.online ? "Connected" : "Offline" }),
        el("div", { class: "grow" }, el("div", {}, d.name), el("div", { class: "sub" }, `${d.short}${d.online ? " · connected" : ""}`)),
        el("button", {
          class: "danger",
          onclick: async (ev) => {
            if (!(await ask(`Remove ${d.name}? It will be disconnected and need a new invite.`))) return;
            act(ev.target, () => invoke("revoke", { id: d.id }));
          },
        }, "Remove"),
      ),
    ),
  );
  $("device-empty").hidden = state.devices.length > 0;

  // Settings (only fill once so we don't overwrite the user's typing)
  if (!settingsLoaded) {
    const st = state.settings;
    $("set-port").value = st.port;
    $("set-address").value = st.public_addr || "";
    $("set-upnp").checked = st.upnp;
    $("set-approval").checked = st.require_approval;
    $("set-lan").checked = st.allow_lan;
    $("set-launch").checked = st.share_on_launch;
    $("set-autostart").checked = state.autostart;
    settingsLoaded = true;
  }

  // Connect
  const c = state.connection;
  $("conn-title").textContent = c ? (c.connected ? `Connected to ${c.host}` : `Reconnecting to ${c.host}…`) : "Not connected";
  $("conn-sub").textContent = c
    ? [
        c.rtt_ms != null ? `Ping ${c.rtt_ms} ms` : null,
        `↑ ${bytes(c.up)} ↓ ${bytes(c.down)}`,
        c.system_proxy ? "Apps on this computer go through the host" : `Proxy at ${c.socks} (SOCKS5)`,
      ].filter(Boolean).join(" · ")
    : "Connect to a computer that's sharing its internet.";
  $("conn-disconnect").hidden = !c;
  $("conn-card").classList.toggle("on", !!(c && c.connected));

  const hl = $("host-list");
  hl.replaceChildren(
    ...state.hosts.map((h) => {
      const active = c && c.host === h.name;
      return el("li", {},
        el("span", { class: `dot ${active && c.connected ? "on" : ""}` }),
        el("div", { class: "grow" }, el("div", {}, h.name), el("div", { class: "sub" }, `${h.addr}:${h.port}`)),
        active
          ? el("span", { class: "muted" }, "Active")
          : el("button", {
              class: "primary",
              onclick: (ev) => act(ev.target, async () => {
                ev.target.textContent = "Connecting…";
                await invoke("connect", { name: h.name, systemProxy: $("use-system-proxy").checked });
              }),
            }, "Connect"),
        el("button", {
          class: "danger",
          title: "Forget this host",
          onclick: async (ev) => {
            if (!(await ask(`Forget ${h.name}? You'll need a new invite to add it again.`))) return;
            act(ev.target, () => invoke("remove_host", { name: h.name }));
          },
        }, "✕"),
      );
    }),
  );
  $("host-empty").hidden = state.hosts.length > 0;
}

async function refresh() {
  try {
    state = await invoke("overview");
    render();
  } catch (e) {
    toast(String(e), true);
  }
}

// ---------- actions ----------

$("share-toggle").addEventListener("click", (ev) =>
  act(ev.target, async () => {
    if (state && state.sharing) {
      await invoke("stop_sharing");
    } else {
      ev.target.textContent = "Starting…";
      await invoke("start_sharing");
    }
  }),
);

$("invite-btn").addEventListener("click", (ev) =>
  act(ev.target, async () => {
    const code = await invoke("create_invite", { minutes: 15 });
    $("invite-code").textContent = code;
    $("invite-box").hidden = false;
    if (!state.sharing) toast("Remember to start sharing so the device can connect.");
  }),
);

$("invite-copy").addEventListener("click", async () => {
  const text = $("invite-code").textContent;
  try {
    await navigator.clipboard.writeText(text);
    toast("Invite code copied.");
    return;
  } catch (_) {}
  // Fallback for webviews without the async clipboard API.
  const ta = el("textarea");
  ta.value = text;
  document.body.append(ta);
  ta.select();
  const ok = document.execCommand("copy");
  ta.remove();
  toast(ok ? "Invite code copied." : "Select the code and copy it.", !ok);
});

$("check-btn").addEventListener("click", (ev) =>
  act(ev.target, async () => {
    ev.target.textContent = "Checking…";
    const r = await invoke("check_network");
    $("check-lan").textContent = r.lan_ip || "unknown";
    $("check-public").textContent = r.public_ip || "unknown";
    $("check-wan").textContent = r.router_wan_ip || (r.upnp ? "unknown" : "router doesn't say (UPnP off)");
    const v = $("check-verdict");
    v.textContent = {
      Forwardable: "Your router has a public address, so port forwarding should work.",
      Cgnat: "Your internet provider uses CGNAT (a shared address). Port forwarding can't work on this connection. Ask your provider for a public IPv4 address.",
      DoubleNat: "There are two routers in a row. Forward the port on both, or put the first one in bridge mode.",
      Unknown: "Couldn't ask your router (UPnP is off). Forward the port by hand, then test from another network such as a phone hotspot.",
      NoInternet: "Couldn't reach the internet to check your public address.",
    }[r.verdict];
    v.className = r.verdict === "Forwardable" ? "ok" : r.verdict === "Cgnat" ? "bad" : "warn";
    $("check-result").hidden = false;
  }),
);

$("settings-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const button = ev.target.querySelector("button[type=submit]");
  act(button, async () => {
    const settings = {
      port: Number($("set-port").value),
      public_addr: $("set-address").value.trim() || null,
      upnp: $("set-upnp").checked,
      require_approval: $("set-approval").checked,
      allow_lan: $("set-lan").checked,
      share_on_launch: $("set-launch").checked,
    };
    await invoke("save_settings", { settings });
    if ($("set-autostart").checked !== state.autostart) {
      await invoke("set_autostart", { enabled: $("set-autostart").checked });
    }
    toast(state.sharing ? "Saved. Stop and start sharing to apply." : "Saved.");
  });
});

$("conn-disconnect").addEventListener("click", (ev) => act(ev.target, () => invoke("disconnect")));

$("add-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const button = ev.target.querySelector("button[type=submit]");
  act(button, async () => {
    button.textContent = "Waiting for host…";
    $("add-note").textContent = "The host may need to approve this device.";
    try {
      const saved = await invoke("add_host", {
        code: $("add-code").value,
        name: $("add-name").value.trim() || null,
      });
      $("add-code").value = "";
      $("add-name").value = "";
      $("add-card").open = false;
      toast(`Added ${saved.name}. Click Connect to use it.`);
    } finally {
      $("add-note").textContent = "";
    }
  });
});

// ---------- pairing approvals (host) ----------

const pairQueue = [];

function showNextPair() {
  const d = $("pair-dialog");
  if (d.open || pairQueue.length === 0) return;
  const req = pairQueue[0];
  $("pair-name").textContent = req.name || "A device";
  $("pair-id").textContent = req.device;
  d.showModal();
}

function answerPair(allow) {
  const req = pairQueue.shift();
  $("pair-dialog").close();
  if (req) invoke("answer_pair", { request: req.request, allow }).finally(refresh);
  showNextPair();
}

$("pair-allow").addEventListener("click", () => answerPair(true));
$("pair-deny").addEventListener("click", () => answerPair(false));
$("pair-dialog").addEventListener("cancel", (ev) => { ev.preventDefault(); answerPair(false); });

listen("pair-request", (ev) => {
  showTab("share");
  pairQueue.push(ev.payload);
  showNextPair();
});

listen("pair-request-done", (ev) => {
  const i = pairQueue.findIndex((r) => r.request === ev.payload);
  if (i === 0 && $("pair-dialog").open) { $("pair-dialog").close(); }
  if (i >= 0) pairQueue.splice(i, 1);
  showNextPair();
});

// ---------- start ----------

try { showTab(localStorage.getItem("tab") || "share"); } catch (_) { showTab("share"); }
refresh();
setInterval(() => { if (!busy && !document.hidden) refresh(); }, 1500);
