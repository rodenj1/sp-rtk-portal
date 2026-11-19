// The Session bar: follows the Remote session over its status channel, a
// websocket on the Portal's own origin. While it is open the user counts as
// present; the base's tunnel closes once nobody has been present for the
// idle timeout. Once Connected, the base's own UI loads in a sandboxed frame
// (ADR 0004): an opaque origin, no popups, no top navigation. Base pages
// never talk to this page (no postMessage).
//
// The Portal decides every state (its clock, not the browser's); this script
// only shows them. A state is shown by the elements whose data-show lists it;
// elements with data-holds show only while the base holds its tunnel
// ("true": it comes back by itself) or only while it polls ("false": Wakes).
//
// Lease (ADR 0005): the frame's path token lives only while this bar renews
// it. The Portal asks for a renewal every 60 s (a status message with
// `renew`) and the bar answers on the channel, so a hidden tab's throttled
// timers don't matter. A session whose lease expired (the laptop slept), or
// a channel that dropped, is handled like a tunnel drop: one automatic
// reconnect (Open remotely again, then follow the new session), then the
// ended state.
"use strict";

(function () {
  const bar = document.querySelector("[data-session-bar]");
  if (!bar) return;
  // Ignore anything a framed page might post to us.
  window.addEventListener("message", (event) => event.stopImmediatePropagation(), true);

  const name = bar.dataset.name;
  const field = (f) => bar.querySelector("[data-field=" + f + "]");
  const status = field("status");
  const box = field("frame-box");
  // Never add allow-same-origin, allow-top-navigation or allow-popups.
  const SANDBOX = "allow-scripts allow-forms allow-downloads";
  // The page carries each view's label (the server words them once).
  const labels = JSON.parse(bar.dataset.labels || "{}");

  // Load the base's UI once Connected; keep it loaded (hidden) while
  // reconnecting after a tunnel drop, so its own scripts reconnect; unload it
  // when the session ends (or pauses).
  function frame(state, path) {
    let iframe = box.querySelector("iframe");
    if (state === "ended" || state === "none" || !path) {
      if (iframe) iframe.remove();
      return;
    }
    if (state !== "connected" || (iframe && iframe.dataset.path === path)) return;
    if (iframe) iframe.remove();
    iframe = document.createElement("iframe");
    iframe.setAttribute("sandbox", SANDBOX);
    iframe.setAttribute("referrerpolicy", "no-referrer");
    iframe.title = name + " (served by the base)";
    iframe.dataset.field = "frame";
    iframe.dataset.path = path;
    iframe.src = path;
    box.appendChild(iframe);
  }

  // Full screen: the frame fills the window and the bar steps aside, leaving
  // only "Exit full screen". Anything the user must see ends it.
  function fullScreen(on) {
    if (on) bar.dataset.fullscreen = "";
    else delete bar.dataset.fullscreen;
    field("exit-fullscreen").hidden = !on;
  }
  field("fullscreen").addEventListener("click", () => fullScreen(true));
  field("exit-fullscreen").addEventListener("click", () => fullScreen(false));

  function show(view) {
    bar.dataset.state = view;
    status.textContent = labels[view] || view;
    bar.querySelectorAll("[data-show]").forEach((el) => {
      el.hidden = !el.dataset.show.split(" ").includes(view);
    });
    holds(bar.dataset.holds);
  }

  function holds(value) {
    bar.dataset.holds = value;
    bar.querySelectorAll("[data-holds]").forEach((el) => {
      if (el !== bar) el.hidden = el.dataset.holds !== value;
    });
  }

  function presence(others) {
    const el = field("presence");
    el.textContent = others.length
      ? "Also connected: " + others.map((p) => p.name + " (" + p.role + ")").join(", ")
      : "";
    el.hidden = !others.length;
  }

  function update(msg) {
    // A session the hard cap ended is shown as paused, with Reconnect; one
    // ended because remote access was paused on the base says so (#92).
    const endedAs = { hard_cap: "paused", paused: "remote_paused" };
    const view = (msg.state === "ended" && endedAs[msg.reason]) || msg.state;
    show(view);
    frame(msg.state, msg.frame);
    const stillThere = Boolean(msg.still_there) && msg.state !== "ended";
    field("still-there").hidden = !stillThere;
    if (view !== "connected" || stillThere) fullScreen(false);
    presence(msg.state === "ended" ? [] : msg.present || []);
    if (msg.last_seen) field("last-seen").textContent = msg.last_seen;
    if (msg.connection) field("connection").textContent = msg.connection;
    if (typeof msg.holds === "boolean") holds(String(msg.holds));
  }

  // No Remote session (yet): nothing to follow.
  if (["none", "ended", "offline", "remote_paused"].includes(bar.dataset.state)) return;
  const base = "/bases/" + encodeURIComponent(bar.dataset.base);
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  let reconnects = 1; // automatic reconnects left; back to one once Connected
  let leaving = false;
  window.addEventListener("pagehide", () => { leaving = true; });

  function follow() {
    let over = false; // the Portal said it ended: its close is expected
    const channel = new WebSocket(scheme + "//" + location.host + base + "/session");
    channel.addEventListener("message", (event) => {
      let msg = {};
      try { msg = JSON.parse(event.data); } catch (e) { return; }
      if (msg.renew) channel.send(JSON.stringify({ type: "renew" }));
      if (!msg.state) return;
      if (msg.state === "connected") reconnects = 1;
      if (msg.state === "ended") {
        over = true;
        if (msg.reason === "lease_expired" && reconnect()) return;
      }
      update(msg);
    });
    channel.addEventListener("close", () => {
      if (over || leaving) return;
      if (!reconnect()) update({ state: "ended" });
    });
  }

  function reconnect() {
    if (reconnects < 1) return false;
    reconnects -= 1;
    update({ state: "reconnecting" });
    fetch(base + "/remote", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Portal-Action": "1" },
      body: "{}",
    })
      .then((resp) => { if (resp.ok) follow(); else update({ state: "ended" }); })
      .catch(() => update({ state: "ended" }));
    return true;
  }

  follow();
})();
