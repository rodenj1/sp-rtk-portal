// The Session bar: follows the Remote session over its status channel, a
// websocket on the Portal's own origin. While it is open the user counts as
// present; the base's tunnel closes once nobody has been present for the
// idle timeout. Once Connected, the base's own UI loads in a sandboxed frame
// (ADR 0004): an opaque origin, no popups, no top navigation. Base pages
// never talk to this page (no postMessage).
"use strict";

(function () {
  const bar = document.querySelector("[data-session-bar]");
  if (!bar) return;
  const name = bar.dataset.name;
  const status = bar.querySelector("[data-field=status]");
  const box = bar.querySelector("[data-field=frame-box]");
  // Never add allow-same-origin, allow-top-navigation or allow-popups.
  const SANDBOX = "allow-scripts allow-forms allow-downloads";
  const labels = {
    waking: "Waking " + name + "…",
    connected: "Connected",
    ended: "Session ended",
    none: "Not connected",
  };

  // Load the base's UI once Connected; keep it loaded (hidden) while Waking
  // again after a tunnel drop, so its own scripts reconnect; unload it when
  // the session ends.
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

  const reasons = {
    paused: "Remote access was paused on the base",
  };

  function show(state, reason) {
    bar.dataset.state = state;
    status.textContent =
      (state === "ended" && reasons[reason]) || labels[state] || state;
    bar.querySelectorAll("[data-show]").forEach((el) => {
      el.hidden = !el.dataset.show.split(" ").includes(state);
    });
  }

  if (bar.dataset.state === "none" || bar.dataset.state === "ended") return;
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const channel = new WebSocket(
    scheme + "//" + location.host + "/bases/" + encodeURIComponent(bar.dataset.base) + "/session"
  );
  channel.addEventListener("message", (event) => {
    let msg = {};
    try { msg = JSON.parse(event.data); } catch (e) { return; }
    if (msg.state) {
      show(msg.state, msg.reason);
      frame(msg.state, msg.frame);
    }
  });
  // Ignore anything a framed page might post to us.
  window.addEventListener("message", (event) => event.stopImmediatePropagation(), true);
})();
