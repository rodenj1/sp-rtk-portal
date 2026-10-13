// The Session bar: follows the Remote session over its status channel, a
// websocket on the Portal's own origin. While it is open the user counts as
// present; the base's tunnel closes once nobody has been present for the
// idle timeout. Base pages never talk to this page (no postMessage).
"use strict";

(function () {
  const bar = document.querySelector("[data-session-bar]");
  if (!bar) return;
  const name = bar.dataset.name;
  const status = bar.querySelector("[data-field=status]");
  const labels = {
    waking: "Waking " + name + "…",
    connected: "Connected",
    ended: "Session ended",
    none: "Not connected",
  };

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
    if (msg.state) show(msg.state, msg.reason);
  });
  // Ignore anything a framed page might post to us.
  window.addEventListener("message", (event) => event.stopImmediatePropagation(), true);
})();
