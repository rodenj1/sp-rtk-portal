// Posts every <form data-action> as JSON, the only way the Portal accepts a
// state-changing request (JSON body, X-Portal-Action header, same Origin).
// Replies: {next: url} navigates, {step: name} shows that step's form,
// {error: message} shows the message.
"use strict";

function showError(root, message) {
  const el = root.querySelector("[data-error]") || document.querySelector("[data-error]");
  if (!el) return;
  el.textContent = message || "";
  el.hidden = !message;
}

function showStep(name) {
  document.querySelectorAll("form[data-step]").forEach((form) => {
    form.hidden = form.dataset.step !== name;
    if (!form.hidden) {
      const first = form.querySelector("input");
      if (first) first.focus();
    }
  });
}

async function submitAction(form) {
  const body = Object.fromEntries(new FormData(form).entries());
  const button = form.querySelector("button[type=submit]");
  if (button) button.disabled = true;
  try {
    const resp = await fetch(form.dataset.action, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Portal-Action": "1" },
      body: JSON.stringify(body),
    });
    let reply = {};
    try { reply = await resp.json(); } catch (e) { reply = {}; }
    if (reply.next) { window.location.assign(reply.next); return; }
    if (reply.step) showStep(reply.step);
    showError(document, reply.error || (resp.ok ? "" : "Something went wrong."));
    // A Turnstile answer is good for one try: get a fresh one after an error.
    if (!resp.ok && window.turnstile) window.turnstile.reset();
  } catch (e) {
    showError(document, "Network error. Please try again.");
  } finally {
    if (button) button.disabled = false;
  }
}

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.dataset.action) return;
  event.preventDefault();
  submitAction(form);
});
