// Local access on the base list (ticket #97). Chrome and Edge can ask a base
// on this LAN who it is: a Local Network Access fetch to its identity
// endpoint at its primary LAN address. A base that answers with its own <id>
// is reachable here, so Open locally becomes the way in.
//
// The Portal never prompts on its own: it checks quietly only when the
// browser already granted the local-network permission, and otherwise shows
// "Detect bases on this network", whose click is what may prompt. Browsers
// without that permission (Firefox, Safari, iOS) never check; they keep the
// plain Open locally link.
"use strict";

const PERMISSIONS = ["local-network", "local-network-access"];
const CHECK_TIMEOUT_MS = 5000;

async function permissionState() {
  if (!navigator.permissions) return null;
  for (const name of PERMISSIONS) {
    try {
      return (await navigator.permissions.query({ name })).state;
    } catch (e) {
      // Not a permission this browser knows: try the next name.
    }
  }
  return null;
}

function show(choices, state) {
  choices.dataset.local = state;
  choices.querySelectorAll("[data-local-show]").forEach((el) => {
    el.hidden = el.dataset.localShow !== state;
  });
}

async function check(choices) {
  const base = choices.closest("[data-base]");
  try {
    const resp = await fetch(choices.dataset.identity, {
      targetAddressSpace: "local",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
    });
    if (!resp.ok) return;
    const identity = await resp.json();
    if (base && identity && identity.id === base.dataset.base) show(choices, "confirmed");
  } catch (e) {
    // Unreachable, refused or not this browser's LAN: stays unconfirmed.
  }
}

function checkAll() {
  return Promise.all(Array.from(document.querySelectorAll("[data-identity]"), check));
}

async function start() {
  if (!document.querySelector("[data-identity]")) return;
  const state = await permissionState();
  if (state === "granted") {
    await checkAll();
    return;
  }
  const detect = document.querySelector("[data-detect]");
  if (state !== "prompt" || !detect) return;
  detect.hidden = false;
  const button = detect.querySelector("button");
  button.addEventListener("click", async () => {
    button.disabled = true;
    await checkAll();
    detect.hidden = (await permissionState()) === "granted";
    button.disabled = false;
  });
}

start();
