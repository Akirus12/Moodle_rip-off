// static/messages/messages.js

document.addEventListener("DOMContentLoaded", () => {
  const cfg = window.MESSAGING_CONFIG || {};

  const els = {
    contacts: document.getElementById("contacts"),
    chat: document.getElementById("chat"),
    chatName: document.getElementById("chat-name"),
    messageInput: document.getElementById("messageInput"),
    composer: document.getElementById("composer"),
    recipientId: document.getElementById("recipientId"),
    btnBroadcast: document.getElementById("btnBroadcast"),
    btnSchedule: document.getElementById("btnSchedule"),
    msgMenu: document.getElementById("msgMenu"),
    msgEditBtn: document.getElementById("msgEditBtn"),
    msgDeleteBtn: document.getElementById("msgDeleteBtn"),
    search: document.getElementById("search"),

    // schedule modal
    scheduleModal: document.getElementById("scheduleModal"),
    schedulePreview: document.getElementById("schedulePreview"),
    hourValue: document.getElementById("hourValue"),
    minuteValue: document.getElementById("minuteValue"),
    hourUp: document.getElementById("hourUp"),
    hourDown: document.getElementById("hourDown"),
    minuteUp: document.getElementById("minuteUp"),
    minuteDown: document.getElementById("minuteDown"),

    // broadcast modal
    broadcastModal: document.getElementById("broadcastModal"),
    bwStep1: document.getElementById("bwStep1"),
    bwStep2: document.getElementById("bwStep2"),
    broadcastStep1: document.getElementById("broadcastStep1"),
    broadcastStep2: document.getElementById("broadcastStep2"),
    broadcastContactList: document.getElementById("broadcastContactList"),
    broadcastText: document.getElementById("broadcastText"),
  };

  const state = {
    msgMenu: { open: false, msgId: null },
    schedule: { hour: null, minute: null, broadcastMode: false },
    broadcast: { selected: new Set() },
  };

  const activeContactId = els.chat?.dataset.activeContactId || null;

  // --- helpers ---
  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (m) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[m]);
  }

  function toast(msg) {
    const el = document.createElement("div");
    el.textContent = msg;
    Object.assign(el.style, {
      position: "fixed",
      bottom: "18px",
      left: "50%",
      transform: "translateX(-50%)",
      background: "rgba(15,23,42,.85)",
      color: "var(--text)",
      padding: "10px 14px",
      borderRadius: "10px",
      border: "1px solid rgba(148,163,184,.25)",
      zIndex: 9999,
    });
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 2200);
  }

  function getCsrfToken() {
    return cfg.csrfToken || "";
  }

  function formatNowHHMM() {
    const n = new Date();
    const p = (v) => String(v).padStart(2, "0");
    return `${p(n.getHours())}:${p(n.getMinutes())}`;
  }

  // --- change active contact (reload with ?contact=id) ---
  if (els.contacts) {
    els.contacts.addEventListener("click", (e) => {
      const btn = e.target.closest(".contact");
      if (!btn) return;
      const id = btn.dataset.contactId;
      const url = new URL(window.location.href);
      url.searchParams.set("contact", id);
      window.location = url.toString();
    });
  }

  // --- simple search filter (client-side) ---
  if (els.search && els.contacts) {
    els.search.addEventListener("input", (e) => {
      const q = e.target.value.toLowerCase();
      for (const btn of els.contacts.querySelectorAll(".contact")) {
        const name = btn.querySelector("h4")?.textContent.toLowerCase() || "";
        btn.style.display = name.includes(q) ? "" : "none";
      }
    });
  }

  // --- send immediate message (AJAX) ---
  if (els.composer) {
    els.composer.addEventListener("submit", async (e) => {
      e.preventDefault();
      const recipientId = els.recipientId?.value;
      const text = (els.messageInput?.value || "").trim();
      if (!recipientId || !text) return;

      try {
        const res = await fetch(cfg.sendUrl, {
          method: "POST",
          headers: {
            "X-CSRFToken": getCsrfToken(),
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            recipient_id: recipientId,
            text,
            is_scheduled: "0",
          }),
        });

        const data = await res.json();
        if (!data.ok) {
          toast(data.error || "Error sending message");
          return;
        }

        const bubble = document.createElement("div");
        bubble.className = "bubble from-me";
        bubble.dataset.msgId = data.id;
        bubble.tabIndex = 0;
        bubble.innerHTML =
          `<div>${escapeHtml(text).replace(/\n/g, "<br>")}</div>` +
          `<div class="meta"><span>${data.time}</span></div>`;

        els.chat.appendChild(bubble);
        els.chat.scrollTop = els.chat.scrollHeight;
        els.messageInput.value = "";
      } catch (err) {
        console.error(err);
        toast("Network error");
      }
    });
  }

  // --- message menu (edit / delete) ---

  function showMsgMenuAt(bubbleEl, msgId) {
    state.msgMenu = { open: true, msgId };
    const rect = bubbleEl.getBoundingClientRect();
    const menu = els.msgMenu;
    const top = Math.min(window.innerHeight - 10, rect.bottom + 6);
    const left = Math.min(window.innerWidth - 10, rect.right - 140);
    Object.assign(menu.style, { top: `${top}px`, left: `${left}px` });
    menu.classList.add("open");
    menu.setAttribute("aria-hidden", "false");
    els.msgEditBtn.focus();
  }

  function hideMsgMenu() {
    const menu = els.msgMenu;
    menu.classList.remove("open");
    menu.setAttribute("aria-hidden", "true");
    menu.style.top = "-9999px";
    menu.style.left = "-9999px";
    state.msgMenu = { open: false, msgId: null };
  }

  if (els.chat) {
    els.chat.addEventListener("click", (e) => {
      const bubble = e.target.closest(".bubble.from-me");
      if (!bubble) {
        hideMsgMenu();
        return;
      }
      showMsgMenuAt(bubble, bubble.dataset.msgId);
    });

    els.chat.addEventListener("keydown", (e) => {
      if (
        (e.key === "Enter" || e.key === " ") &&
        e.target.classList.contains("from-me")
      ) {
        e.preventDefault();
        const bubble = e.target;
        showMsgMenuAt(bubble, bubble.dataset.msgId);
      }
    });
  }

  document.addEventListener("click", (e) => {
    if (!state.msgMenu.open) return;
    if (!e.target.closest("#msgMenu") && !e.target.closest(".bubble.from-me")) {
      hideMsgMenu();
    }
  });

  // Edit
  if (els.msgEditBtn) {
    els.msgEditBtn.addEventListener("click", async () => {
      const msgId = state.msgMenu.msgId;
      if (!msgId) return hideMsgMenu();

      const bubble = els.chat.querySelector(`.bubble[data-msg-id="${msgId}"]`);
      if (!bubble) return hideMsgMenu();

      const current = bubble.querySelector("div")?.innerText || "";
      const next = prompt("Edit your message:", current);
      if (next === null) return hideMsgMenu();
      const trimmed = next.trim();
      if (!trimmed) {
        toast("Message not changed (empty).");
        return hideMsgMenu();
      }

      const url = `${cfg.editUrlTemplate}${msgId}/`;
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "X-CSRFToken": getCsrfToken(),
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({ text: trimmed }),
        });
        const data = await res.json();
        if (!data.ok) {
          toast(data.error || "Edit failed");
        } else {
          bubble.querySelector("div").innerHTML =
            escapeHtml(trimmed).replace(/\n/g, "<br>");
          const meta = bubble.querySelector(".meta");
          meta.innerHTML = `<span>${data.time}</span><span>• edited</span>`;
        }
      } catch (err) {
        console.error(err);
        toast("Network error");
      }
      hideMsgMenu();
    });
  }

  // Delete
  if (els.msgDeleteBtn) {
    els.msgDeleteBtn.addEventListener("click", async () => {
      const msgId = state.msgMenu.msgId;
      if (!msgId) return hideMsgMenu();

      const url = `${cfg.deleteUrlTemplate}${msgId}/`;
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "X-CSRFToken": getCsrfToken(),
            "X-Requested-With": "XMLHttpRequest",
          },
        });
        const data = await res.json();
        if (!data.ok) {
          toast(data.error || "Delete failed");
        } else {
          const bubble = els.chat.querySelector(
            `.bubble[data-msg-id="${msgId}"]`
          );
          if (bubble) bubble.remove();
        }
      } catch (err) {
        console.error(err);
        toast("Network error");
      }
      hideMsgMenu();
    });
  }

    // ============================================================
  // SCHEDULE MODAL (simple arrows)
  // ============================================================

  const SCHEDULE_MINUTE_STEP = 5;

  function initSchedule(broadcastMode) {
    state.schedule.broadcastMode = !!broadcastMode;

    const now = new Date();
    let hour = now.getHours();
    let minute = Math.round(now.getMinutes() / SCHEDULE_MINUTE_STEP) * SCHEDULE_MINUTE_STEP;
    if (minute >= 60) {
      minute = 0;
      hour = (hour + 1) % 24;
    }

    state.schedule.hour = hour;
    state.schedule.minute = minute;

    updateScheduleUI();
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function updateScheduleUI() {
    if (!els.hourValue || !els.minuteValue || !els.schedulePreview) return;

    const h = state.schedule.hour;
    const m = state.schedule.minute;

    els.hourValue.textContent = h != null ? pad2(h) : "--";
    els.minuteValue.textContent = m != null ? pad2(m) : "--";

    if (h == null || m == null) {
      els.schedulePreview.textContent = "Will send at —:—";
    } else {
      els.schedulePreview.textContent = `Will send at ${pad2(h)}:${pad2(m)}`;
    }
  }

  function changeHour(delta) {
    if (state.schedule.hour == null) state.schedule.hour = 0;
    let h = (state.schedule.hour + delta) % 24;
    if (h < 0) h += 24;
    state.schedule.hour = h;
    updateScheduleUI();
  }

  function changeMinute(delta) {
    if (state.schedule.minute == null) state.schedule.minute = 0;
    let m = state.schedule.minute + delta * SCHEDULE_MINUTE_STEP;
    // wrap 0..55 in steps of SCHEDULE_MINUTE_STEP
    const max = 60 - SCHEDULE_MINUTE_STEP;
    if (m > max) m = 0;
    if (m < 0) m = max;
    state.schedule.minute = m;
    updateScheduleUI();
  }

  function openScheduleInternal(broadcastMode) {
    if (!els.scheduleModal) {
      toast("Schedule UI not available.");
      return;
    }
    initSchedule(broadcastMode);
    els.scheduleModal.classList.add("open");
    els.scheduleModal.setAttribute("aria-hidden", "false");
  }

  function closeScheduleInternal() {
    if (!els.scheduleModal) return;
    els.scheduleModal.classList.remove("open");
    els.scheduleModal.setAttribute("aria-hidden", "true");
  }

  async function confirmScheduleInternal() {
    const { hour, minute, broadcastMode } = state.schedule;
    if (hour == null || minute == null) {
      toast("Please choose time.");
      return;
    }
    const timeStr = `${pad2(hour)}:${pad2(minute)}`;

    if (!broadcastMode) {
      // Schedule single direct message
      const recipientId = els.recipientId?.value;
      let text = (els.messageInput?.value || "").trim();
      if (!recipientId) {
        toast("No recipient selected.");
        closeScheduleInternal();
        return;
      }
      if (!text) {
        text = "(scheduled message)";
      }

      try {
        const res = await fetch(cfg.sendUrl, {
          method: "POST",
          headers: {
            "X-CSRFToken": getCsrfToken(),
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            recipient_id: recipientId,
            text,
            is_scheduled: "1",
            scheduled_for: timeStr,
          }),
        });

        const data = await res.json();
        if (!data.ok) {
          toast(data.error || "Error scheduling message");
          return;
        }

        // Show scheduled bubble immediately
        const bubble = document.createElement("div");
        bubble.className = "bubble from-me";
        bubble.dataset.msgId = data.id;
        bubble.tabIndex = 0;
        bubble.innerHTML =
          `<div>${escapeHtml(text).replace(/\n/g, "<br>")}</div>` +
          `<div class="meta"><span>${timeStr}</span><span>• scheduled</span></div>`;
        els.chat.appendChild(bubble);
        els.chat.scrollTop = els.chat.scrollHeight;
        els.messageInput.value = "";
        toast(`Message scheduled for ${timeStr}.`);
      } catch (err) {
        console.error(err);
        toast("Network error");
      }
    } else {
      // Schedule broadcast (optional, if you use it)
      if (!cfg.isTeacherOrAdmin) {
        toast("Only teachers/admins can broadcast.");
        closeScheduleInternal();
        return;
      }

      const text = (els.broadcastText?.value || "").trim();
      if (!text) {
        toast("Type a message to broadcast.");
        return;
      }
      if (!state.broadcast.selected.size) {
        toast("Select at least one contact.");
        return;
      }

      try {
        const params = new URLSearchParams();
        params.append("text", text);
        state.broadcast.selected.forEach((id) =>
          params.append("recipients[]", id)
        );
        params.append("is_scheduled", "1");
        params.append("scheduled_for", timeStr);

        const res = await fetch(cfg.broadcastUrl, {
          method: "POST",
          headers: {
            "X-CSRFToken": getCsrfToken(),
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: params,
        });

        const data = await res.json();
        if (!data.ok) {
          toast(data.error || "Failed to schedule broadcast");
        } else {
          toast(
            `Scheduled broadcast for ${timeStr} to ${
              data.count || state.broadcast.selected.size
            } contact(s).`
          );
        }
      } catch (err) {
        console.error(err);
        toast("Network error");
      }
    }

    closeScheduleInternal();
  }

  // Hook main Schedule button in composer
  if (els.btnSchedule) {
    els.btnSchedule.addEventListener("click", () => {
      openScheduleInternal(false);
    });
  }

  // Arrows
  if (els.hourUp) {
    els.hourUp.addEventListener("click", () => changeHour(+1));
  }
  if (els.hourDown) {
    els.hourDown.addEventListener("click", () => changeHour(-1));
  }
  if (els.minuteUp) {
    els.minuteUp.addEventListener("click", () => changeMinute(+1));
  }
  if (els.minuteDown) {
    els.minuteDown.addEventListener("click", () => changeMinute(-1));
  }

  // Close on backdrop click
  if (els.scheduleModal) {
    els.scheduleModal.addEventListener("click", (e) => {
      if (e.target.id === "scheduleModal") closeScheduleInternal();
    });
  }

  // Expose to inline HTML handlers
  window.openSchedule = (broadcastMode = false) =>
    openScheduleInternal(!!broadcastMode);
  window.closeSchedule = () => closeScheduleInternal();
  window.confirmSchedule = () => confirmScheduleInternal();


  // ============================================================
  // BROADCAST MODAL (wizard) + sending broadcast
  // ============================================================

  function renderBroadcastContactList() {
    if (!els.broadcastContactList || !els.contacts) return;
    els.broadcastContactList.innerHTML = "";
    state.broadcast.selected = new Set();

    for (const btn of els.contacts.querySelectorAll(".contact")) {
      const id = btn.dataset.contactId;
      const name = btn.querySelector("h4")?.textContent || id;

      const row = document.createElement("div");
      row.className = "item";

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.id = `bsel-${id}`;
      cb.dataset.contactId = id;

      // preselect active contact if there's one
      if (activeContactId && activeContactId === id) {
        cb.checked = true;
        state.broadcast.selected.add(id);
      }

      cb.addEventListener("change", () => {
        if (cb.checked) {
          state.broadcast.selected.add(id);
        } else {
          state.broadcast.selected.delete(id);
        }
      });

      const label = document.createElement("label");
      label.htmlFor = cb.id;

      const av = document.createElement("div");
      av.className = "avatar";
      av.style.width = "28px";
      av.style.height = "28px";
      av.style.borderRadius = "8px";
      av.textContent =
        name.trim().slice(0, 2).toUpperCase() || "?";

      const nameDiv = document.createElement("div");
      nameDiv.textContent = name;

      label.append(av, nameDiv);

      row.append(cb, label);
      els.broadcastContactList.appendChild(row);
    }
  }

  function openBroadcastInternal() {
    if (!els.broadcastModal) {
      toast("Broadcast UI not available.");
      return;
    }
    state.broadcast.selected = new Set();
    if (els.bwStep1) els.bwStep1.classList.add("active");
    if (els.bwStep2) els.bwStep2.classList.remove("active");
    if (els.broadcastStep1) els.broadcastStep1.style.display = "";
    if (els.broadcastStep2) els.broadcastStep2.style.display = "none";
    if (els.broadcastText) els.broadcastText.value = "";

    renderBroadcastContactList();

    els.broadcastModal.classList.add("open");
    els.broadcastModal.setAttribute("aria-hidden", "false");
  }

  function closeBroadcastInternal() {
    if (!els.broadcastModal) return;
    els.broadcastModal.classList.remove("open");
    els.broadcastModal.setAttribute("aria-hidden", "true");
  }

  function gotoBroadcastStep2Internal() {
    if (els.bwStep1) els.bwStep1.classList.remove("active");
    if (els.bwStep2) els.bwStep2.classList.add("active");
    if (els.broadcastStep1) els.broadcastStep1.style.display = "none";
    if (els.broadcastStep2) els.broadcastStep2.style.display = "";
    if (els.broadcastText) els.broadcastText.focus();
  }

  function gotoBroadcastStep1Internal() {
    if (els.bwStep1) els.bwStep1.classList.add("active");
    if (els.bwStep2) els.bwStep2.classList.remove("active");
    if (els.broadcastStep1) els.broadcastStep1.style.display = "";
    if (els.broadcastStep2) els.broadcastStep2.style.display = "none";
  }

  async function sendBroadcastInternal() {
    if (!cfg.isTeacherOrAdmin) {
      toast("Only teachers/admins can broadcast.");
      return;
    }

    const text = (els.broadcastText?.value || "").trim();
    if (!text) {
      toast("Type a message to broadcast.");
      return;
    }
    if (!state.broadcast.selected.size) {
      toast("Select at least one contact.");
      return;
    }

    try {
      const params = new URLSearchParams();
      params.append("text", text);
      state.broadcast.selected.forEach((id) =>
        params.append("recipients[]", id)
      );

      const res = await fetch(cfg.broadcastUrl, {
        method: "POST",
        headers: {
          "X-CSRFToken": getCsrfToken(),
          "X-Requested-With": "XMLHttpRequest",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params,
      });

      const data = await res.json();
      if (!data.ok) {
        toast(data.error || "Broadcast failed");
      } else {
        const count = data.count || state.broadcast.selected.size;
        toast(`Broadcast sent to ${count} contact(s).`);

        // If current active contact is among selected, append bubble locally
        if (activeContactId && state.broadcast.selected.has(activeContactId)) {
          const timeStr = formatNowHHMM();
          const bubble = document.createElement("div");
          bubble.className = "bubble from-me";
          bubble.tabIndex = 0;
          // we don't know exact msg.id from backend; bubble won't be editable/deletable, but visible
          bubble.innerHTML =
            `<div>${escapeHtml(text).replace(/\n/g, "<br>")}</div>` +
            `<div class="meta"><span>${timeStr}</span></div>`;
          els.chat.appendChild(bubble);
          els.chat.scrollTop = els.chat.scrollHeight;
        }
      }
    } catch (err) {
      console.error(err);
      toast("Network error");
    }

    closeBroadcastInternal();
  }

  // Hook broadcast button in composer
  if (els.btnBroadcast && cfg.isTeacherOrAdmin) {
    els.btnBroadcast.addEventListener("click", () => {
      openBroadcastInternal();
    });
  }

  // close broadcast on backdrop click
  if (els.broadcastModal) {
    els.broadcastModal.addEventListener("click", (e) => {
      if (e.target.id === "broadcastModal") closeBroadcastInternal();
    });
  }

  // expose to global for inline onclicks
  window.openBroadcast = () => openBroadcastInternal();
  window.closeBroadcast = () => closeBroadcastInternal();
  window.gotoBroadcastStep1 = () => gotoBroadcastStep1Internal();
  window.gotoBroadcastStep2 = () => gotoBroadcastStep2Internal();
  window.sendBroadcast = () => sendBroadcastInternal();
});
