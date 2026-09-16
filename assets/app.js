/* Logika strony: zakładki, katalogi zagrożeń, symulator, checklista. */
(function () {
  "use strict";

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const SEV = { crit: "Krytyczne", high: "Wysokie", med: "Średnie", low: "Niskie" };

  /* ---------- motyw ---------- */
  const themeBtn = $("#themeBtn");
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    themeBtn.textContent = t === "dark" ? "Jasny motyw" : "Ciemny motyw";
    try { localStorage.setItem("owasp-theme", t); } catch (e) {}
  }
  let theme = "dark";
  try { theme = localStorage.getItem("owasp-theme") || "dark"; } catch (e) {}
  applyTheme(theme);
  themeBtn.addEventListener("click", () =>
    applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"));

  /* ---------- zakładki ---------- */
  $$("nav.tabs button").forEach((b) => b.addEventListener("click", () => {
    $$("nav.tabs button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    $$("main > section").forEach((s) => { s.hidden = s.id !== "tab-" + b.dataset.tab; });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }));

  /* ---------- mapa na stronie głównej ---------- */
  const MAP = [
    ["①", "Niezaufane wejście", "Prompt użytkownika, dokument RAG, strona WWW, e-mail, opis narzędzia MCP, odpowiedź innego agenta."],
    ["②", "Model bez granicy danych", "Model nie odróżnia instrukcji od danych — każdy tekst w kontekście może zmienić plan."],
    ["③", "Zdolność działania", "Narzędzia, pamięć, generowanie kodu, komunikacja z innymi agentami."],
    ["④", "Uprawnienia i zasięg", "Token agenta, dostęp do sieci, prawa zapisu — tu decyduje się skala szkody."],
    ["⑤", "Skutek", "Eksfiltracja, zmiana danych, koszt, utrata rozliczalności, trwałe zatrucie pamięci."]
  ];
  $("#mapFlow").innerHTML = MAP.map((m) =>
    '<div class="step"><span class="ico">' + m[0] + '</span><span><b>' + esc(m[1]) +
    '</b><br><span style="color:var(--muted)">' + esc(m[2]) + "</span></span></div>").join("");

  /* ---------- katalog LLM ---------- */
  function threatCard(t, extra) {
    return '<article class="card threat">' +
      '<h3><span class="id">' + esc(t.id) + '</span> <span>' + esc(t.name) + '</span>' +
      '<span class="tag ' + t.sev + '">' + SEV[t.sev] + "</span></h3>" +
      "<p>" + esc(t.desc) + "</p>" +
      (t.example ? '<div class="note warn" style="font-size:13px"><b>Przykład:</b> ' + esc(t.example) + "</div>" : "") +
      '<details class="mit"><summary>Przeciwdziałanie (' + t.mits.length + ")</summary><ul>" +
      t.mits.map((m) => "<li>" + esc(m) + "</li>").join("") + "</ul></details>" +
      (extra || "") + "</article>";
  }

  const llmList = $("#llmList");
  function renderLLM(sev) {
    const items = sev ? LLM_TOP10.filter((t) => t.sev === sev) : LLM_TOP10;
    llmList.innerHTML = items.map((t) => threatCard(t)).join("");
  }
  const filters = [["", "Wszystkie"], ["crit", "Krytyczne"], ["high", "Wysokie"], ["med", "Średnie"]];
  $("#llmFilter").innerHTML = filters.map((f, i) =>
    '<button class="chip" data-sev="' + f[0] + '"' + (i === 0 ? ' style="border-color:var(--acc)"' : "") + ">" + f[1] + "</button>").join("");
  $$("#llmFilter .chip").forEach((c) => c.addEventListener("click", () => {
    $$("#llmFilter .chip").forEach((x) => (x.style.borderColor = ""));
    c.style.borderColor = "var(--acc)";
    renderLLM(c.dataset.sev);
  }));
  renderLLM("");

  /* ---------- katalog agentowy ---------- */
  $("#agList").innerHTML = AGENTIC.map((t) => threatCard(t)).join("");

  /* ---------- symulator ---------- */
  const sel = $("#scenSel"), logEl = $("#log"), defBox = $("#defBox");
  let current = "rag", running = false;

  sel.innerHTML = Object.keys(SCENARIOS).map((k) =>
    '<option value="' + k + '">' + esc(SCENARIOS[k].name) + "</option>").join("");

  function defState() {
    const on = {};
    $$("#defBox input").forEach((i) => { on[i.dataset.id] = i.checked; });
    return on;
  }

  function loadScenario(key, allOn) {
    current = key;
    const s = SCENARIOS[key];
    $("#scenIntro").textContent = s.intro;
    $("#scenTags").innerHTML = s.tags.map((t) => '<span class="chip">' + esc(t) + "</span>").join("");
    $("#scenPayload").textContent = s.payload;
    defBox.innerHTML = s.defenses.map((id) => {
      const d = DEFENSES[id];
      return '<label class="switch"><input type="checkbox" data-id="' + id + '"' + (allOn ? " checked" : "") + ">" +
        "<span><b>" + esc(d.n) + "</b><span>" + esc(d.d) + " &middot; <i>" + esc(d.ref) + "</i></span></span></label>";
    }).join("");
    reset();
  }

  function reset() {
    logEl.innerHTML = '<div class="dim">// gotowy — wybierz zabezpieczenia i uruchom przebieg</div>';
    $("#chain").innerHTML = "";
    $("#dmgBar").style.width = "0%";
    $("#dmgVal").textContent = "0 / 100";
    $("#verdict").textContent = "Uruchom symulację, aby zobaczyć wynik.";
    $("#verdict").style.color = "var(--muted)";
  }

  function line(kind, txt) {
    const d = document.createElement("div");
    const ts = new Date().toLocaleTimeString("pl-PL", { hour12: false });
    d.innerHTML = '<span class="t">' + ts + "</span> " + '<span class="' + kind + '">' + txt + "</span>";
    logEl.appendChild(d);
    logEl.scrollTop = logEl.scrollHeight;
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  async function run() {
    if (running) return;
    running = true;
    $("#runBtn").disabled = true;
    const s = SCENARIOS[current], on = defState();
    logEl.innerHTML = "";
    $("#chain").innerHTML = "";

    line("inf", "▶ Scenariusz: " + esc(s.name));
    const active = s.defenses.filter((d) => on[d]);
    line("dim", "Aktywne zabezpieczenia: " + (active.length ? active.map((d) => DEFENSES[d].n).join(", ") : "brak"));
    await wait(420);

    let dmg = 0, stopped = false, stoppedBy = null, detected = false;
    const seenDet = {};
    const rows = [];

    for (let i = 0; i < s.steps.length; i++) {
      const st = s.steps[i];
      await wait(stopped ? 90 : 520);
      if (stopped) {
        rows.push(['<span class="ico">·</span>', "", esc(st.a) + ": " + esc(st.t) + " — niewykonane"]);
        continue;
      }
      const blocker = (st.block || []).find((d) => on[d]);
      if (blocker) {
        line("ok", "⛔ [" + esc(st.a) + "] " + esc(st.t));
        line("ok", "   └─ ZABLOKOWANE: " + esc(DEFENSES[blocker].n) + " (" + esc(DEFENSES[blocker].ref) + ")");
        rows.push(['<span class="ico">⛔</span>', "blocked", esc(st.t) + " — zablokowane przez: " + esc(DEFENSES[blocker].n)]);
        stopped = true; stoppedBy = blocker;
        continue;
      }
      dmg += st.dmg;
      line(st.dmg >= 25 ? "bad" : st.dmg > 0 ? "warn" : "dim", "✔ [" + esc(st.a) + "] " + esc(st.t));
      const det = (st.detect || []).find((d) => on[d]);
      if (det) {
        detected = true;
        if (!seenDet[det]) {
          seenDet[det] = true;
          line("inf", "   └─ odnotowane (nie powstrzymane): " + esc(DEFENSES[det].n));
        }
      }
      rows.push(['<span class="ico">' + (st.dmg >= 25 ? "✖" : "•") + "</span>", st.dmg >= 25 ? "hit" : "",
        esc(st.a) + ": " + esc(st.t)]);
      $("#dmgBar").style.width = Math.min(100, dmg) + "%";
      $("#dmgVal").textContent = Math.min(100, dmg) + " / 100";
    }

    const score = Math.min(100, dmg);
    const bar = $("#dmgBar");
    bar.style.background = score >= 60 ? "var(--crit)" : score >= 30 ? "var(--warn)" : score > 0 ? "var(--acc)" : "var(--ok)";

    const v = $("#verdict");
    if (stopped) {
      const early = s.steps.findIndex((x) => (x.block || []).some((d) => on[d])) <= 1;
      v.innerHTML = "<b>Atak przerwany.</b> " + esc(s.lose) + " Punkt przerwania: <code>" +
        esc(DEFENSES[stoppedBy].n) + "</code>." +
        (early ? " Zatrzymany wcześnie — szkoda resztkowa minimalna." : " Część kroków zdążyła się wykonać — warto dołożyć kontrolę wcześniej w łańcuchu.");
      v.style.color = "var(--txt)";
      line("ok", "■ Wynik: atak powstrzymany. Poziom szkody " + score + "/100.");
    } else {
      v.innerHTML = "<b>Atak zakończony powodzeniem.</b> " + esc(s.win) +
        (detected ? " Zdarzenie zostało przynajmniej odnotowane w audycie — jest co badać po fakcie." :
          " Brak śladu audytowego: incydent jest niewykrywalny od wewnątrz.");
      v.style.color = "var(--txt)";
      line("bad", "■ Wynik: atak udany. Poziom szkody " + score + "/100.");
    }

    $("#chain").innerHTML = rows.map((r) =>
      '<div class="step ' + r[1] + '">' + r[0] + "<span>" + r[2] + "</span></div>").join("");

    running = false;
    $("#runBtn").disabled = false;
  }

  sel.addEventListener("change", () => loadScenario(sel.value, false));
  $("#runBtn").addEventListener("click", run);
  $("#resetBtn").addEventListener("click", reset);
  $("#allOn").addEventListener("click", () => { $$("#defBox input").forEach((i) => (i.checked = true)); });
  $("#allOff").addEventListener("click", () => { $$("#defBox input").forEach((i) => (i.checked = false)); });
  loadScenario("rag", false);

  /* ---------- checklista ---------- */
  const chkBox = $("#chkBox");
  const KEY = "owasp-checklist";
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { saved = {}; }

  const groups = [];
  CHECKLIST.forEach((c) => {
    let g = groups.find((x) => x.name === c.g);
    if (!g) { g = { name: c.g, items: [] }; groups.push(g); }
    g.items.push(c);
  });

  chkBox.innerHTML = groups.map((g) =>
    '<div class="card"><h3>' + esc(g.name) + "</h3>" +
    '<div class="grid" style="gap:8px">' + g.items.map((c) =>
      '<label class="switch"><input type="checkbox" data-id="' + c.id + '"' + (saved[c.id] ? " checked" : "") + ">" +
      "<span><b>" + esc(c.t) + '</b><span>waga ' + c.w + " pkt &middot; " + esc(c.ref) + "</span></span></label>").join("") +
    "</div></div>").join("");

  const MAXPTS = CHECKLIST.reduce((a, c) => a + c.w, 0);

  function scoreUp() {
    const state = {};
    let pts = 0;
    $$("#chkBox input").forEach((i) => {
      state[i.dataset.id] = i.checked;
      if (i.checked) pts += CHECKLIST.find((c) => c.id === i.dataset.id).w;
    });
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {}
    const pct = Math.round((pts / MAXPTS) * 100);
    $("#scoreTxt").textContent = pts + " / " + MAXPTS + " punktów (" + pct + "%)";
    const bar = $("#scoreBar");
    bar.style.width = pct + "%";
    const lbl = $("#scoreLbl");
    let cls = "crit", txt = "Krytyczne braki";
    if (pct >= 85) { cls = "low"; txt = "Dojrzałe"; }
    else if (pct >= 60) { cls = "med"; txt = "Podstawy zabezpieczone"; }
    else if (pct >= 35) { cls = "high"; txt = "Istotne luki"; }
    bar.style.background = cls === "low" ? "var(--ok)" : cls === "med" ? "var(--warn)" : cls === "high" ? "#f07a2e" : "var(--crit)";
    lbl.className = "tag " + cls;
    lbl.textContent = txt;
  }
  chkBox.addEventListener("change", scoreUp);
  $("#clearChk").addEventListener("click", () => {
    $$("#chkBox input").forEach((i) => (i.checked = false));
    scoreUp();
  });
  scoreUp();
})();
