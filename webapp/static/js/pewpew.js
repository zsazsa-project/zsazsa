// The pew-pew map on Reporting > Pew-pew map. It replays the indicators the
// page was rendered with, oldest first, and reads them again from the JSON
// route each time the replay ends. Every text from MISP goes in with
// textContent.
(function () {
  "use strict";
  const dataEl = document.getElementById("pew-data");
  const canvas = document.getElementById("pew-canvas");
  if (!dataEl || !canvas) return;

  // Land on a 2.5 degree grid from 82.5N to 57.5S, from Natural Earth 1:110m.
  const MASK = [
    "000000000000000000000000000000000000000111111110000001111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000111111111110111111111111111111110000000000000111110000000000000000000000000011100000000000000000000000000000000",
    "000000000000000000000000110000000000011110001111111111111111111100000000000000100000000000000000000000000000000001000000000000000000000000000000",
    "000000000000000000000000000110001111111100000000011111111111111100000000000000000000000000000011000000000001111111111000000000011101000000000000",
    "000000000000000000000011011101011010111100000000001111111111111000000000000000000000000000000100000010001111111111111111111100001100000000000000",
    "000000011111111000000000011111110010001101111000001111111111111000000000000000001111000000000000000110111111111111111111111111111111111100001000",
    "001111000000000000000000000010000000000110100011111000000001111111111111111111000000000011100000000001000000000000000000000000000000000000000000",
    "110110000000000000000000000000000000010110000111111000001111111000111111111100001100001100000000000000000000000000000000000000000000000000000000",
    "000000111111111111111111111111111110001000001000000011100000000000000000001111101111111111111111111111111111111111111111111111111111111110111111",
    "000001111111100111111111111111111100000001110000000000000000000000000000001111100100111111111111111111111111111111111111111111111111110001100000",
    "000000000110000000011111111111111110000001111110000000000000000000000010000001100011111111111111111111111111111111111111111111110000000110000000",
    "000000100000000000001111111111111111111001111111100000000000000000000010000100001111111111111111111111111111111111111111111111000000001110000000",
    "000000000000000000000111111111111111111001111111110000000000000000001011101111111111111111111111111111111111111111111111111111111000001000000000",
    "000000000000000000000111111111111111111111111000010000000000000000000000111111111111111111111111111111111111111111111111111111110100000000000000",
    "000000000000000000000011111111111111111111111100001000000000000000000001111111111111111111111111111111111111111111111111111111110000000000000000",
    "000000000000000000000011111111111111111111111010000000000000000000000001111110111111010111100111111111111111111111111111111111100000000000000000",
    "000000000000000000000011111111111111111111110000000000000000000000001111100111011110000001100111111111111111111111111111111100001000000000000000",
    "000000000000000000000011111111111111111111000000000000000000000000001111000100101101111111110111111111111111111111111111011000001000000000000000",
    "000000000000000000000001111111111111111110000000000000000000000000001111000001000001111111110011111111111111111111111111100100010000000000000000",
    "000000000000000000000000111111111111111111000000000000000000000000000111111100000000011111111111111111111111111111111111000001110000000000000000",
    "000000000000000000000000011111111111111100000000000000000000000000001111111111001000001111111111111111111111111111111111000010000000000000000000",
    "000000000000000000000000000111111111001000000000000000000000000000001111111111111111111111101111111111111111111111111111100000000000000000000000",
    "000000000000000000000000001011111000000100000000000000000000000000011111111111111111101111110111111111111111111111111111000000000000000000000000",
    "000000000000000000000000000101111000000000000000000000000000000000111111111111111111110111111010000111111111111111111111100000000000000000000000",
    "000000000000000000000000000000111000001100000000000000000000000001111111111111111111111011111111000011111111011111111100000000000000000000000000",
    "000000000000000000000000000000111000100001000000000000000000000001111111111111111111111011111110000001111100011111000000000000000000000000000000",
    "000000000000000000000000000000011111100000000000000000000000000000111111111111111111111001111100000001111000001111100000100000000000000000000000",
    "000000000000000000000000000000000001111000000000000000000000000001111111111111111111111101110000000000110000000111110000100000000000000000000000",
    "000000000000000000000000000000000000011000000000000000000000000001111111111111111111111110000000000000110000000101110000100000000000000000000000",
    "000000000000000000000000000000000000001000101110000000000000000000111111111111111111111111110000000000110000000100100001000000000000000000000000",
    "000000000000000000000000000000000000000001111111100000000000000000011111111111111111111111110000000000001000000000000000001000000000000000000000",
    "000000000000000000000000000000000000000001111111111000000000000000001101001111111111111111100000000000000000001010000011000000000000000000000000",
    "000000000000000000000000000000000000000001111111111100000000000000000000000011111111111111000000000000000000000101000110000000000000000000000000",
    "000000000000000000000000000000000000000011111111111100000000000000000000000011111111111110000000000000000000000011001110000000000000000000000000",
    "000000000000000000000000000000000000000011111111111111100000000000000000000011111111111100000000000000000000000011001110100001110000000000000000",
    "000000000000000000000000000000000000000111111111111111111000000000000000000001111111111100000000000000000000000000000000000000011100000000000000",
    "000000000000000000000000000000000000000011111111111111111100000000000000000001111111111100000000000000000000000000011000000000011110000000000000",
    "000000000000000000000000000000000000000001111111111111111100000000000000000001111111111100000000000000000000000000000000010000000001000000000000",
    "000000000000000000000000000000000000000001111111111111111000000000000000000001111111111100000000000000000000000000000000000011100000000000000000",
    "000000000000000000000000000000000000000000111111111111110000000000000000000001111111111100010000000000000000000000000000001111000100000000000000",
    "000000000000000000000000000000000000000000011111111111110000000000000000000001111111111000110000000000000000000000000000011111111100000000000000",
    "000000000000000000000000000000000000000000001111111111110000000000000000000001111111110000100000000000000000000000000000111111111110000000000000",
    "000000000000000000000000000000000000000000001111111111100000000000000000000000111111110001100000000000000000000000000111111111111111000000000000",
    "000000000000000000000000000000000000000000001111111110000000000000000000000000111111110000100000000000000000000000000111111111111111100000000000",
    "000000000000000000000000000000000000000000001111111110000000000000000000000000111111100000000000000000000000000000000011111111111111100000000000",
    "000000000000000000000000000000000000000000011111111100000000000000000000000000011111000000000000000000000000000000000011111111111111100000000000",
    "000000000000000000000000000000000000000000011111111000000000000000000000000000011110000000000000000000000000000000000011110000111111100000000000",
    "000000000000000000000000000000000000000000011111100000000000000000000000000000000000000000000000000000000000000000000000000000011111000000000000",
    "000000000000000000000000000000000000000000011111100000000000000000000000000000000000000000000000000000000000000000000000000000001111000000000000",
    "000000000000000000000000000000000000000000011110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010",
    "000000000000000000000000000000000000000000111110000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000001000",
    "000000000000000000000000000000000000000000111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000",
    "000000000000000000000000000000000000000000111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  ];
  const COLS = 144, ROWS = 57;
  const RM = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const mapEl = canvas.closest(".pew-map");
  const css = name => getComputedStyle(mapEl).getPropertyValue(name).trim();
  const MEANS = {
    scraper: { color: css("--m-scraper") || "#38e1cf", pitch: 1760, at: [-140, -55], on: true },
    misp: { color: css("--m-misp") || "#6aa8ff", pitch: 1319, at: [-35, -55], on: true },
    newsletter: { color: css("--m-newsletter") || "#ffb547", pitch: 1109, at: [65, -55], on: true },
    manual: { color: css("--m-manual") || "#b8f36a", pitch: 2093, at: [105, -55], on: true }
  };
  const BASKET = [20, -47];
  const LITTER = [150, -48];
  const MAX_PENDING = 30;

  let data = JSON.parse(dataEl.textContent);
  const uv = (lon, lat) => ({ u: (lon + 180) / 360, v: (83.75 - lat) / 142.5 });
  const rand = (a, b) => a + Math.random() * (b - a);

  // canvas and the land drawn once per size
  const stage = document.getElementById("pew-stage");
  const ctx = canvas.getContext("2d");
  const land = document.createElement("canvas");
  let W = 1, H = 1, DPR = 1, cell = 1;
  const heat = new Float32Array(COLS * ROWS);
  const heatColor = new Array(COLS * ROWS).fill("#38e1cf");

  function resize() {
    const r = stage.getBoundingClientRect();
    W = Math.max(1, r.width); H = Math.max(1, r.height); cell = W / COLS;
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = land.width = Math.round(W * DPR);
    canvas.height = land.height = Math.round(H * DPR);
    drawLand();
    // A new size clears the canvas: draw now rather than wait for the next frame.
    draw();
  }
  function drawLand() {
    const g = land.getContext("2d");
    g.setTransform(DPR, 0, 0, DPR, 0, 0);
    g.clearRect(0, 0, W, H);
    g.strokeStyle = "rgba(95,143,151,.10)"; g.lineWidth = 1;
    for (let lon = -150; lon <= 150; lon += 30) { const x = uv(lon, 0).u * W; g.beginPath(); g.moveTo(x, 0); g.lineTo(x, H); g.stroke(); }
    for (let lat = -30; lat <= 60; lat += 30) {
      const y = uv(0, lat).v * H; g.setLineDash(lat === 0 ? [4, 6] : []);
      g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke();
    }
    g.setLineDash([]);
    const rLand = cell * .3, rSea = Math.max(.5, cell * .07);
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const x = (c + .5) * cell, y = (r + .5) * cell;
        if (MASK[r].charCodeAt(c) === 49) { g.fillStyle = "#1d5560"; g.beginPath(); g.arc(x, y, rLand, 0, 6.2832); g.fill(); }
        else if ((r + c) % 2 === 0) { g.fillStyle = "#0e2a32"; g.beginPath(); g.arc(x, y, rSea, 0, 6.2832); g.fill(); }
      }
    }
  }

  // the replay
  // A minute at least between two reads of the data, also when there is
  // nothing to replay: each read asks MISP for the RFIs.
  const RELOAD_EVERY = 60;
  let queue = [], qi = 0, nextAt = 1, idleFor = 0, reloading = false, lastReload = 0;
  function plan(list) {
    queue = list.slice(); qi = 0; nextAt = .8; idleFor = 0;
    const n = queue.length;
    if (!n) return;
    let last = queue[0].ts || 0;
    queue.forEach(it => { it.ts = it.ts || last; last = it.ts; });
    const span = Math.max(1, queue[n - 1].ts - queue[0].ts);
    const loop = Math.min(240, Math.max(40, n * .9));
    for (let i = 1; i < n; i++) {
      queue[i].gap = Math.min(3, Math.max(.06, (queue[i].ts - queue[i - 1].ts) / span * loop));
    }
  }
  function reload() {
    reloading = true; lastReload = simTime;
    fetch(canvas.dataset.jsonUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(r => (r.ok ? r.json() : null))
      .then(fresh => { if (fresh && Array.isArray(fresh.indicators)) data = fresh; })
      .catch(() => {})
      .then(() => { reloading = false; plan(data.indicators); });
  }

  // world state
  const lasers = [], dots = [], particles = [], floaters = [], recent = [];
  let paused = false, simTime = 0;

  function fire(it) {
    const m = MEANS[it.means] || MEANS.manual;
    const a = uv(m.at[0], m.at[1]);
    const located = typeof it.lat === "number";
    const b = located ? uv(it.lon, it.lat) : uv(LITTER[0], LITTER[1]);
    const dist = Math.hypot(b.u - a.u, (b.v - a.v) * .4);
    lasers.push({ a, b, c: { u: (a.u + b.u) / 2, v: Math.min(a.v, b.v) - .08 - dist * .45 },
                  p: 0, dur: RM ? .25 : rand(.9, 1.4), color: m.color, it, located });
    it.row = addRow(it);
    pew(m.pitch);
    recent.push(simTime);
  }

  function landed(L) {
    const it = L.it;
    if (!L.located) {
      addLitter(it);
      floaters.push({ u: L.b.u, v: L.b.v - .05, text: "plop", life: 1.2, color: L.color });
      setStatus(it, it.caught.length ? "caught" : "litter");
      return;
    }
    const d = { u: L.b.u, v: L.b.v, color: L.color, age: 0, it, state: it.caught.length ? "pending" : "sniff" };
    dots.push(d);
    const c = Math.floor(d.u * COLS), r = Math.floor(d.v * ROWS);
    for (let dr = -1; dr <= 1; dr++) for (let dc = -1; dc <= 1; dc++) {
      const rr = r + dr, cc = c + dc;
      if (rr < 0 || rr >= ROWS || cc < 0 || cc >= COLS) continue;
      const i = rr * COLS + cc;
      heat[i] = Math.min(1.4, heat[i] + (dr || dc ? .45 : 1)); heatColor[i] = L.color;
    }
    for (let i = 0; i < 10; i++) {
      const an = rand(0, 6.28), sp = rand(.02, .07);
      particles.push({ u: d.u, v: d.v, du: Math.cos(an) * sp, dv: Math.sin(an) * sp * 2.5, life: rand(.4, .8), color: L.color });
    }
    setStatus(it, d.state === "pending" ? "loose" : "ignored");
    const pending = dots.filter(x => x.state === "pending");
    if (pending.length > MAX_PENDING) catchDot(pending[0], true);
  }

  function step(dt) {
    simTime += dt;
    if (!reloading) {
      nextAt -= dt;
      while (nextAt <= 0 && qi < queue.length) {
        const it = queue[qi++];
        if ((MEANS[it.means] || MEANS.manual).on) { fire(it); setClock(it); }
        nextAt += qi < queue.length ? queue[qi].gap : 0;
      }
      if (qi >= queue.length && !lasers.length) {
        idleFor += dt;
        if (idleFor > 5 && simTime - lastReload > RELOAD_EVERY && canvas.dataset.jsonUrl) reload();
      }
    }
    while (recent.length && simTime - recent[0] > 1.6) recent.shift();
    if (recent.length >= 3 && recent.length !== lastCombo) showCombo(recent.length);
    if (recent.length < 3) lastCombo = 0;

    for (let i = lasers.length - 1; i >= 0; i--) {
      const L = lasers[i], before = L.p;
      L.p += dt / L.dur;
      if (before < 1 && L.p >= 1) landed(L);
      if (L.p > 1.35) lasers.splice(i, 1);
    }
    for (let i = dots.length - 1; i >= 0; i--) {
      const d = dots[i]; d.age += dt;
      // One she has not got to in a while goes without her.
      if (d.state === "sniff" && d.age > 14) sniffed(d, true);
      if ((d.state === "caught" && d.age - d.doneAt > .5) || (d.state === "sniffed" && d.age - d.doneAt > 1)) dots.splice(i, 1);
    }
    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i]; p.life -= dt; p.u += p.du * dt; p.v += p.dv * dt; p.dv += .05 * dt;
      if (p.life <= 0) particles.splice(i, 1);
    }
    for (let i = floaters.length - 1; i >= 0; i--) { const f = floaters[i]; f.life -= dt; f.v -= .04 * dt; if (f.life <= 0) floaters.splice(i, 1); }
    const k = Math.exp(-dt / 5);
    for (let i = 0; i < heat.length; i++) if (heat[i] > .001) heat[i] *= k;
    moveCat(dt);
  }

  // Zsa Zsa
  const SPR = {
    runA: ["............#.#.", "...........#####", "#..........##e##", ".#.........####p", "..###s###s###s#.", "..############..", "..##s###s###s#..", ".#.#......#.#...", "#...#....#...#.."],
    runB: ["............#.#.", "...........#####", "...........##e##", "#..........####p", ".##s###s###s###.", "..############..", "..##s###s###s#..", "...##.....##....", "...##.....##...."],
    sit: ["............#.#.", "...........#####", "...........##e##", "...........####p", ".........##s##..", "........###s##..", ".......#s####s..", ".##....#######..", "..#############."],
    blink: ["............#.#.", "...........#####", "...........#####", "...........####p", ".........##s##..", "........###s##..", ".......#s####s..", ".##....#######..", "..#############."]
  };
  const SPR_COL = { "#": "#f08a1c", s: "#b85e0a", e: "#05141a", p: "#ff8fb1" };
  const home = uv(BASKET[0], BASKET[1]);
  const cat = { u: home.u, v: home.v, dir: 1, state: "idle", t: 0, target: null, pt: 0, su: 0, sv: 0, lastMeow: -9, zoomies: false };

  // What the cat goes for: the nearest dot in scope, and when there is none,
  // the nearest one that is not, which she only sniffs at.
  function nearestTarget() {
    for (const state of ["pending", "sniff"]) {
      let best = null, bd = 1e9;
      for (const d of dots) {
        if (d.state !== state) continue;
        const dd = Math.hypot(d.u - cat.u, (d.v - cat.v) * H / W);
        if (dd < bd) { bd = dd; best = d; }
      }
      if (best) return best;
    }
    return null;
  }
  function moveCat(dt) {
    cat.t += dt;
    const aspect = H / W || .4;
    if (cat.state === "pounce") {
      cat.pt += dt / (RM ? .12 : .34);
      const p = Math.min(1, cat.pt), tg = cat.target;
      cat.u = cat.su + (tg.u - cat.su) * p; cat.v = cat.sv + (tg.v - cat.sv) * p;
      if (p >= 1) { catchDot(tg, false); cat.state = "idle"; cat.target = null; }
      return;
    }
    if (cat.state === "sniffing") {
      cat.pt += dt;
      if (cat.pt >= .9) { sniffed(cat.target, false); cat.state = "idle"; cat.target = null; }
      return;
    }
    const pending = dots.filter(d => d.state === "pending").length;
    if (!cat.target || !["pending", "sniff"].includes(cat.target.state) || (cat.target.state === "sniff" && pending)) {
      cat.target = nearestTarget();
    }
    const tg = cat.target || (Math.hypot(home.u - cat.u, home.v - cat.v) > .006 ? { u: home.u, v: home.v, home: true } : null);
    if (!tg) { cat.state = "idle"; setCatline(); return; }
    const du = tg.u - cat.u, dv = (tg.v - cat.v) * aspect, d = Math.hypot(du, dv);
    if (!tg.home && d < .018) {
      cat.state = tg.state === "pending" ? "pounce" : "sniffing";
      cat.pt = 0; cat.su = cat.u; cat.sv = cat.v; cat.dir = du >= 0 ? 1 : -1;
      setCatline(); return;
    }
    if (tg.home && d < .004) { cat.state = "idle"; setCatline(); return; }
    const pace = tg.home ? .5 : tg.state === "sniff" ? .75 : 1;
    const speed = (RM ? .5 : .21) * (1 + Math.min(pending, 10) * .12) * pace;
    const s = Math.min(d, speed * dt);
    cat.u += du / d * s; cat.v += dv / d * s / aspect;
    if (Math.abs(du) > .002) cat.dir = du >= 0 ? 1 : -1;
    cat.state = "run"; cat.zoomies = pending >= 5;
    setCatline();
  }
  function sniffed(d, quietly) {
    if (d.state !== "sniff") return;
    d.state = "sniffed"; d.doneAt = d.age;
    if (!quietly) floaters.push({ u: d.u, v: d.v - .05, text: "not in scope", life: 1.1, color: "#8fb6bd" });
  }
  function catchDot(d, quietly) {
    if (d.state !== "pending") return;
    d.state = "caught"; d.doneAt = d.age;
    setStatus(d.it, "caught");
    if (quietly) return;
    floaters.push({ u: d.u, v: d.v - .05, text: d.it.caught[0], life: 1.3, color: "#ffb547" });
    for (let i = 0; i < 14; i++) {
      const an = rand(0, 6.28), sp = rand(.03, .09);
      particles.push({ u: d.u, v: d.v, du: Math.cos(an) * sp, dv: Math.sin(an) * sp * 2.5, life: rand(.3, .7), color: "#ffe2a8" });
    }
    if (simTime - cat.lastMeow > .7) { meow(); cat.lastMeow = simTime; }
  }

  // drawing
  const P = (u, v) => [u * W, v * H];
  function bez(L, t) {
    const a = L.a, b = L.b, c = L.c, it = 1 - t;
    return P(it * it * a.u + 2 * it * t * c.u + t * t * b.u, it * it * a.v + 2 * it * t * c.v + t * t * b.v);
  }
  const MONO = "JetBrains Mono, ui-monospace, Menlo, monospace";
  function draw() {
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.drawImage(land, 0, 0, W, H);
    const rH = cell * .36;
    for (let i = 0; i < heat.length; i++) {
      if (heat[i] < .03) continue;
      const r = (i / COLS) | 0, c = i % COLS;
      if (MASK[r].charCodeAt(c) !== 49) continue;
      ctx.globalAlpha = Math.min(1, heat[i]) * .85; ctx.fillStyle = heatColor[i];
      ctx.beginPath(); ctx.arc((c + .5) * cell, (r + .5) * cell, rH, 0, 6.2832); ctx.fill();
    }
    ctx.globalAlpha = 1;
    drawTurrets(); drawBasket(); drawLitterBox();

    ctx.globalCompositeOperation = "lighter";
    ctx.lineCap = "round";
    for (const L of lasers) {
      const head = Math.min(1, L.p), tail = Math.max(0, L.p - .32);
      ctx.globalAlpha = .07 * Math.max(0, 1.35 - L.p); ctx.strokeStyle = L.color; ctx.lineWidth = 1;
      ctx.beginPath();
      for (let k = 0; k <= 24; k++) { const q = bez(L, k / 24); if (k) ctx.lineTo(q[0], q[1]); else ctx.moveTo(q[0], q[1]); }
      ctx.stroke();
      const N = 14;
      for (let k = 0; k < N; k++) {
        const q0 = bez(L, tail + (head - tail) * k / N), q1 = bez(L, tail + (head - tail) * (k + 1) / N), f = (k + 1) / N;
        ctx.globalAlpha = f * f; ctx.lineWidth = .6 + f * 2.4;
        ctx.beginPath(); ctx.moveTo(q0[0], q0[1]); ctx.lineTo(q1[0], q1[1]); ctx.stroke();
      }
      if (L.p < 1) {
        const q = bez(L, head), g = ctx.createRadialGradient(q[0], q[1], 0, q[0], q[1], cell * 2.4);
        g.addColorStop(0, "rgba(255,255,255,.95)"); g.addColorStop(.25, L.color); g.addColorStop(1, "rgba(0,0,0,0)");
        ctx.globalAlpha = 1; ctx.fillStyle = g; ctx.beginPath(); ctx.arc(q[0], q[1], cell * 2.4, 0, 6.2832); ctx.fill();
      }
    }
    ctx.globalAlpha = 1;
    for (const d of dots) {
      const [x, y] = P(d.u, d.v);
      if (d.state === "pending") {
        const pulse = (d.age * 1.4) % 1;
        ctx.globalAlpha = 1 - pulse; ctx.strokeStyle = d.color; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(x, y, cell * (.8 + pulse * 2.4), 0, 6.2832); ctx.stroke();
        ctx.globalAlpha = 1; ctx.fillStyle = d.color; ctx.beginPath(); ctx.arc(x, y, cell * .7, 0, 6.2832); ctx.fill();
        ctx.fillStyle = "#ffffff"; ctx.beginPath(); ctx.arc(x, y, cell * .28, 0, 6.2832); ctx.fill();
      } else if (d.state === "sniff" || d.state === "sniffed") {
        const fade = d.state === "sniffed" ? Math.max(0, 1 - (d.age - d.doneAt)) : 1;
        ctx.globalAlpha = .75 * fade; ctx.fillStyle = d.color;
        ctx.beginPath(); ctx.arc(x, y, cell * .45, 0, 6.2832); ctx.fill();
      } else {
        const t = (d.age - d.doneAt) / .5;
        ctx.globalAlpha = Math.max(0, 1 - t); ctx.strokeStyle = "#ffe2a8"; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, cell * (1 + t * 4), 0, 6.2832); ctx.stroke();
      }
    }
    for (const p of particles) {
      const [x, y] = P(p.u, p.v);
      ctx.globalAlpha = Math.max(0, Math.min(1, p.life * 2)); ctx.fillStyle = p.color;
      ctx.fillRect(x - 1.2, y - 1.2, 2.4, 2.4);
    }
    ctx.globalCompositeOperation = "source-over";
    ctx.globalAlpha = 1;
    drawCat();
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.font = "700 " + Math.max(10, cell * 1.6) + "px " + MONO;
    for (const f of floaters) {
      const [x, y] = P(f.u, f.v);
      ctx.globalAlpha = Math.max(0, Math.min(1, f.life * 1.5));
      ctx.fillStyle = "#05141a"; ctx.fillText(f.text, x + 2, y + 2);
      ctx.fillStyle = f.color; ctx.fillText(f.text, x, y);
    }
    ctx.globalAlpha = 1;
  }
  function drawTurrets() {
    for (const m of Object.values(MEANS)) {
      const [x, y] = P(uv(m.at[0], m.at[1]).u, uv(m.at[0], m.at[1]).v);
      ctx.globalAlpha = m.on ? 1 : .3;
      ctx.fillStyle = "#123a43"; ctx.fillRect(x - cell * 1.6, y - cell * .3, cell * 3.2, cell * 1.4);
      ctx.fillStyle = m.color; ctx.fillRect(x - cell * .45, y - cell * 1.3, cell * .9, cell * 1.2);
      ctx.fillRect(x - cell * 1.2, y + cell * .1, cell * 2.4, cell * .35);
    }
    ctx.globalAlpha = 1;
  }
  function drawBasket() {
    const [x, y] = P(home.u, home.v);
    ctx.fillStyle = "#3a2a1a"; ctx.beginPath(); ctx.ellipse(x, y + cell * .2, cell * 3.6, cell * 1.1, 0, 0, 6.2832); ctx.fill();
    ctx.strokeStyle = "#7a5530"; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.ellipse(x, y + cell * .2, cell * 3.6, cell * 1.1, 0, 0, 6.2832); ctx.stroke();
  }
  function drawLitterBox() {
    const p = uv(LITTER[0], LITTER[1]), [x, y] = P(p.u, p.v);
    const w = cell * 9, h = cell * 2.6;
    ctx.fillStyle = "#123a43"; ctx.fillRect(x - w / 2, y - h * .2, w, h);
    ctx.fillStyle = "#1d5560"; ctx.fillRect(x - w / 2 - cell * .4, y - h * .2, w + cell * .8, cell * .6);
    ctx.fillStyle = "#3b6d75";
    for (let i = 0; i < 7; i++) ctx.fillRect(x - w / 2 + cell * (1 + i * 1.1), y - h * .2 + cell * .9 + (i % 2) * cell * .4, cell * .5, cell * .5);
    ctx.font = "600 " + Math.max(8, cell * 1.05) + "px " + MONO; ctx.textAlign = "center"; ctx.textBaseline = "bottom";
    ctx.fillStyle = "#6f9ca4"; ctx.fillText("LITTER BOX", x, y - h * .2 - cell * .5);
  }
  function drawCat() {
    let spr = (cat.t % 3.2) < .14 ? SPR.blink : SPR.sit;
    if (cat.state === "run") spr = (Math.floor(cat.t / (cat.zoomies ? .06 : .1)) % 2) ? SPR.runA : SPR.runB;
    if (cat.state === "pounce") spr = SPR.runA;
    const ps = Math.max(2, cell * .46);
    const [gx, gy] = P(cat.u, cat.v);
    let y = gy;
    if (cat.state === "pounce") y -= Math.sin(Math.min(1, cat.pt) * Math.PI) * ps * 7;
    ctx.fillStyle = "rgba(0,0,0,.45)";
    ctx.beginPath(); ctx.ellipse(gx, gy + ps * .4, ps * 6, ps * 1.2, 0, 0, 6.2832); ctx.fill();
    const ox = gx - 8 * ps, oy = y - 9 * ps;
    for (let r = 0; r < spr.length; r++) {
      for (let c = 0; c < 16; c++) {
        const ch = spr[r][cat.dir > 0 ? c : 15 - c];
        if (ch === ".") continue;
        ctx.fillStyle = SPR_COL[ch];
        ctx.fillRect(Math.round(ox + c * ps), Math.round(oy + r * ps), Math.ceil(ps), Math.ceil(ps));
      }
    }
  }

  // the page around the map
  const feed = document.getElementById("pew-feed");
  const eventUrl = feed ? feed.dataset.eventUrl : "";
  const MEANS_LABEL = {};
  (data.means || []).forEach(m => { MEANS_LABEL[m.id] = m.label; });
  const when = ts => new Date(ts * 1000).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  function td(cls, text) { const el = document.createElement("td"); if (cls) el.className = cls; if (text !== undefined) el.textContent = text; return el; }
  function addRow(it) {
    if (!feed) return null;
    const tr = document.createElement("tr");
    if (!RM) tr.className = "fresh";
    const via = td(""), vs = document.createElement("span"), vi = document.createElement("i"), vt = document.createElement("span");
    vs.className = "pew-via means-" + it.means; vt.textContent = it.source; vs.title = MEANS_LABEL[it.means] || ""; vs.append(vi, vt); via.appendChild(vs);
    const ev = td("ev"), a = document.createElement("a");
    a.href = eventUrl.replace("__uuid__", encodeURIComponent(it.event_uuid)) + "?source=" + encodeURIComponent(it.source_id);
    a.textContent = it.event; ev.appendChild(a);
    const tl = td(""), chip = document.createElement("span");
    chip.className = "pew-tlp " + it.tlp; chip.textContent = "TLP:" + it.tlp.toUpperCase(); tl.appendChild(chip);
    const st = td(""), s = document.createElement("span");
    s.className = "pew-loose"; s.textContent = "in flight"; st.appendChild(s);
    tr.append(td("t", it.ts ? when(it.ts) : ""), via, td("ty", it.type), td("v", it.value), ev, tl, st);
    feed.insertBefore(tr, feed.firstChild);
    while (feed.children.length > 9) feed.removeChild(feed.lastChild);
    return s;
  }
  function setStatus(it, what) {
    const s = it.row;
    if (!s) return;
    if (what === "caught") {
      s.className = "pew-catch";
      s.textContent = "caught: " + it.caught.slice(0, 2).join(", ") + (it.caught.length > 2 ? " +" + (it.caught.length - 2) : "");
    } else {
      s.className = "pew-loose";
      s.textContent = { loose: "on the loose", ignored: "not in scope", litter: "in the litter box" }[what] || what;
    }
  }
  const litter = document.getElementById("pew-litter");
  function addLitter(it) {
    if (!litter) return;
    litter.querySelector(".pew-litter-empty")?.remove();
    const li = document.createElement("li");
    const k = document.createElement("span"); k.className = "k"; k.textContent = it.type;
    const v = document.createElement("span"); v.className = "val"; v.textContent = it.value; v.title = it.value;
    const w = document.createElement("span"); w.className = "why";
    w.textContent = (it.why_not ? it.why_not + ", " : "") + (it.caught.length ? "caught by " + it.caught[0] : "via " + it.source);
    li.append(k, v, w);
    litter.insertBefore(li, litter.firstChild);
    while (litter.children.length > 6) litter.removeChild(litter.lastChild);
  }
  const clock = document.getElementById("pew-clock");
  function setClock(it) { if (clock && it.ts) clock.textContent = "Replaying " + when(it.ts); }

  const catline = document.getElementById("pew-catline");
  let lastCat = "";
  function setCatline() {
    let lead = "Zsa Zsa is ", what;
    if (paused) what = "waiting for you";
    else if (cat.state === "pounce") what = "pouncing";
    else if (cat.state === "sniffing") { lead = "Zsa Zsa sniffs at "; what = cat.target.it.value + ", not in scope"; }
    else if (cat.state === "run" && cat.target && cat.target.it && cat.target.state === "sniff") {
      lead = "Zsa Zsa is checking out "; what = cat.target.it.value;
    } else if (cat.state === "run" && cat.target && cat.target.it) {
      lead = cat.zoomies ? "Zsa Zsa has the zoomies, chasing " : "Zsa Zsa is chasing ";
      what = cat.target.it.value + " for " + cat.target.it.caught[0];
    } else if (cat.state === "run") what = "trotting back to her basket";
    else what = "napping";
    if (lead + what === lastCat) return;
    lastCat = lead + what;
    catline.textContent = lead;
    const b = document.createElement("b"); b.textContent = what; catline.appendChild(b);
  }
  const comboEl = document.getElementById("pew-combo");
  let lastCombo = 0;
  function showCombo(n) {
    lastCombo = n;
    if (RM) return;
    comboEl.textContent = "PEW x" + n;
    comboEl.classList.remove("pop"); void comboEl.offsetWidth; comboEl.classList.add("pop");
  }

  // sound: a chiptune of our own, a pew per collection means and a meow per catch
  let actx = null, master = null, tuneOn = false, sfxOn = false, tuneTimer = null, stepN = 0, nextNote = 0, noiseBuf = null;
  function audio() {
    if (!actx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      actx = new AC(); master = actx.createGain(); master.gain.value = .55; master.connect(actx.destination);
    }
    if (actx.state === "suspended") actx.resume();
    return actx;
  }
  const hz = m => 440 * Math.pow(2, (m - 69) / 12);
  function tone(t, midi, dur, type, vol) {
    const o = actx.createOscillator(), g = actx.createGain();
    o.type = type; o.frequency.setValueAtTime(hz(midi), t);
    g.gain.setValueAtTime(.0001, t); g.gain.exponentialRampToValueAtTime(vol, t + .006); g.gain.exponentialRampToValueAtTime(.0001, t + dur);
    o.connect(g); g.connect(master); o.start(t); o.stop(t + dur + .02);
  }
  function hat(t, vol) {
    if (!noiseBuf) {
      noiseBuf = actx.createBuffer(1, actx.sampleRate * .05, actx.sampleRate);
      const d = noiseBuf.getChannelData(0); for (let i = 0; i < d.length; i++) d[i] = Math.random() * 2 - 1;
    }
    const s = actx.createBufferSource(), f = actx.createBiquadFilter(), g = actx.createGain();
    s.buffer = noiseBuf; f.type = "highpass"; f.frequency.value = 7000;
    g.gain.setValueAtTime(vol, t); g.gain.exponentialRampToValueAtTime(.0001, t + .04);
    s.connect(f); f.connect(g); g.connect(master); s.start(t);
  }
  // Eight bars of eighths: four tiptoeing, four chasing.
  const LEAD = [
    69, 0, 72, 0, 71, 0, 69, 68, 69, 0, 0, 64, 65, 0, 64, 0,
    62, 0, 65, 0, 69, 0, 74, 72, 71, 0, 68, 0, 64, 0, 0, 0,
    69, 72, 76, 81, 80, 76, 72, 71, 69, 72, 77, 81, 79, 77, 76, 74,
    74, 77, 81, 86, 84, 81, 77, 74, 76, 80, 83, 88, 86, 83, 80, 71
  ];
  const ROOTS = [45, 41, 38, 40];
  const EIGHTH = 60 / 152 / 2;
  function schedule() {
    while (nextNote < actx.currentTime + .15) {
      const i = stepN % 64, bar = (i / 8) | 0, beat = i % 8, chase = bar >= 4, r = ROOTS[bar % 4];
      if (LEAD[i]) tone(nextNote, LEAD[i], chase ? EIGHTH * .9 : EIGHTH * .55, "square", chase ? .05 : .06);
      const bass = chase ? [r, r + 12, r, r + 12, r, r + 12, r + 7, r + 12][beat] : [r, 0, r + 7, 0, r + 12, 0, r + 7, 0][beat];
      if (bass) tone(nextNote, bass, EIGHTH * (chase ? .8 : .45), "triangle", .16);
      if (chase || beat % 2 === 1) hat(nextNote, chase ? .05 : .03);
      nextNote += EIGHTH; stepN++;
    }
  }
  function pew(pitch) {
    if (!sfxOn || !actx) return;
    const t = actx.currentTime, o = actx.createOscillator(), g = actx.createGain();
    o.type = "square"; o.frequency.setValueAtTime(pitch, t); o.frequency.exponentialRampToValueAtTime(pitch / 7, t + .14);
    g.gain.setValueAtTime(.045, t); g.gain.exponentialRampToValueAtTime(.0001, t + .15);
    o.connect(g); g.connect(master); o.start(t); o.stop(t + .17);
  }
  function meow() {
    if (!sfxOn || !actx) return;
    const t = actx.currentTime, o = actx.createOscillator(), f = actx.createBiquadFilter(), g = actx.createGain(), k = rand(.9, 1.15);
    o.type = "sawtooth"; f.type = "bandpass"; f.Q.value = 3.5;
    o.frequency.setValueAtTime(470 * k, t); o.frequency.linearRampToValueAtTime(760 * k, t + .13); o.frequency.linearRampToValueAtTime(420 * k, t + .44);
    f.frequency.setValueAtTime(900, t); f.frequency.linearRampToValueAtTime(1900, t + .16); f.frequency.linearRampToValueAtTime(700, t + .44);
    g.gain.setValueAtTime(.0001, t); g.gain.exponentialRampToValueAtTime(.22, t + .05); g.gain.exponentialRampToValueAtTime(.0001, t + .46);
    o.connect(f); f.connect(g); g.connect(master); o.start(t); o.stop(t + .5);
  }

  const tuneBtn = document.getElementById("pew-tune"), sfxBtn = document.getElementById("pew-sfx"), pauseBtn = document.getElementById("pew-pause");
  tuneBtn.addEventListener("click", () => {
    if (!tuneOn && !audio()) return;
    tuneOn = !tuneOn;
    if (tuneOn) { nextNote = actx.currentTime + .05; stepN = 0; tuneTimer = setInterval(schedule, 25); schedule(); }
    else { clearInterval(tuneTimer); tuneTimer = null; }
    tuneBtn.setAttribute("aria-pressed", String(tuneOn));
    tuneBtn.querySelector("span").textContent = tuneOn ? "Stop the chase tune" : "Play the chase tune";
  });
  sfxBtn.addEventListener("click", () => {
    if (!sfxOn && !audio()) return;
    sfxOn = !sfxOn;
    sfxBtn.setAttribute("aria-pressed", String(sfxOn));
    if (sfxOn) meow();
  });
  pauseBtn.addEventListener("click", () => {
    paused = !paused;
    pauseBtn.setAttribute("aria-pressed", String(paused));
    pauseBtn.querySelector("span").textContent = paused ? "Resume" : "Pause";
    document.getElementById("pew-live").classList.toggle("paused", paused);
    lastCat = ""; setCatline();
  });
  document.querySelectorAll(".pew-mean").forEach(btn => {
    btn.addEventListener("click", () => {
      const m = MEANS[btn.dataset.means];
      if (!m) return;
      m.on = !m.on;
      btn.setAttribute("aria-pressed", String(m.on));
    });
  });
  const filters = document.getElementById("pew-filters");
  filters.querySelectorAll("select, input").forEach(el => el.addEventListener("change", () => filters.submit()));

  // Maximise: the map takes the whole browser window, until the button or Escape.
  const maxBtn = document.getElementById("pew-max");
  function maximise(on) {
    mapEl.classList.toggle("maximised", on);
    document.body.classList.toggle("pew-maximised", on);
    maxBtn.setAttribute("aria-pressed", String(on));
    maxBtn.querySelector("span").textContent = on ? "Back to normal view" : "Maximise";
    maxBtn.querySelector("i").className = (on ? "fas fa-compress" : "fas fa-expand") + " me-1";
  }
  maxBtn.addEventListener("click", () => maximise(!mapEl.classList.contains("maximised")));
  document.addEventListener("keydown", e => { if (e.key === "Escape" && mapEl.classList.contains("maximised")) maximise(false); });

  let last = performance.now();
  function frame(now) {
    const dt = Math.min(.05, (now - last) / 1000); last = now;
    if (!paused) step(dt);
    draw();
    requestAnimationFrame(frame);
  }
  resize();
  plan(data.indicators || []);
  // A first frame with something in the air rather than an empty sea.
  for (let i = 0; i < 3 && qi < queue.length; i++) { const it = queue[qi++]; fire(it); setClock(it); lasers[lasers.length - 1].p = .3 + i * .2; }
  if (qi < queue.length) nextAt = queue[qi].gap || .5;
  recent.length = 0;
  draw();
  if ("ResizeObserver" in window) new ResizeObserver(resize).observe(stage);
  else window.addEventListener("resize", resize);
  requestAnimationFrame(t => { last = t; frame(t); });
})();
