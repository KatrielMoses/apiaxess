#!/usr/bin/env node
/*
 * Regenerates the Windows installer's brand art from the vector sources:
 *
 *   packaging/windows/banner.bmp   493x58  24-bit  WixUIBannerBmp (top banner)
 *   packaging/windows/dialog.bmp   493x312 24-bit  WixUIDialogBmp (Welcome/Exit)
 *   apps/desktop/icons/icon.ico    16..256 PNG     app icon embedded in
 *                                                  apiaxess-desktop.exe (ARP,
 *                                                  shortcuts, taskbar, wizard)
 *
 * Every pixel is rasterised once, at its final size, by the pinned Chromium the
 * MSI already bundles (packaging/assets/chromium-manifest.toml) — the mark is
 * never drawn small and scaled up, and there is no hand-made intermediate.
 * Sources of truth:
 *
 *   apps/desktop/icons/icon.svg          mark geometry, tile, and colours
 *   apps/gui/src/brand/logo.ts           lockup ratios and wordmark glyph
 *   apps/gui/src/styles/tokens.css       palette
 *   apps/gui/public/fonts/*.woff2        Outfit (wordmark), Archivo (caption)
 *
 * Usage (from the repository root, Windows, Node 22+):
 *
 *   node packaging/windows/gen-installer-bmps.mjs            write all outputs
 *   node packaging/windows/gen-installer-bmps.mjs --check    exit 1 on drift
 *   ... --chromium <chrome.exe>   use a specific Chromium build
 *   ... --preview <dir>           also write PNG previews (icon frames, art)
 *
 * Without --chromium the script uses the Chromium that build-msi.ps1 or
 * fetch-chromium.ps1 staged under target/, fetching it (pinned + SHA-256
 * verified) through fetch-chromium.ps1 when neither exists.
 */

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inflateSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");

const paths = {
  iconSvg: join(repo, "apps", "desktop", "icons", "icon.svg"),
  iconIco: join(repo, "apps", "desktop", "icons", "icon.ico"),
  banner: join(here, "banner.bmp"),
  dialog: join(here, "dialog.bmp"),
  outfit: join(repo, "apps", "gui", "public", "fonts", "outfit-latin.woff2"),
  archivo: join(repo, "apps", "gui", "public", "fonts", "archivo-latin.woff2"),
};

/* Palette (tokens.css). */
const INK = "#0D0D0D";
const PAPER = "#FFFFFF";
const SIGNAL_BLUE = "#2D7FF9";
const SIGNAL_GREEN = "#00E676";
const INK_TEXT_MUTED = "#B0B0B0";
/*
 * Windows' default dialog face (COLOR_BTNFACE). MSI paints checkboxes and the
 * button bar in it, opaquely, so the art's text ground must match it exactly
 * or the Welcome/Exit checkboxes sit in a visible grey box.
 */
const DIALOG_FACE = "#F0F0F0";

/* Lockup ratios (logo.ts). */
const MARK_TO_WORDMARK = 1.375;
const STACKED_MARK_TO_WORDMARK = 2.227;
const LOCKUP_GAP_EM = 0.354;
const STACKED_GAP_EM = 0.545;
const GLYPH_WIDTH_RATIO = 0.542;
const GLYPH_HEIGHT_RATIO = 0.521;

/*
 * WixUI geometry. The dialog set is 370x270 dialog units; the bitmaps map
 * 370 DLU onto 493 px (4/3 px per DLU at 100% scaling). Text on the Welcome
 * and Exit dialogs starts at X=135 DLU (180 px), and the banner's title and
 * description span X=15..305 DLU (20..407 px, though real strings end well
 * before 330 px). WixUI_Minimal's first page (WelcomeEulaDlg) starts its title
 * and license box further left, at X=130 DLU (173 px), so the rail stops at
 * 156 px (117 DLU) to leave that column clear air.
 */
const DIALOG = { width: 493, height: 312, panel: 156 };
const BANNER = { width: 493, height: 58, panel: 156 };

/*
 * The mark: 200x200 kit space, 14-unit round strokes, taken verbatim from
 * icon.svg so the installer can never drift from the app icon.
 */
function readMark() {
  const svg = readFileSync(paths.iconSvg, "utf8");
  const group = svg.match(/<g\s+transform="translate\(([\d.]+),([\d.]+)\)\s*scale\(([\d.]+)\)"[^>]*stroke-width="([\d.]+)"/);
  const tile = svg.match(/<rect[^>]*width="(\d+)"[^>]*rx="(\d+)"[^>]*fill="(#[0-9A-Fa-f]{6})"/);
  const strokes = [...svg.matchAll(/<path d="([^"]+)" stroke="(#[0-9A-Fa-f]{6})"\/>/g)].map((m) => ({
    d: m[1],
    accent: m[2].toUpperCase() === SIGNAL_BLUE,
  }));
  if (!group || !tile || strokes.length !== 4) {
    throw new Error(`icon.svg no longer has the expected tile + 4-stroke mark layout (${paths.iconSvg})`);
  }
  return {
    paths: strokes,
    stroke: Number(group[4]),
    tileSize: Number(tile[1]),
    tileRadius: Number(tile[2]),
    tileFill: tile[3],
    offsetX: Number(group[1]),
    offsetY: Number(group[2]),
    scale: Number(group[3]),
  };
}

const mark = readMark();

/** The mark as inline SVG, `size` px square, with an optional stroke override. */
function markSvg(size, { ink = PAPER, accent = SIGNAL_BLUE, stroke = mark.stroke, cls = "mark" } = {}) {
  const body = mark.paths
    .map((p) => `<path d="${p.d}" stroke="${p.accent ? accent : ink}"/>`)
    .join("");
  return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 200 200" fill="none" stroke-width="${stroke}" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
}

/** The wordmark (logo.ts): Outfit 500, -0.05em, chevron glyph for the x. */
function wordmarkHtml(fontPx, { ink = PAPER, accent = SIGNAL_BLUE } = {}) {
  const w = Math.round(fontPx * GLYPH_WIDTH_RATIO);
  const h = Math.round(fontPx * GLYPH_HEIGHT_RATIO);
  const glyph = `<svg class="glyph" width="${w}" height="${h}" viewBox="0 0 56 54" fill="none" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"><path d="M6 10 L24 27 L6 44" stroke="${ink}"/><path d="M50 10 L32 27 L50 44" stroke="${accent}"/></svg>`;
  return `<span class="wordmark" style="font-size:${fontPx}px;color:${ink}">apia${glyph}ess</span>`;
}

function fontFace(family, file, weight) {
  const data = readFileSync(file).toString("base64");
  return `@font-face{font-family:"${family}";font-weight:${weight};font-style:normal;font-display:block;src:url(data:font/woff2;base64,${data}) format("woff2")}`;
}

const baseCss = [
  fontFace("Outfit", paths.outfit, "100 900"),
  fontFace("Archivo", paths.archivo, "100 900"),
  `*{margin:0;padding:0;box-sizing:border-box}
   html,body{width:100%;height:100%;overflow:hidden;background:transparent}
   .abs{position:absolute}
   .mark,.glyph{display:block;flex:none}
   .lockup{display:inline-flex;align-items:center;white-space:nowrap}
   .lockup--stacked{flex-direction:column}
   .wordmark{display:inline-flex;align-items:baseline;font-family:"Outfit";font-weight:500;letter-spacing:-0.05em;line-height:1;white-space:nowrap}
   .glyph{display:inline-block;margin:0 0.04em}`,
].join("\n");

/*
 * After fonts load, nudge every `.snap` element by a sub-pixel amount so the
 * mark's horizontal Signal Blue shaft — the one axis-aligned stroke — lands
 * exactly on pixel rows. Diagonals are anti-aliased either way; the shaft is
 * where a half-pixel offset would read as blur.
 */
const snapScript = `
for (const el of document.querySelectorAll(".snap")) {
  const m = el.querySelector(".mark");
  const r = m.getBoundingClientRect();
  const stroke = Number(m.getAttribute("stroke-width")) * r.height / 200;
  const shaftTop = r.top + r.height / 2 - stroke / 2;
  const dy = Math.round(shaftTop) - shaftTop;
  const dx = Math.round(r.left) - r.left;
  el.style.transform = "translate(" + dx + "px," + dy + "px)";
}`;

function page(body, css = "") {
  return `<!doctype html><html><head><meta charset="utf-8"><style>${baseCss}\n${css}</style></head><body>${body}</body></html>`;
}

/* ------------------------------------------------------------------ *
 * Compositions
 * ------------------------------------------------------------------ */

/*
 * Welcome/Exit art. Ink rail on the left carrying the stacked lockup; the rest
 * is the plain ground the wizard's title, body and "Launch APIaxess now"
 * checkbox sit on. WixUI draws that text in the system text colour (black) and
 * paints the checkboxes on the system dialog face, so the ground is that face
 * and carries nothing — the art reads as one surface with the button bar.
 */
function dialogHtml() {
  const { width, height, panel } = DIALOG;
  const strokePx = 5; // mark stroke in px: an integer keeps the shaft crisp
  const markPx = (strokePx * 200) / mark.stroke;
  const wordPx = markPx / STACKED_MARK_TO_WORDMARK;
  const css = `
    body{width:${width}px;height:${height}px;background:${DIALOG_FACE}}
    .rail{left:0;top:0;width:${panel}px;height:${height}px;background:${INK}}
    .edge{left:${panel}px;top:0;width:2px;height:${height}px;background:${SIGNAL_BLUE}}
    .center{left:0;top:0;width:${panel}px;height:${height - 44}px;display:flex;align-items:center;justify-content:center}
    .lockup--stacked{gap:${STACKED_GAP_EM}em;font-size:${wordPx}px}
    .caption{left:0;bottom:22px;width:${panel}px;display:flex;align-items:center;justify-content:center;gap:7px;
      font-family:"Archivo";font-weight:500;font-size:11px;line-height:12px;letter-spacing:0.02em;color:${INK_TEXT_MUTED}}
    .dot{width:6px;height:6px;border-radius:3px;background:${SIGNAL_GREEN}}`;
  const body = `
    <div class="abs rail"></div>
    <div class="abs edge"></div>
    <div class="abs center"><div class="lockup lockup--stacked snap">${markSvg(markPx)}${wordmarkHtml(wordPx)}</div></div>
    <div class="abs caption"><span class="dot"></span><span>API security workbench</span></div>`;
  return { html: page(body, css), width, height, opaque: true };
}

/*
 * Banner: Paper ground under WixUI's black page title and description, with
 * the horizontal lockup reversed out of an Ink block at the right edge — the
 * same 156 px as the dialog's rail, so the two read as one system.
 */
function bannerHtml() {
  const { width, height, panel } = BANNER;
  const strokePx = 2; // 28.6 px mark, 20.8 px wordmark
  const markPx = (strokePx * 200) / mark.stroke;
  const wordPx = markPx / MARK_TO_WORDMARK;
  const css = `
    body{width:${width}px;height:${height}px;background:${PAPER}}
    .block{left:${width - panel}px;top:0;width:${panel}px;height:${height}px;background:${INK};
      display:flex;align-items:center;justify-content:center}
    .edge{left:${width - panel - 2}px;top:0;width:2px;height:${height}px;background:${SIGNAL_BLUE}}
    .lockup{gap:${LOCKUP_GAP_EM}em;font-size:${wordPx}px}`;
  const body = `
    <div class="abs edge"></div>
    <div class="abs block"><div class="lockup snap">${markSvg(markPx)}${wordmarkHtml(wordPx)}</div></div>`;
  return { html: page(body, css), width, height, opaque: true };
}

/*
 * App icon frames. 64 px and up are the icon.svg master exactly. Below that the
 * master's 14-unit stroke falls under ~2 px and, by 16 px, dissolves into grey,
 * so the smaller frames are optically sized the way hand-hinted icons are: the mark
 * fills more of the tile and its stroke is held near 1.5-2 px, while geometry,
 * colours and the tile stay the master's.
 */
const ICON_FRAMES = [
  // size, mark box as a fraction of the tile, stroke (kit units), tile radius fraction
  { size: 16, cover: 0.84, stroke: 22, radius: 0.19 },
  { size: 20, cover: 0.8, stroke: 21, radius: 0.2 },
  { size: 24, cover: 0.78, stroke: 20, radius: 0.2 },
  { size: 32, cover: 0.72, stroke: 18, radius: 0.21 },
  { size: 40, cover: 0.68, stroke: 16, radius: 0.21 },
  { size: 48, cover: 0.64, stroke: 15, radius: 0.215 },
  { size: 64 },
  { size: 256 },
];

function iconHtml(frame) {
  const { size } = frame;
  const master = frame.cover === undefined;
  const radius = (master ? mark.tileRadius / mark.tileSize : frame.radius) * size;
  let markPx;
  let left;
  let top;
  if (master) {
    markPx = (mark.scale * 200 * size) / mark.tileSize;
    left = (mark.offsetX * size) / mark.tileSize;
    top = (mark.offsetY * size) / mark.tileSize;
  } else {
    // Keep the master's optical centre (its mark sits slightly left of centre
    // because the arrowhead's open side is lighter).
    const cx = (mark.offsetX + 100 * mark.scale) / mark.tileSize;
    const cy = (mark.offsetY + 100 * mark.scale) / mark.tileSize;
    markPx = frame.cover * size;
    left = cx * size - markPx / 2;
    top = cy * size - markPx / 2;
  }
  const stroke = frame.stroke ?? mark.stroke;
  const css = `
    body{width:${size}px;height:${size}px}
    .tile{left:0;top:0;width:${size}px;height:${size}px;border-radius:${radius}px;background:${mark.tileFill}}
    .at{left:${left}px;top:${top}px}`;
  const body = `<div class="abs tile"></div><div class="abs at snap">${markSvg(markPx, { stroke })}</div>`;
  return { html: page(body, css), width: size, height: size, opaque: false };
}

/* ------------------------------------------------------------------ *
 * Chromium over the DevTools protocol
 * ------------------------------------------------------------------ */

function resolveChromium(explicit) {
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`--chromium ${explicit} does not exist`);
    return explicit;
  }
  const staged = [
    join(repo, "target", "packaging", "windows-x64", "chromium-runtime", "chrome.exe"),
    join(repo, "target", "packaging", "chromium-windows_x64", "chrome.exe"),
  ];
  const found = staged.find((p) => existsSync(p));
  if (found) return found;
  console.log("Fetching the pinned Chromium renderer (fetch-chromium.ps1)...");
  const fetched = spawnSync(
    "pwsh",
    ["-NoProfile", "-File", join(repo, "packaging", "assets", "fetch-chromium.ps1"), "-Platform", "windows_x64"],
    { stdio: "inherit" },
  );
  if (fetched.status !== 0 || !existsSync(staged[1])) {
    throw new Error("could not fetch the pinned Chromium; pass --chromium <chrome.exe>");
  }
  return staged[1];
}

async function launchChromium(binary) {
  const profile = mkdtempSync(join(tmpdir(), "apiaxess-installer-art-"));
  const child = spawn(
    binary,
    [
      "--headless",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--hide-scrollbars",
      "--force-color-profile=srgb",
      "--force-device-scale-factor=1",
      "--disable-lcd-text",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"], windowsHide: true },
  );
  const endpoint = await new Promise((resolveEndpoint, reject) => {
    let log = "";
    const timer = setTimeout(() => reject(new Error(`Chromium did not expose DevTools:\n${log}`)), 30000);
    child.stderr.on("data", (chunk) => {
      log += chunk;
      const hit = log.match(/DevTools listening on (ws:\/\/\S+)/);
      if (hit) {
        clearTimeout(timer);
        resolveEndpoint(hit[1]);
      }
    });
    child.on("exit", (code) => reject(new Error(`Chromium exited (${code}) before DevTools came up:\n${log}`)));
  });

  const socket = new WebSocket(endpoint);
  await new Promise((ok, fail) => {
    socket.onopen = ok;
    socket.onerror = () => fail(new Error("DevTools socket failed to open"));
  });
  let nextId = 0;
  const pending = new Map();
  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    const waiter = msg.id !== undefined && pending.get(msg.id);
    if (!waiter) return;
    pending.delete(msg.id);
    if (msg.error) waiter.reject(new Error(`${waiter.method}: ${msg.error.message}`));
    else waiter.resolve(msg.result);
  };
  const send = (method, params = {}, sessionId) =>
    new Promise((ok, fail) => {
      const id = ++nextId;
      pending.set(id, { resolve: ok, reject: fail, method });
      socket.send(JSON.stringify({ id, method, params, sessionId }));
    });

  const close = async () => {
    try {
      await Promise.race([send("Browser.close"), new Promise((r) => setTimeout(r, 3000))]);
    } catch {
      /* already gone */
    }
    socket.close();
    if (child.exitCode === null) {
      await new Promise((r) => {
        const kill = setTimeout(() => {
          child.kill();
          r();
        }, 5000);
        child.once("exit", () => {
          clearTimeout(kill);
          r();
        });
      });
    }
    rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  };
  return { send, close };
}

async function render(browser, scratch, name, { html, width, height, opaque }) {
  const file = join(scratch, `${name}.html`);
  writeFileSync(file, html);
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await browser.send("Target.attachToTarget", { targetId, flatten: true });
  const s = (method, params) => browser.send(method, params, sessionId);
  await s("Page.enable");
  await s("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
  await s("Emulation.setDefaultBackgroundColorOverride", { color: { r: 0, g: 0, b: 0, a: 0 } });
  await s("Page.navigate", { url: pathToFileURL(file).href });
  const ready = await s("Runtime.evaluate", {
    expression: `new Promise((ok) => { const go = () => Promise.all([
        document.fonts.load('500 20px "Outfit"'), document.fonts.load('500 11px "Archivo"'),
      ]).then(() => document.fonts.ready).then(() => {
      ${snapScript}
      requestAnimationFrame(() => requestAnimationFrame(() => ok(
        document.fonts.check('500 20px "Outfit"') && document.fonts.check('500 11px "Archivo"'))));
    }); if (document.readyState === "complete") go(); else addEventListener("load", go); })`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (ready.result.value !== true) throw new Error(`${name}: brand fonts did not load`);
  const shot = await s("Page.captureScreenshot", {
    format: "png",
    clip: { x: 0, y: 0, width, height, scale: 1 },
    fromSurface: true,
  });
  await browser.send("Target.closeTarget", { targetId });
  const png = Buffer.from(shot.data, "base64");
  const image = decodePng(png);
  if (image.width !== width || image.height !== height) {
    throw new Error(`${name}: rendered ${image.width}x${image.height}, expected ${width}x${height}`);
  }
  if (opaque) {
    for (let i = 3; i < image.rgba.length; i += 4) {
      if (image.rgba[i] !== 255) throw new Error(`${name}: art must be fully opaque`);
    }
  }
  return { png, image };
}

/* ------------------------------------------------------------------ *
 * Image codecs (PNG decode, BMP + ICO encode) — no dependencies
 * ------------------------------------------------------------------ */

function decodePng(buf) {
  const sig = "89504e470d0a1a0a";
  if (buf.subarray(0, 8).toString("hex") !== sig) throw new Error("not a PNG");
  let pos = 8;
  let width = 0;
  let height = 0;
  let colorType = 0;
  const idat = [];
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString("latin1", pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      colorType = data[9];
      if (data[8] !== 8 || data[12] !== 0 || (colorType !== 6 && colorType !== 2)) {
        throw new Error("PNG must be 8-bit, non-interlaced RGB/RGBA");
      }
    } else if (type === "IDAT") {
      idat.push(data);
    }
    pos += 12 + len;
  }
  const bpp = colorType === 6 ? 4 : 3;
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * bpp;
  const out = Buffer.alloc(width * height * 4);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    const line = Buffer.from(raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)));
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? line[x - bpp] : 0;
      const b = prev[x];
      const c = x >= bpp ? prev[x - bpp] : 0;
      let add = 0;
      if (filter === 1) add = a;
      else if (filter === 2) add = b;
      else if (filter === 3) add = (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        add = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      line[x] = (line[x] + add) & 0xff;
    }
    for (let x = 0; x < width; x++) {
      const o = (y * width + x) * 4;
      out[o] = line[x * bpp];
      out[o + 1] = line[x * bpp + 1];
      out[o + 2] = line[x * bpp + 2];
      out[o + 3] = bpp === 4 ? line[x * bpp + 3] : 255;
    }
    prev = line;
  }
  return { width, height, rgba: out };
}

/** 24-bit, bottom-up, uncompressed BMP — the format WixUI bitmaps require. */
function encodeBmp24({ width, height, rgba }) {
  const rowBytes = Math.ceil((width * 3) / 4) * 4;
  const pixelBytes = rowBytes * height;
  const buf = Buffer.alloc(54 + pixelBytes);
  buf.write("BM", 0, "latin1");
  buf.writeUInt32LE(54 + pixelBytes, 2);
  buf.writeUInt32LE(54, 10);
  buf.writeUInt32LE(40, 14);
  buf.writeInt32LE(width, 18);
  buf.writeInt32LE(height, 22);
  buf.writeUInt16LE(1, 26);
  buf.writeUInt16LE(24, 28);
  buf.writeUInt32LE(0, 30);
  buf.writeUInt32LE(pixelBytes, 34);
  buf.writeInt32LE(3780, 38); // 96 dpi
  buf.writeInt32LE(3780, 42);
  for (let y = 0; y < height; y++) {
    const row = 54 + (height - 1 - y) * rowBytes;
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      buf[row + x * 3] = rgba[i + 2];
      buf[row + x * 3 + 1] = rgba[i + 1];
      buf[row + x * 3 + 2] = rgba[i];
    }
  }
  return buf;
}

function decodeBmp24(buf) {
  if (buf.toString("latin1", 0, 2) !== "BM" || buf.readUInt16LE(28) !== 24 || buf.readUInt32LE(30) !== 0) {
    throw new Error("not an uncompressed 24-bit BMP");
  }
  const width = buf.readInt32LE(18);
  const height = buf.readInt32LE(22);
  const offset = buf.readUInt32LE(10);
  const rowBytes = Math.ceil((width * 3) / 4) * 4;
  const rgba = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y++) {
    const row = offset + (height - 1 - y) * rowBytes;
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      rgba[i] = buf[row + x * 3 + 2];
      rgba[i + 1] = buf[row + x * 3 + 1];
      rgba[i + 2] = buf[row + x * 3];
      rgba[i + 3] = 255;
    }
  }
  return { width, height, rgba };
}

/** ICO with PNG-compressed frames (supported by Windows since Vista). */
function encodeIco(frames) {
  const header = Buffer.alloc(6 + 16 * frames.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(frames.length, 4);
  let offset = header.length;
  frames.forEach(({ size, png }, i) => {
    const e = 6 + i * 16;
    header[e] = size >= 256 ? 0 : size;
    header[e + 1] = size >= 256 ? 0 : size;
    header.writeUInt16LE(1, e + 4);
    header.writeUInt16LE(32, e + 6);
    header.writeUInt32LE(png.length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += png.length;
  });
  return Buffer.concat([header, ...frames.map((f) => f.png)]);
}

function decodeIco(buf) {
  const count = buf.readUInt16LE(4);
  const frames = [];
  for (let i = 0; i < count; i++) {
    const e = 6 + i * 16;
    const size = buf[e] || 256;
    const len = buf.readUInt32LE(e + 8);
    const at = buf.readUInt32LE(e + 12);
    frames.push({ size, image: decodePng(buf.subarray(at, at + len)) });
  }
  return frames;
}

/** Mean absolute channel difference; tolerates renderer AA noise, not redesigns. */
function drift(a, b) {
  if (a.width !== b.width || a.height !== b.height) return Infinity;
  let sum = 0;
  for (let i = 0; i < a.rgba.length; i++) sum += Math.abs(a.rgba[i] - b.rgba[i]);
  return sum / a.rgba.length;
}

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

function parseArgs(argv) {
  const args = { check: false, chromium: undefined, preview: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") args.check = true;
    else if (a === "--chromium") args.chromium = argv[++i];
    else if (a === "--preview") args.preview = resolve(argv[++i]);
    else throw new Error(`unknown argument ${a}`);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const chromium = resolveChromium(args.chromium);
  const scratch = mkdtempSync(join(tmpdir(), "apiaxess-installer-art-src-"));
  const browser = await launchChromium(chromium);
  let dialog;
  let banner;
  const frames = [];
  try {
    dialog = await render(browser, scratch, "dialog", dialogHtml());
    banner = await render(browser, scratch, "banner", bannerHtml());
    for (const frame of ICON_FRAMES) {
      const { png, image } = await render(browser, scratch, `icon-${frame.size}`, iconHtml(frame));
      frames.push({ size: frame.size, png, image });
    }
  } finally {
    await browser.close();
    rmSync(scratch, { recursive: true, force: true });
  }

  if (args.preview) {
    mkdirSync(args.preview, { recursive: true });
    writeFileSync(join(args.preview, "dialog.png"), dialog.png);
    writeFileSync(join(args.preview, "banner.png"), banner.png);
    for (const f of frames) writeFileSync(join(args.preview, `icon-${f.size}.png`), f.png);
  }

  if (args.check) {
    const problems = [];
    const compare = (label, fresh, committedPath, decode) => {
      if (!existsSync(committedPath)) return problems.push(`${label}: missing ${committedPath}`);
      const committed = decode(readFileSync(committedPath));
      const d = drift(fresh, committed);
      if (d > 1) problems.push(`${label}: differs from a fresh render (mean channel drift ${d.toFixed(2)})`);
    };
    compare("dialog.bmp", dialog.image, paths.dialog, decodeBmp24);
    compare("banner.bmp", banner.image, paths.banner, decodeBmp24);
    if (existsSync(paths.iconIco)) {
      const committed = new Map(decodeIco(readFileSync(paths.iconIco)).map((f) => [f.size, f.image]));
      for (const f of frames) {
        const c = committed.get(f.size);
        if (!c) problems.push(`icon.ico: no ${f.size}px frame`);
        else if (drift(f.image, c) > 1) problems.push(`icon.ico: ${f.size}px frame differs from a fresh render`);
      }
    } else {
      problems.push(`icon.ico: missing ${paths.iconIco}`);
    }
    if (problems.length) {
      console.error(`Installer art is stale — rerun node packaging/windows/gen-installer-bmps.mjs:\n  ${problems.join("\n  ")}`);
      process.exit(1);
    }
    console.log("Installer art matches its vector sources.");
    return;
  }

  writeFileSync(paths.dialog, encodeBmp24(dialog.image));
  writeFileSync(paths.banner, encodeBmp24(banner.image));
  writeFileSync(paths.iconIco, encodeIco(frames));
  console.log(`Wrote ${paths.dialog}\nWrote ${paths.banner}\nWrote ${paths.iconIco} (${frames.map((f) => f.size).join("/")} px)`);
}

main().catch((error) => {
  console.error(error.message ?? error);
  process.exit(1);
});
