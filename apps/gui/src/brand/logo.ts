/**
 * APIaxess logo assets, transcribed verbatim from the identity kit
 * (`assets/brand/Apiaxess Logo Kit.html`, Identity kit / v2.1).
 *
 * The mark is the chevron-plus-arrow: an Ink bracket enclosing a Signal Blue
 * shaft and arrowhead. The horizontal lockup — mark beside the wordmark — is
 * the primary lockup and is what the app shell uses.
 *
 * Colours are emitted as `currentColor` and `var(--color-accent)` so the marks
 * inherit the token system rather than pinning hex values a second time.
 */

/** Ink/accent split used by every full-colour mark. */
type MarkTone = "duo" | "mono";

interface MarkOptions {
  /** Rendered edge length in pixels; the mark is always square. */
  readonly size: number;
  /** `duo` keeps the Signal Blue accent, `mono` renders single-colour. */
  readonly tone?: MarkTone;
  /** Accessible title, or omitted for decorative use. */
  readonly title?: string;
}

const ACCENT = "var(--color-accent)";

/*
 * Lockup proportions, measured off every lockup in the kit. They are identical
 * across the primary (132/96), reversed (66/48) and clearspace (104/74)
 * lockups, so they are the kit's ratios rather than one sample's.
 */

/** Horizontal lockup: mark edge as a multiple of the wordmark's font size. */
const MARK_TO_WORDMARK = 1.375;
/** Stacked lockup: the kit sets a larger mark over a smaller wordmark (98/44). */
const STACKED_MARK_TO_WORDMARK = 2.227;
/** Inline chevron glyph, as a multiple of the wordmark's font size. */
const GLYPH_WIDTH_RATIO = 0.542;
const GLYPH_HEIGHT_RATIO = 0.521;

function accentStroke(tone: MarkTone): string {
  return tone === "mono" ? "currentColor" : ACCENT;
}

/**
 * The primary mark at kit geometry: 200x200 viewBox, 14-unit strokes.
 */
export function markSvg({ size, tone = "duo", title }: MarkOptions): string {
  const accent = accentStroke(tone);
  const label =
    title === undefined
      ? ' aria-hidden="true" focusable="false"'
      : ` role="img" aria-label="${title}"`;
  return `<svg class="brand-mark" width="${size}" height="${size}" viewBox="0 0 200 200" fill="none"${label}>
<path d="M138 60 L100 22 L22 100 L100 178 L138 140" stroke="currentColor" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"></path>
<path d="M50 100 H140" stroke="${accent}" stroke-width="14" stroke-linecap="round"></path>
<path d="M118 78 L142 100 L118 122" stroke="${accent}" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"></path>
<path d="M168 78 L142 100 L168 122" stroke="currentColor" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"></path>
</svg>`;
}

/**
 * The wordmark's inline chevron glyph, which replaces the `x` in "apiaxess".
 * Kit geometry: 56x54 viewBox, 11-unit strokes, baseline-aligned.
 */
function wordmarkGlyph(fontSizePx: number, tone: MarkTone): string {
  const width = Math.round(fontSizePx * GLYPH_WIDTH_RATIO);
  const height = Math.round(fontSizePx * GLYPH_HEIGHT_RATIO);
  const accent = accentStroke(tone);
  return `<svg class="brand-wordmark__glyph" width="${width}" height="${height}" viewBox="0 0 56 54" fill="none" aria-hidden="true" focusable="false">
<path d="M6 10 L24 27 L6 44" stroke="currentColor" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"></path>
<path d="M50 10 L32 27 L50 44" stroke="${accent}" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"></path>
</svg>`;
}

/**
 * The wordmark: Outfit 500 at the kit's -0.05em tracking, with the chevron
 * glyph standing in for the `x`. The literal text is kept in an
 * accessibility-only span so the product name stays selectable and readable
 * to assistive technology.
 */
export function wordmarkHtml(fontSizePx: number, tone: MarkTone = "duo"): string {
  return `<span class="brand-wordmark" style="font-size:${fontSizePx}px" translate="no"><span class="visually-hidden">apiaxess</span><span aria-hidden="true">apia${wordmarkGlyph(fontSizePx, tone)}ess</span></span>`;
}

/**
 * Primary horizontal lockup — mark, kit clearspace, wordmark.
 *
 * The mark is derived from the wordmark size at the kit's ratio rather than
 * being passed separately, so the lockup cannot be assembled out of proportion.
 * `.brand-lockup` supplies the clearspace gap in the same em unit.
 */
export function lockupHtml(wordmarkSize = 24, tone: MarkTone = "duo"): string {
  const markSize = Math.round(wordmarkSize * MARK_TO_WORDMARK);
  return `<span class="brand-lockup" style="font-size:${wordmarkSize}px" translate="no">${markSvg({ size: markSize, tone })}${wordmarkHtml(wordmarkSize, tone)}</span>`;
}

/**
 * Stacked lockup — mark over wordmark, at the kit's own stacked proportions,
 * which set a larger mark against a smaller wordmark than the horizontal
 * lockup does.
 */
export function stackedLockupHtml(
  wordmarkSize = 28,
  tone: MarkTone = "duo",
): string {
  const markSize = Math.round(wordmarkSize * STACKED_MARK_TO_WORDMARK);
  return `<span class="brand-lockup brand-lockup--stacked" style="font-size:${wordmarkSize}px" translate="no">${markSvg({ size: markSize, tone, title: "APIaxess" })}${wordmarkHtml(wordmarkSize, tone)}</span>`;
}
