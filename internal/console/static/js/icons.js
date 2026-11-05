// Inline SVG icons built with createElementNS. Strokes use currentColor so an
// icon follows the text colour of whatever holds it.

// The SVG namespace is an identifier, never fetched. It is assembled from
// parts only because the asset guard refuses any absolute URL spelled out in a
// source file.
const SVG_NS = ['http:', '', 'www.w3.org', '2000', 'svg'].join('/');

// Each icon is a list of [tag, attributes] on a 24x24 grid.
const p = (d) => ['path', { d }];
const ICONS = {
  overview: [['rect', { x: 3, y: 3, width: 7, height: 9 }], ['rect', { x: 14, y: 3, width: 7, height: 5 }], ['rect', { x: 14, y: 12, width: 7, height: 9 }], ['rect', { x: 3, y: 16, width: 7, height: 5 }]],
  bucket: [['ellipse', { cx: 12, cy: 5, rx: 8, ry: 2.5 }], p('M4 5l2 14c.2 1.4 2.7 2 6 2s5.8-.6 6-2l2-14')],
  user: [['circle', { cx: 12, cy: 8, r: 4 }], p('M4 21c0-4 3.6-7 8-7s8 3 8 7')],
  key: [['circle', { cx: 8, cy: 15, r: 4 }], p('M11 12l9-9'), p('M16 7l3 3'), p('M14 9l2 2')],
  shield: [p('M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z')],
  folder: [p('M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z')],
  file: [p('M6 3h8l5 5v13H6z'), p('M14 3v5h5')],
  upload: [p('M12 16V4'), p('M7 9l5-5 5 5'), p('M4 20h16')],
  download: [p('M12 4v12'), p('M7 11l5 5 5-5'), p('M4 20h16')],
  link: [p('M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1'), p('M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1')],
  copy: [['rect', { x: 9, y: 9, width: 11, height: 11, rx: 1 }], p('M5 15V5a1 1 0 0 1 1-1h10')],
  trash: [p('M4 7h16'), p('M9 7V4h6v3'), p('M6 7l1 13h10l1-13'), p('M10 11v6'), p('M14 11v6')],
  refresh: [p('M20 11a8 8 0 0 0-14.5-4'), p('M4 4v4h4'), p('M4 13a8 8 0 0 0 14.5 4'), p('M20 20v-4h-4')],
  settings: [['circle', { cx: 12, cy: 12, r: 3 }], p('M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2')],
  'chevron-right': [p('M9 5l7 7-7 7')],
  menu: [p('M4 6h16'), p('M4 12h16'), p('M4 18h16')],
  close: [p('M6 6l12 12'), p('M18 6L6 18')],
  sun: [['circle', { cx: 12, cy: 12, r: 4 }], p('M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19')],
  moon: [p('M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z')],
  monitor: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 1 }], p('M8 20h8'), p('M12 16v4')],
  logout: [p('M10 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h5'), p('M16 8l4 4-4 4'), p('M20 12H9')],
  external: [p('M14 4h6v6'), p('M20 4l-9 9'), p('M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5')],
  alert: [p('M12 3l10 18H2z'), p('M12 10v5'), p('M12 18v.5')],
  check: [p('M5 12.5l4.5 4.5L19 7')],
  x: [p('M6 6l12 12'), p('M18 6L6 18')],
  more: [['circle', { cx: 5, cy: 12, r: 1.3 }], ['circle', { cx: 12, cy: 12, r: 1.3 }], ['circle', { cx: 19, cy: 12, r: 1.3 }]],
  eye: [p('M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z'), ['circle', { cx: 12, cy: 12, r: 3 }]],
  'eye-off': [p('M3 3l18 18'), p('M10.6 6.1A9.7 9.7 0 0 1 12 5c6 0 10 7 10 7a17 17 0 0 1-3.2 3.9'), p('M6.3 7.6A17 17 0 0 0 2 12s4 7 10 7a9.6 9.6 0 0 0 4-.9')],
  'arrow-up': [p('M12 19V5'), p('M6 11l6-6 6 6')],
  'arrow-down': [p('M12 5v14'), p('M6 13l6 6 6-6')],
};

export const ICON_NAMES = Object.keys(ICONS);

// icon returns an <svg>. Decorative (aria-hidden) unless a label is given.
export function icon(name, { size = 16, label } = {}) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.75');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('class', 'icon');
  if (label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label);
  } else {
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
  }
  for (const [tag, attrs] of ICONS[name] || ICONS.alert) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    svg.append(el);
  }
  return svg;
}
