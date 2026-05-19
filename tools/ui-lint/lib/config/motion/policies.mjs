//
// tools/ui-lint/lib/config/motion/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const BASE_MOTION_RESET_CSS = `
  *, *::before, *::after {
    animation: none !important;
    transition: none !important;
    scroll-behavior: auto !important;
    caret-color: transparent !important;
  }
`;

const LEAFLET_MOTION_RESET_CSS = `
  .leaflet-pane,
  .leaflet-control-container {
    animation: none !important;
    transition: none !important;
  }
`;

const CHARTS_MOTION_RESET_CSS = `
  .chart,
  .apexcharts-canvas,
  canvas {
    animation: none !important;
    transition: none !important;
  }
`;

const PULSE_MARKERS_MOTION_RESET_CSS = `
  .pulse-marker,
  #peer-map img,
  #peer-map canvas {
    animation: none !important;
    transition: none !important;
  }
`;

export const MOTION_POLICY = Object.freeze({
    resetCss: BASE_MOTION_RESET_CSS,
    appSpecificRules: Object.freeze({
        leaflet: LEAFLET_MOTION_RESET_CSS,
        charts: CHARTS_MOTION_RESET_CSS,
        pulseMarkers: PULSE_MARKERS_MOTION_RESET_CSS,
    }),
});

export function buildMotionResetCSS({ disableLeaflet = false, disableCharts = false, disablePulseMarkers = false } = {}) {
    const parts = [BASE_MOTION_RESET_CSS.trim()];

    if (disableLeaflet) {
        parts.push(LEAFLET_MOTION_RESET_CSS.trim());
    }
    if (disableCharts) {
        parts.push(CHARTS_MOTION_RESET_CSS.trim());
    }
    if (disablePulseMarkers) {
        parts.push(PULSE_MARKERS_MOTION_RESET_CSS.trim());
    }

    return parts.join('\n\n');
}

export const MOTION_RESET_CSS = BASE_MOTION_RESET_CSS;
export const APP_SPECIFIC_MOTION_RESET_CSS = [
    LEAFLET_MOTION_RESET_CSS.trim(),
    CHARTS_MOTION_RESET_CSS.trim(),
    PULSE_MARKERS_MOTION_RESET_CSS.trim(),
].join('\n\n');
export const FULL_MOTION_RESET_CSS = buildMotionResetCSS({
    disableLeaflet: true,
    disableCharts: true,
    disablePulseMarkers: true,
});

export const TRANSITION_POLICY = Object.freeze({
    defaultMaxMs: 200,
    slowMaxMs: 300,
    fastMaxMs: 150,
});