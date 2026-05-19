//
// tools/ui-lint/lib/dom-runtime/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export { collectDOMSnapshot, querySnapshot, getByDataUi, getByClass, getByTag } from './snapshot/snapshot-engine.mjs';
export { buildLayoutSnapshot } from './snapshot/layout-snapshot.mjs';
export { buildRenderingSnapshot } from './snapshot/rendering-snapshot.mjs';
export { buildAccessibilitySnapshot } from './snapshot/accessibility-snapshot.mjs';
export { buildInteractionSnapshot } from './snapshot/interaction-snapshot.mjs';
export { buildCoordinateSpaces } from './geometry/coordinate-spaces.mjs';
export { parseTransforms, normalizeGeometry } from './geometry/transforms.mjs';
export { buildClippingSnapshot } from './geometry/clipping.mjs';
export { buildStackingContexts } from './geometry/stacking-contexts.mjs';
export { buildSemanticGroups } from './collections/semantic-groups.mjs';
export { buildScrollTopology } from './collections/scroll-topology.mjs';
export { buildOverlaySnapshot } from './collections/overlays.mjs';
export { detectVirtualizedUi } from './collections/virtualized-ui.mjs';
export { buildPaintOrder } from './rendering/paint-order.mjs';
export { buildCompositingSnapshot } from './rendering/compositing.mjs';
export { buildTypographySnapshot } from './rendering/typography.mjs';
export { buildColorSnapshot } from './rendering/colors.mjs';
export { buildMutationFingerprint } from './runtime/mutation-fingerprints.mjs';
export { buildIncrementalSnapshot } from './runtime/incremental-snapshots.mjs';
export { buildStableId } from './runtime/stable-ids.mjs';
export { serializeCompact, serializeVerbose } from './runtime/serialization.mjs';
export { buildCompactSchema } from './exports/compact-schema.mjs';
export { buildVerboseSchema } from './exports/verbose-schema.mjs';
export { diffSnapshots } from './exports/snapshot-diff.mjs';
