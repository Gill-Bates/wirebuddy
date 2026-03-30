import {
    ABOUT_MOBILE_STACK_GAP_VARIANCE_TOLERANCE_PX,
    CLICK_TARGET_MIN_SIZE_PX,
    DASHBOARD_TRANSFER_COLOR_DISTANCE_MIN,
    KPI_CARD_PADDING_EXPECTED,
    KPI_CARD_PADDING_TOLERANCE,
    KPI_CARD_REQUIRED_SCOPES,
    KPI_HEIGHT_TOLERANCE_PX,
    KPI_ICON_CENTER_TOLERANCE_PX,
    KPI_ICON_MAX,
    KPI_ICON_MIN,
    KPI_ICON_NEUTRAL_COLOR_DISTANCE_MAX,
    KPI_ROW_VARIANCE_MAX,
    LAYOUT_SHIFT_THRESHOLD,
    SETTINGS_TAB_COLOR_DISTANCE_MAX,
    VISUAL_DRIFT_THRESHOLD,
    VERTICAL_GAP_MAX,
    VERTICAL_GAP_MIN,
} from './constants.mjs';

export function summarizeFindings(result) {
    const hardFindings = [];
    const warnings = [];
    const pushHard = (value) => hardFindings.push(value);
    const pushWarning = (value) => warnings.push(value);

    if (result.metrics.duplicateIds.length) pushHard(`duplicateIds=${result.metrics.duplicateIds.length}`);
    if (result.metrics.emptyAriaLabels.length) pushWarning(`emptyAriaLabels=${result.metrics.emptyAriaLabels.length}`);
    if (result.metrics.unlabeledControls.length) pushHard(`unlabeledControls=${result.metrics.unlabeledControls.length}`);
    if (result.metrics.namelessButtons.length) pushHard(`namelessButtons=${result.metrics.namelessButtons.length}`);
    if (result.metrics.headingSkips.length) pushWarning(`headingSkips=${result.metrics.headingSkips.length}`);
    if (result.metrics.tablesWithoutHeaders.length) pushWarning(`tablesWithoutHeaders=${result.metrics.tablesWithoutHeaders.length}`);
    if (result.metrics.tableCellOverlapIssues?.length) pushHard(`tableCellOverlaps=${result.metrics.tableCellOverlapIssues.length}`);
    if (result.metrics.tablesWithoutResponsive?.length) pushWarning(`tablesWithoutResponsive=${result.metrics.tablesWithoutResponsive.length}`);
    if (result.metrics.ghostScroll) pushWarning('ghostScrollDetected');
    if (result.metrics.ghostScrollContainers?.length) pushWarning(`ghostScrollContainers=${result.metrics.ghostScrollContainers.length}`);
    if (result.metrics.horizontalOverflow.hasOverflow) pushHard('horizontalOverflow');
    if (result.metrics.horizontalOverflow.hasOverflow && result.metrics.horizontalOverflow.offenders.length) {
        pushHard(`overflowOffenders=${result.metrics.horizontalOverflow.offenders.length}`);
    }
    if (result.metrics.clippedButtons.length) pushWarning(`clippedButtons=${result.metrics.clippedButtons.length}`);
    if (result.metrics.clickTargetsTooSmall?.length) pushHard(`clickTargetsTooSmall=${result.metrics.clickTargetsTooSmall.length}`);
    if (result.metrics.iconButtonsTouchBlocked?.length) pushHard(`iconButtonsTouchBlocked=${result.metrics.iconButtonsTouchBlocked.length}`);
    if (result.metrics.deprecatedButtonClasses?.length) pushHard(`deprecatedButtonClasses=${result.metrics.deprecatedButtonClasses.length}`);
    if (result.metrics.hiddenInteractiveElements.length) pushHard(`hiddenInteractive=${result.metrics.hiddenInteractiveElements.length}`);
    if (result.metrics.bootstrapGridIssues?.length) pushWarning(`bootstrapGridIssues=${result.metrics.bootstrapGridIssues.length}`);
    if (result.metrics.bootstrapColumnsOutsideRows?.length) pushWarning(`bootstrapColumnsOutsideRows=${result.metrics.bootstrapColumnsOutsideRows.length}`);
    if (result.metrics.breakpointDisplayConflicts?.length) pushWarning(`breakpointDisplayConflicts=${result.metrics.breakpointDisplayConflicts.length}`);
    if (result.metrics.navbarCollapseIssues?.length) pushWarning(`navbarCollapseIssues=${result.metrics.navbarCollapseIssues.length}`);
    if (result.metrics.focusOrderIssues?.length) pushWarning(`focusOrderIssues=${result.metrics.focusOrderIssues.length}`);
    if (result.metrics.focusIndicatorMissing?.length) pushWarning(`focusIndicatorMissing=${result.metrics.focusIndicatorMissing.length}`);
    if (result.metrics.scrollEdgeCrowding?.length) pushWarning(`scrollEdgeCrowding=${result.metrics.scrollEdgeCrowding.length}`);
    if (result.metrics.scrollBottomCrowding?.length) pushWarning(`scrollBottomCrowding=${result.metrics.scrollBottomCrowding.length}`);
    if (result.metrics.nestedScrollContainers?.length) pushWarning(`nestedScrollContainers=${result.metrics.nestedScrollContainers.length}`);
    if (result.metrics.badgeStyleMismatches?.length) pushWarning(`badgeStyleMismatches=${result.metrics.badgeStyleMismatches.length}`);
    if (result.metrics.monospaceToneMismatches?.length) pushWarning(`monospaceToneMismatches=${result.metrics.monospaceToneMismatches.length}`);
    if (result.metrics.cardContainment.cardsPastFooter.length) pushWarning(`cardsPastFooter=${result.metrics.cardContainment.cardsPastFooter.length}`);
    if (result.metrics.modalBackdrop) {
        if (!result.metrics.modalBackdrop.blurMatchesReference) {
            pushWarning(`modalBackdropBlur=${result.metrics.modalBackdrop.blurPx ?? 'missing'}`);
        }
        if (!result.metrics.modalBackdrop.saturateMatchesReference) {
            pushWarning(`modalBackdropSaturate=${result.metrics.modalBackdrop.saturate ?? 'missing'}`);
        }
        if (!result.metrics.modalBackdrop.alphaMatchesReference) {
            pushWarning(`modalBackdropAlpha=${result.metrics.modalBackdrop.alpha ?? 'missing'}`);
        }
    }
    if (result.metrics.spacing.rowToRowGap !== undefined && !result.metrics.spacing.rowToRowGapInRange) {
        pushWarning(`rowToRowGapOutOfRange=${result.metrics.spacing.rowToRowGap}`);
    }
    if (result.name.includes('dns') && result.metrics.spacing.dnsLogScrollLayout) {
        const dnsLogLayout = result.metrics.spacing.dnsLogScrollLayout;
        if (!dnsLogLayout.bodyMinHeightAllowsShrink) pushHard('dnsLogBodyMinHeightNotZero');
        if (!dnsLogLayout.wrapMinHeightAllowsShrink) pushHard('dnsLogWrapMinHeightNotZero');
        if (!dnsLogLayout.wrapScrollsInternally) pushHard('dnsLogWrapNotScrollable');
        if (!dnsLogLayout.bodyActsAsFlexChild) pushWarning('dnsLogBodyNotFlexing');
        if (!dnsLogLayout.wrapActsAsFlexChild) pushWarning('dnsLogWrapNotFlexing');
        if (!dnsLogLayout.bodyClipsOverflow) pushWarning('dnsLogBodyOverflowVisible');
        if (!dnsLogLayout.wrapFitsBody) pushWarning('dnsLogWrapExceedsBody');
    }
    if (result.metrics.spacing.outlierVerticalGaps?.length) pushWarning(`outlierVerticalGaps=${result.metrics.spacing.outlierVerticalGaps.length}`);
    if (result.metrics.spacing.rowGutterMarginConflicts?.length) pushWarning(`rowGutterMarginConflicts=${result.metrics.spacing.rowGutterMarginConflicts.length}`);
    if (result.name.includes('mobile-') && result.metrics.spacing.mobileRowCardStackGaps?.length) {
        const inconsistentRows = result.metrics.spacing.mobileRowCardStackGaps.filter((entry) => !entry.gapsConsistent);
        if (inconsistentRows.length) {
            pushWarning(`mobileRowCardStackGapVariance=${inconsistentRows.length}`);
        }
    }
    if (result.name.includes('settings') && result.metrics.spacing.settingsTabColors?.length) {
        const tabColorProblems = result.metrics.spacing.settingsTabColors.filter(
            (entry) => entry.colorDelta != null && entry.colorDelta > SETTINGS_TAB_COLOR_DISTANCE_MAX
        );
        if (tabColorProblems.length) {
            pushWarning(`settingsTabActiveColorMismatch=${tabColorProblems.length}`);
        }
    }
    if (result.name.includes('dashboard') && result.metrics.spacing.dashboardTopRowAlignment && !result.metrics.spacing.dashboardTopRowAlignment.aligned) {
        pushWarning(`dashboardTopRowVariance=${result.metrics.spacing.dashboardTopRowAlignment.variance}`);
    }
    if (result.name.includes('mobile-dashboard') && result.metrics.spacing.dashboardMobileStackOrder) {
        const order = result.metrics.spacing.dashboardMobileStackOrder;
        if (!order.speedtestAboveMap || !order.mapAboveRecent) {
            pushWarning('dashboardMobileStackOrder');
        }
    }
    if (result.name.includes('desktop-settings-logs') && result.metrics.spacing.logsDeleteLayout) {
        const logsDeleteLayout = result.metrics.spacing.logsDeleteLayout;
        if (
            logsDeleteLayout.deleteBlockCount !== logsDeleteLayout.cardCount ||
            logsDeleteLayout.deleteInnerCount !== logsDeleteLayout.cardCount ||
            logsDeleteLayout.hairlineCount !== logsDeleteLayout.cardCount
        ) {
            pushWarning(`logsDeleteStructureMismatch=${logsDeleteLayout.cardCount}`);
        }
        if (!logsDeleteLayout.hairlineAligned) {
            pushWarning(`logsDeleteHairlineVariance=${logsDeleteLayout.hairlineVariance}`);
        }
    }
    if (result.name.includes('settings-logs') && result.metrics.spacing.logsPathLayout?.length) {
        const pathStyleProblems = result.metrics.spacing.logsPathLayout.filter(
            (entry) => entry.whiteSpace !== 'nowrap' || entry.textOverflow !== 'ellipsis' || entry.overflowX !== 'hidden'
        );
        if (pathStyleProblems.length) {
            pushWarning(`logsPathStyleMismatch=${pathStyleProblems.length}`);
        }

        const wrappedPaths = result.metrics.spacing.logsPathLayout.filter((entry) => entry.wraps);
        if (wrappedPaths.length) {
            pushWarning(`logsPathWrapped=${wrappedPaths.length}`);
        }
    }
    if (result.name.includes('settings') && result.metrics.spacing.compactCardActionRows?.length) {
        const compactActionRowProblems = result.metrics.spacing.compactCardActionRows.filter(
            (entry) => !entry.isCompactMargin || !entry.isCompactPadding || !entry.isBorderless
        );
        if (compactActionRowProblems.length) {
            pushWarning(`compactCardActionRows=${compactActionRowProblems.length}`);
        }
    }
    if (result.name.includes('users') && result.metrics.spacing.usersActionButtons) {
        const usersActionButtons = result.metrics.spacing.usersActionButtons;
        if (usersActionButtons.missingClassCount) {
            pushHard(`usersActionButtonsMissingClass=${usersActionButtons.missingClassCount}`);
        }
        if (usersActionButtons.undersizedCount) {
            pushHard(`usersActionButtonsTooSmall=${usersActionButtons.undersizedCount}`);
        }
        if (usersActionButtons.alignmentMismatchCount) {
            pushWarning(`usersActionButtonsAlignment=${usersActionButtons.alignmentMismatchCount}`);
        }
        if (usersActionButtons.sizeMismatchCount) {
            pushWarning(`usersActionButtonsSizeMismatch=${usersActionButtons.sizeMismatchCount}`);
        }
        if (usersActionButtons.borderRadiusMismatchCount) {
            pushWarning(`usersActionButtonsRadiusMismatch=${usersActionButtons.borderRadiusMismatchCount}`);
        }
        if (usersActionButtons.missingIconMdCount) {
            pushWarning(`usersActionButtonsMissingIconMd=${usersActionButtons.missingIconMdCount}`);
        }
        if (usersActionButtons.iconPointerMismatchCount) {
            pushHard(`usersActionButtonsIconPointer=${usersActionButtons.iconPointerMismatchCount}`);
        }
    }
    if (result.metrics.spacing.about?.updateValueStyleMismatches?.length) pushWarning(`aboutUpdateValueStyleMismatches=${result.metrics.spacing.about.updateValueStyleMismatches.length}`);
    if (result.metrics.spacing.about?.missingDetailsRows?.length) {
        pushHard(`aboutDetailsMissing=${result.metrics.spacing.about.missingDetailsRows.join(',')}`);
    }
    if (result.metrics.spacing.about?.forbiddenDetailsRows?.length) {
        pushHard(`aboutDetailsForbidden=${result.metrics.spacing.about.forbiddenDetailsRows.join(',')}`);
    }
    if (result.metrics.spacing.about?.missingBoldUpdateLabels?.length) {
        pushHard(`aboutUpdateLabelsNotBold=${result.metrics.spacing.about.missingBoldUpdateLabels.join(',')}`);
    }
    if (result.metrics.spacing.about?.topRowLayout?.active) {
        const topRowLayout = result.metrics.spacing.about.topRowLayout;
        if (!topRowLayout.heightsMatch) {
            pushWarning(`aboutTopRowHeightMismatch=${topRowLayout.variance}px`);
        }
        if (!topRowLayout.compactCardsStayCompact) {
            pushWarning(`aboutCompactCardExpanded=${topRowLayout.compactCardCount}`);
        }
    }
    if (result.name.includes('mobile-about') && result.metrics.spacing.about?.mobileTopRowStack?.active) {
        const mobileTopRowStack = result.metrics.spacing.about.mobileTopRowStack;
        if (!mobileTopRowStack.gapsConsistent) {
            pushWarning(`aboutMobileStackGapVariance=${mobileTopRowStack.gapVariance}px`);
        }
    }
    if (result.metrics.spacing.peersDesktopStatusCell?.length) {
        const flexCells = result.metrics.spacing.peersDesktopStatusCell.filter((r) => !r.isTableCell);
        if (flexCells.length) {
            pushHard(`peersStatusCellNotTableCell=${flexCells.map((c) => c.statusDisplay).join('+')}`);
        }
        const overlapCells = result.metrics.spacing.peersDesktopStatusCell.filter((r) => r.overlapsActions);
        if (overlapCells.length) {
            pushHard(`peersStatusOverlapsActions=${overlapCells.length}rows`);
        }
    }
    if (result.metrics.spacing.peersMobileLayout?.length) {
        const mobileIssues = result.metrics.spacing.peersMobileLayout.filter(
            (r) => !r.connectionBadgeVisible || !r.enabledBadgeVisible || !r.lastSeenCellHidden || !r.statusAlignedWithName || !r.clientIpBelowVpn
        );
        if (mobileIssues.length) {
            const reasons = new Set();
            for (const issue of mobileIssues) {
                if (!issue.connectionBadgeVisible) reasons.add('connectionBadgeHidden');
                if (!issue.enabledBadgeVisible) reasons.add('enabledBadgeHidden');
                if (!issue.lastSeenCellHidden) reasons.add('lastSeenCellVisible');
                if (!issue.statusAlignedWithName) reasons.add('statusNotAlignedWithName');
                if (!issue.clientIpBelowVpn) reasons.add('clientIpNotBelowVpn');
            }
            pushHard(`peersMobileLayout=${[...reasons].join('+')}`);
        }
    }
    if (result.metrics.spacing.peersModalValidation) {
        const addModal = result.metrics.spacing.peersModalValidation.addPeerModal;
        if (addModal?.found && !addModal.valid) {
            if (!addModal.hasRequiredAttr) pushHard('peerNameInputMissingRequired');
            if (!addModal.hasRequiredMarker) pushWarning('peerNameLabelMissingRequiredMarker');
        }
        const editModal = result.metrics.spacing.peersModalValidation.editPeerModal;
        if (editModal?.found && !editModal.valid) {
            if (!editModal.hasRequiredAttr) pushHard('editPeerNameInputMissingRequired');
            if (!editModal.hasRequiredMarker) pushWarning('editPeerNameLabelMissingRequiredMarker');
        }
    }
    if (result.metrics.spacing.nodesMobileLayout?.length) {
        const mobileIssues = result.metrics.spacing.nodesMobileLayout.filter(
            (r) => !r.theadHidden || !r.isGridLayout || !r.portHidden || !r.versionHidden ||
                !r.peersHidden || !r.lastSeenHidden || !r.mobileMetaVisible ||
                !r.statusAlignedWithName || !r.fqdnBelowName
        );
        if (mobileIssues.length) {
            const reasons = new Set();
            for (const issue of mobileIssues) {
                if (!issue.theadHidden) reasons.add('theadVisible');
                if (!issue.isGridLayout) reasons.add('notGridLayout');
                if (!issue.portHidden) reasons.add('portVisible');
                if (!issue.versionHidden) reasons.add('versionVisible');
                if (!issue.peersHidden) reasons.add('peersVisible');
                if (!issue.lastSeenHidden) reasons.add('lastSeenVisible');
                if (!issue.mobileMetaVisible) reasons.add('mobileMetaHidden');
                if (!issue.statusAlignedWithName) reasons.add('statusNotAlignedWithName');
                if (!issue.fqdnBelowName) reasons.add('fqdnNotBelowName');
            }
            pushHard(`nodesMobileLayout=${[...reasons].join('+')}`);
        }
    }
    if (result.metrics.spacing.nodesDesktopLayout?.length) {
        const overlapRows = result.metrics.spacing.nodesDesktopLayout.filter((r) => r.overlapsActions);
        if (overlapRows.length) {
            pushHard(`nodesStatusOverlapsActions=${overlapRows.length}rows`);
        }
    }
    if (result.metrics.layoutShift.value > LAYOUT_SHIFT_THRESHOLD) pushHard(`layoutShift=${result.metrics.layoutShift.value.toFixed(4)}`);
    if (result.metrics.componentLayoutShift?.length) pushHard(`componentLayoutShift=${result.metrics.componentLayoutShift.length}`);
    if (result.metrics.contrastProblems.length) pushHard(`contrastProblems=${result.metrics.contrastProblems.length}`);
    if (result.metrics.visualContainmentIssues?.length) pushWarning(`visualContainmentIssues=${result.metrics.visualContainmentIssues.length}`);
    if (result.metrics.formSwitchMarginIssues?.length) pushWarning(`formSwitchMarginIssues=${result.metrics.formSwitchMarginIssues.length}`);
    if (result.metrics.formSwitchProportionIssues?.length) pushHard(`formSwitchProportionIssues=${result.metrics.formSwitchProportionIssues.length}`);
    if (result.metrics.formSwitchHeightIssues?.length) pushHard(`formSwitchHeightIssues=${result.metrics.formSwitchHeightIssues.length}`);
    if (result.metrics.inputGroupHeightIssues?.length) pushHard(`inputGroupHeightIssues=${result.metrics.inputGroupHeightIssues.length}`);
    if (result.diff.ratio > VISUAL_DRIFT_THRESHOLD) pushHard(`visualDrift=${result.diff.ratio.toFixed(4)}`);
    if (result.network.consoleEntries.length) pushHard(`console=${result.network.consoleEntries.length}`);
    if (result.network.pageErrors.length) pushHard(`pageErrors=${result.network.pageErrors.length}`);
    if (result.network.requestFailures.length) pushHard(`failedRequests=${result.network.requestFailures.length}`);
    if (result.network.badResponses.length) pushHard(`badResponses=${result.network.badResponses.length}`);
    if (result.diff.sizeMismatch) pushHard('screenshotSizeMismatch');

    const duplicateRequestMap = new Map();
    for (const entry of result.network.requests || []) {
        if (!entry?.url || entry.method !== 'GET') continue;
        duplicateRequestMap.set(entry.url, (duplicateRequestMap.get(entry.url) || 0) + 1);
    }
    result.network.duplicateRequests = Array.from(duplicateRequestMap.entries())
        .filter(([, count]) => count > 3)
        .map(([url, count]) => ({ url, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
    if (result.network.duplicateRequests.length) pushWarning(`duplicateRequests=${result.network.duplicateRequests.length}`);

    if (result.metrics.spacing.kpiCards?.length) {
        const paddingProblems = result.metrics.spacing.kpiCards.filter((card) =>
            Math.abs(card.paddingTop - KPI_CARD_PADDING_EXPECTED) > KPI_CARD_PADDING_TOLERANCE ||
            Math.abs(card.paddingBottom - KPI_CARD_PADDING_EXPECTED) > KPI_CARD_PADDING_TOLERANCE
        );

        if (paddingProblems.length) {
            pushWarning(`kpiPaddingMismatch=${paddingProblems.length}`);
        }

        const iconProblems = result.metrics.spacing.kpiCards.filter((card) =>
            card.iconSize &&
            (card.iconSize < KPI_ICON_MIN || card.iconSize > KPI_ICON_MAX)
        );

        if (iconProblems.length) {
            pushWarning(`kpiIconSizeMismatch=${iconProblems.length}`);
        }
    }

    if (result.name.includes('dashboard') && result.metrics.spacing.dashboardKpiIcons?.length) {
        const contextualColorProblems = result.metrics.spacing.dashboardKpiIcons.filter(
            (card) => card.contextualClasses?.length
        );
        if (contextualColorProblems.length) {
            pushWarning(`dashboardKpiContextualIconColor=${contextualColorProblems.length}`);
        }

        const neutralColorProblems = result.metrics.spacing.dashboardKpiIcons.filter(
            (card) => card.iconColorDelta != null && card.iconColorDelta > KPI_ICON_NEUTRAL_COLOR_DISTANCE_MAX
        );
        if (neutralColorProblems.length) {
            pushWarning(`dashboardKpiNeutralIconMismatch=${neutralColorProblems.length}`);
        }

        const verticalCenterProblems = result.metrics.spacing.dashboardKpiIcons.filter(
            (card) => card.iconCenterDelta != null && card.iconCenterDelta > KPI_ICON_CENTER_TOLERANCE_PX
        );
        if (verticalCenterProblems.length) {
            pushWarning(`dashboardKpiIconVerticalCenter=${verticalCenterProblems.length}`);
        }
    }

    if (result.name.includes('dashboard') && result.metrics.spacing.kpiCards?.length) {
        const widths = result.metrics.spacing.statCardWidths || [];
        if (widths.length > 1) {
            const variance = Math.max(...widths) - Math.min(...widths);
            if (variance > 8) {
                pushWarning(`kpiCardWidthVariance=${variance}`);
            }
        }
    }

    if (result.metrics.spacing.kpiHeights?.length) {
        const variance = result.metrics.spacing.kpiHeightVariance || 0;

        if (variance > KPI_ROW_VARIANCE_MAX) {
            pushWarning(`kpiHeightVariance=${variance}`);
        }

        const uneven = result.metrics.spacing.kpiHeights.filter(
            (h) => Math.abs(h - result.metrics.spacing.kpiHeights[0]) > KPI_HEIGHT_TOLERANCE_PX
        );

        if (uneven.length) {
            pushWarning(`kpiHeightMismatch=${uneven.length}`);
        }
    }

    if (!result.name.includes('mobile') && result.metrics.spacing.kpiHeights?.length >= 4) {
        const firstRow = result.metrics.spacing.kpiHeights.slice(0, 4);
        const variance = Math.max(...firstRow) - Math.min(...firstRow);

        if (variance > KPI_ROW_VARIANCE_MAX) {
            pushWarning(`kpiRowHeightVariance=${variance}`);
        }
    }

    if (
        KPI_CARD_REQUIRED_SCOPES.some((scope) => result.name.includes(scope)) &&
        result.metrics.spacing.cardsMissingKpiClass?.length
    ) {
        pushWarning(`cardsMissingKpiClass=${result.metrics.spacing.cardsMissingKpiClass.length}`);
    }

    if (result.metrics.spacing.cardBorderRadiusIssues?.length) {
        pushWarning(`cardBorderRadiusMismatch=${result.metrics.spacing.cardBorderRadiusIssues.length}`);
    }

    if (result.name.includes('dns') && result.metrics.spacing.dnsUnavailableStates?.length) {
        const states = result.metrics.spacing.dnsUnavailableStates;

        for (const state of states) {
            if (!state.hasSubText) {
                pushWarning(`dnsUnavailableNoSubtext:${state.id || 'unknown'}`);
                continue;
            }

            if (!state.hasSmallClass) {
                pushHard(`dnsUnavailableMissingSmallClass:${state.id || 'unknown'}`);
            }

            if (!state.marginCompensatesGap) {
                pushHard(`dnsUnavailableSpacingIncorrect:${state.id || 'unknown'} (gap=${state.gap}, marginTop=${state.marginTop})`);
            }

            if (!state.visualGapExpected) {
                pushWarning(`dnsUnavailableVisualGap:${state.id || 'unknown'} (${state.visualGap}px)`);
            }
        }
    }

    if (result.name.includes('settings-logs') && result.metrics.spacing.sliderAlignment?.length) {
        for (const slider of result.metrics.spacing.sliderAlignment) {
            if (!slider.tickCountMatch) {
                pushWarning(`sliderTickCount:${slider.sliderId}=${slider.tickCount}/${slider.expectedTickCount}`);
            }
            if (!slider.usesIndexVar) {
                pushWarning(`sliderMissingIndexVar:${slider.sliderId}`);
            }
            if (slider.tickMisaligned.length) {
                pushHard(`sliderTickMisaligned:${slider.sliderId}=${slider.tickMisaligned.length}`);
            }
            if (slider.labelMisaligned.length) {
                pushWarning(`sliderLabelMisaligned:${slider.sliderId}=${slider.labelMisaligned.length}`);
            }
            if (slider.labelOverlap.length) {
                pushHard(`sliderLabelOverlap:${slider.sliderId}=${slider.labelOverlap.length}`);
            }
        }
    }

    if (result.name.includes('status') && result.metrics.spacing.statusFlow) {
        const flow = result.metrics.spacing.statusFlow;

        if (!flow.hasWrapper) {
            pushHard('statusFlowWrapperMissing');
        }
        if (!flow.nodeCountMatch) {
            pushHard(`statusFlowNodeCount=${flow.nodeCount}/${flow.expectedNodeCount}`);
        }
        if (!flow.connectorCountMatch) {
            pushHard(`statusFlowConnectorCount=${flow.connectorCount}/${flow.expectedConnectorCount}`);
        }
        if (!flow.nodeOrderMatches) {
            pushHard('statusFlowNodeOrderMismatch');
        }
        if (!flow.connectorOrderMatches) {
            pushHard('statusFlowConnectorOrderMismatch');
        }
        if (!flow.allNodesHaveStructure) {
            const incomplete = flow.nodes.filter((n) => !n.hasIcon || !n.hasLabel || !n.hasMeta);
            pushWarning(`statusFlowIncompleteNodes=${incomplete.length}`);
        }
        if (flow.labelMismatches.length) {
            pushHard(`statusFlowLabelMismatch=${flow.labelMismatches.length}`);
        }
        if (flow.iconMismatches.length) {
            pushHard(`statusFlowIconMismatch=${flow.iconMismatches.length}`);
        }
        if (flow.nodeStateConflicts.length) {
            pushHard(`statusFlowStateConflict=${flow.nodeStateConflicts.length}`);
        }
        if (flow.nodeContentStateMismatches.length) {
            pushHard(`statusFlowContentStateMismatch=${flow.nodeContentStateMismatches.length}`);
        }
        if (flow.heightVariance > flow.expectedHeightVarianceMax) {
            pushWarning(`statusFlowHeightVariance=${flow.heightVariance}/${flow.expectedHeightVarianceMax}`);
        }
        if (flow.widthVariance > 24) {
            pushWarning(`statusFlowWidthVariance=${flow.widthVariance}`);
        }
        if (flow.orientationIssues.length) {
            pushHard(`statusFlowOrientation=${flow.orientationIssues.length}`);
        }
        if (flow.connectorOrientationIssues.length) {
            pushHard(`statusFlowConnectorOrientation=${flow.connectorOrientationIssues.length}`);
        }
        if (flow.compactMobileLayout) {
            if (flow.compactMobileIssues.nodes.length) {
                pushWarning(`statusFlowCompactMobileNodes=${flow.compactMobileIssues.nodes.length}`);
            }
            if (flow.compactMobileIssues.connectors.length) {
                pushWarning(`statusFlowCompactMobileConnectors=${flow.compactMobileIssues.connectors.length}`);
            }
        }
    }

    if (result.name.includes('status') && result.metrics.spacing.statusCheckMonospace) {
        const checkMonospace = result.metrics.spacing.statusCheckMonospace;

        if (!checkMonospace.allCorrect) {
            const missingTitles = checkMonospace.missing.map((c) => c.title).join(', ');
            pushHard(`statusCheckMonospaceMissing: ${missingTitles}`);
        }
    }
    if (result.name.includes('status') && result.metrics.spacing.statusDetailCards) {
        const detailCards = result.metrics.spacing.statusDetailCards;
        if (!detailCards.allPopulated) {
            const emptyTitles = detailCards.empty.map((card) => card.title).join(', ');
            pushHard(`statusDetailCardsEmpty=${emptyTitles}`);
        }
    }

    if (result.name.includes('login-error')) {
        const loginFailure = result.metrics.loginFailure || {};
        const errorText = loginFailure.errorText || '';
        const isRateLimited = errorText.toLowerCase().includes('too many') || errorText.toLowerCase().includes('try again later');
        if (isRateLimited) {
            pushWarning('rateLimited');
        } else {
            const alertPresent = loginFailure.alertVisible || errorText.length > 0;
            if (!alertPresent) pushHard('loginErrorAlertMissing');
            if (!loginFailure.passwordInvalidClass) pushHard('loginPasswordNotInvalid');
            if (!loginFailure.passwordAriaInvalid) pushHard('loginPasswordAriaInvalidMissing');
            if (!loginFailure.passwordBorderIsDangerLike) pushWarning('loginPasswordNotDangerStyled');
            if (!loginFailure.cardShakeClass) pushWarning('loginCardShakeClassMissing');
        }
    }

    if (result.metrics.colorSchemeConsistency?.length) {
        for (const issue of result.metrics.colorSchemeConsistency) {
            if (issue.type === 'downloadColorMismatch') {
                pushWarning(`colorScheme:downloadMismatch:distance=${issue.distance}`);
            } else if (issue.type === 'uploadColorMismatch') {
                pushWarning(`colorScheme:uploadMismatch:distance=${issue.distance}`);
            } else if (issue.type === 'transferColorsTooSimilar') {
                pushWarning(`colorScheme:transferColorsTooSimilar:distance=${issue.distance}`);
            } else if (issue.type === 'missingGaugeElements') {
                pushWarning('colorScheme:missingElements');
            }
        }
    }

    if (result.metrics.deprecatedColorUsage?.length) {
        for (const issue of result.metrics.deprecatedColorUsage) {
            pushHard(`deprecatedColor:${issue.property}:${issue.selector}:${issue.value}`);
        }
    }

    return {
        findings: [...hardFindings, ...warnings],
        hardFindings,
        warnings,
    };
}

export function isExpectedStatusUnavailable(view, response) {
    if (view.scope !== 'status' || !response) return false;
    try {
        return new URL(response.url()).pathname === '/status' && response.status() === 404;
    } catch {
        return false;
    }
}
