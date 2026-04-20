#!/usr/bin/env python3
#
# app/utils/onboarding.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Onboarding workflow configuration.

``ONBOARDING_STEPS`` is a sequence of step definitions consumed by the
``fragments/onboarding_modal.html`` template via the template context.

Decoupled from the presentation layer to enable:
- Unit testing without rendering templates
- Internationalization without template changes
- Dynamic step modification (e.g., skip if already completed)

Each step must conform to the ``OnboardingStep`` schema.

TypedDict provides static type checking only. Runtime schema validation is
performed by ``_validate_steps()`` below.
"""

from typing import TypedDict


class OnboardingStep(TypedDict):
    """Schema for a single onboarding step.
    
    Fields:
        title: Step heading (e.g., "Change Admin Password")
        body_pre: Text before the hyperlink (includes trailing space if needed)
        href: Absolute path to the target page (e.g., "/ui/users")
        link_label: Hyperlink text (e.g., "Users")
        body_post: Text after the hyperlink (includes leading space if needed)
        show_default_badge: Whether to display a "Default" badge below the step
    
    Note: body_pre and body_post include intentional surrounding spaces to form
    a complete sentence around the linked anchor element.
    
    Subpath Note: All hrefs assume the app is served from the domain root (/).
    If deployed under a subpath (e.g., "/wirebuddy/"), these must be updated
    or made configurable via environment or context processor.
    """
    title: str
    body_pre: str
    href: str
    link_label: str
    body_post: str
    show_default_badge: bool


ONBOARDING_STEPS: tuple[OnboardingStep, ...] = (
    {
        "title": "Change Admin Password",
        "body_pre": "Go to ",
        "href": "/ui/users",
        "link_label": "Users",
        "body_post": " and set a secure password for the admin account.",
        "show_default_badge": False,
    },
    {
        "title": "Create an Interface",
        "body_pre": "Under ",
        "href": "/ui/settings",
        "link_label": "Settings",
        "body_post": ", create your first WireGuard interface (e.g., wg0).",
        "show_default_badge": False,
    },
    {
        "title": "Set Your Server FQDN",
        "body_pre": "In ",
        "href": "/ui/settings",
        "link_label": "WireGuard",
        "body_post": " settings, enter your server's public hostname or domain.",
        "show_default_badge": False,
    },
    {
        "title": "Generate PresharedKey",
        "body_pre": "PSK is enabled by default. Generate a global key in ",
        "href": "/ui/settings",
        "link_label": "Settings",
        "body_post": " under WireGuard.",
        "show_default_badge": True,
    },
    {
        "title": "Add Your First Peer",
        "body_pre": "Go to ",
        "href": "/ui/peers",
        "link_label": "Peers",
        "body_post": " and create VPN clients for your devices.",
        "show_default_badge": False,
    },
)


def _validate_steps() -> None:
    """Fail fast if ONBOARDING_STEPS has missing or malformed fields."""
    required_keys = {
        "title",
        "body_pre",
        "href",
        "link_label",
        "body_post",
        "show_default_badge",
    }

    for idx, step in enumerate(ONBOARDING_STEPS):
        keys = set(step.keys())
        missing = required_keys - keys
        extra = keys - required_keys

        if missing:
            raise ValueError(f"ONBOARDING_STEPS[{idx}] missing keys: {sorted(missing)}")
        if extra:
            raise ValueError(f"ONBOARDING_STEPS[{idx}] has unknown keys: {sorted(extra)}")

        for text_key in ("title", "body_pre", "href", "link_label", "body_post"):
            if not isinstance(step[text_key], str):
                raise ValueError(
                    f"ONBOARDING_STEPS[{idx}]['{text_key}'] must be str, "
                    f"got {type(step[text_key]).__name__}"
                )
        if not isinstance(step["show_default_badge"], bool):
            raise ValueError(
                f"ONBOARDING_STEPS[{idx}]['show_default_badge'] must be bool, "
                f"got {type(step['show_default_badge']).__name__}"
            )


_validate_steps()
