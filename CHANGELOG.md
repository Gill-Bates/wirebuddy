## [1.1.0] - 2026-02-23

- ``New`` Switching from HTTP authentication to cookie authentication
- ``New`` You can now add your own allow and block lists to the DNS
- ``New`` DNS logs can now be deleted
- ``Fix`` Several design improvements to make the front end more mobile-friendly


<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.2] - 2026-02-22

- ``New`` Update Dependencies (``fastapi``)
- ``Fix`` Changing the password had no effect
- ``Fix`` Unbound crashed unexpectedly when the blocklist was updated
- ``Fix`` Several Design improvements in the GUI

## [1.0.1] - 2026-02-20

- ``New`` Internal DNS serve (Unbound) is now dual-stack capable
- ``New`` Custom DNS upstream servers added by the user are now checked before saving
- ``Fix`` The pie charts under DNS displayed incorrect values due to a race condition
- ``Fix`` In the front end, each block list was displayed with the same size (7 MB)
- ``Fix`` Various security hardening measures (e.g. brute force, IP spoofing)
- ``Fix`` Several Design issues in the GUI

## [1.0.0] - 2026-02-19
- Project initialization


