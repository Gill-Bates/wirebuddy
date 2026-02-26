## [1.2.0] - 2026-02-26

- ``New`` Introducing MFA to provide an additional layer of access restriction
- ``New`` Easylist has been replaced by the significantly more comprehensive HaGeZi Pro
- ``New`` Update Dependencies (``fastapi``)
- ``New`` A new status page now allows you to check the configuration on the client side
- ``New`` You can now define your own filter rules for each client
- ``Fix`` The ``bleach`` package has been replaced by ``nh3``
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly
- ``Fix`` The creation of new peers also automatically created a new PSK
- ``Fix`` The blocklists are no longer downloaded again each time the container is restarted

<details markdown="1">
<summary>Previous versions...</summary>

## [1.1.1] - 2026-02-24

- ``New`` When Wirebuddy is running in bridge mode, an alternative port can be defined for the Wireguard configuration
- ``Fix`` Several design improvements to make the front end more mobile-friendly

## [1.1.0] - 2026-02-23

- ``New`` Switching from HTTP authentication to cookie authentication
- ``New`` You can now add your own allow and block lists to the DNS
- ``New`` DNS logs can now be deleted
- ``Fix`` Several design improvements to make the front end more mobile-friendly

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


