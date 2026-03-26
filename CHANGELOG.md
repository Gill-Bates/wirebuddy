## [1.4.0] - 2026-03-xx

- ``New`` Multi-Node deployment architecture for deploying WireGuard servers across multiple geographic locations
- ``New`` Node management UI with enrollment token generation and status monitoring
- ``New`` Per-peer node assignment with automatic endpoint configuration
- ``New`` DNS logging can be enabled or disabled for each peer
- ``New`` Added the ``tzdata`` package to support time zones
- ``Fix`` Python dependencies updated
- ``Fix`` Fixed an issue with the test server selection for the speed test
- ``Fix`` Improved caching behavior for graphs
- ``Fix`` Several design improvements in the GUI


<details markdown="1">
<summary>Previous versions...</summary>

## [1.3.3] - 2026-03-23

- ``New`` The dashboard now also displays the network load for each interface
- ``Fix`` Design optimized for iPad display
- ``Fix`` The DNS ad blocker could be launched even if Unbound wasn't installed
- ``Fix`` The changes to the downstream and upstream values were not saved
- ``Fix`` In some cases, the peer name was not displayed in the DNS logs
- ``Fix`` If a DNS blocklist has been disabled, the filter has not been updated
- ``Fix`` Several design improvements in the GUI

## [1.3.2] - 2026-03-16

- ``New`` A documentary is now available online: https://gill-bates.github.io/wirebuddy/
- ``New`` Search filter for peers
- ``New`` Connection animation on the status page
- ``Fix`` Hardening the TDSB Engine for Handling Compressed Files
- ``Fix`` Improved stability in the Unbound Watchdog process
- ``Fix`` Improved stability in the speed test engine
- ``Fix`` Sessions expired after 1 hour, despite user interaction
- ``Fix`` A validation routine in the DNS Leak Indicator produced incorrect results
- ``Fix`` Several design improvements

## [1.3.1] - 2026-03-13

- ``New`` New ``health`` endpoint for a Docker health check
- ``New`` Added speed test to monitor server performance
- ``Fix`` An incorrectly entered password did not generate an error message
- ``Fix`` The charts for traffic metrics provided some contradictory information
- ``Fix`` When logged in, several error messages appeared in the GUI under Settings
- ``Fix`` A timeout occurred while saving DNS custom rules
- ``Fix`` Security hardening in the MFA routine & Credential handling
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.3.0] - 2026-03-07

- ``New`` Introducing Passkey for Users to Signin
- ``New`` A global quick filter for peers has been introduced under DNS
- ``New`` The Swagger endpoint can now be disabled in the settings
- ``Fix`` Security hardening of settings endpoints
- ``Fix`` The adaptive calculation of measurement points optimizes
- ``Fix`` Fixed display issues on tablets
- ``Fix`` The retention policy for DNS logs did not apply correctly
- ``Fix`` Fixed a bug that caused Unbound to crash on startup

## [1.2.2] - 2026-03-05

- ``New`` The ad blocker can now be temporarily disabled on a time-based basis
- ``New`` Added a ``/swagger`` endpoint
- ``New`` Metrics can now be saved and deleted in a more differentiated manner
- ``New`` Traffic statistics are now also grouped by ASN
- ``New`` Users without admin rights can log in with read-only rights
- ``Fix`` The logs now show the real IP addresses and not those from the reverse proxy
- ``Fix`` Various stability improvements in the backend and GUI
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.2.1] - 2026-03-02

- ``New`` Passwords for users now require a minimum level of complexity
- ``New`` The DNS ad blocker can now be enabled and disabled globally
- ``New`` A new "Traffic" section now bundles all network activities in an overview
- ``New`` Completely revised migration framework for the database
- ``Fix`` The /status page now reliably detects an existing Wireguard connection
- ``Fix`` Various stability improvements in the backend engine
- ``Fix`` Disabling OTP for a user had no effect
- ``Fix`` Due to a regex validation error, no new user could be created
- ``Fix`` The block lists did not update automatically every 24 hour
- ``Fix`` Creating another Wireguard interface used the same IP range
- ``Fix`` When a peer is deleted, the time series data is now also deleted
- ``Fix`` Application made more resilient when started with an incorrect encryption key
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.2.0] - 2026-02-26

- ``New`` Introducing MFA to provide an additional layer of access restriction
- ``New`` Easylist has been replaced by the significantly more comprehensive HaGeZi Pro
- ``New`` Update Dependencies (``fastapi``)
- ``New`` A new status page now allows you to check the configuration on the client side
- ``New`` You can now define your own filter rules for each client
- ``Fix`` The ``bleach`` package has been replaced by ``nh3``
- ``Fix`` The creation of new peers also automatically created a new PSK
- ``Fix`` The blocklists are no longer downloaded again each time the container is restarted
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.1.1] - 2026-02-24

- ``New`` When Wirebuddy is running in bridge mode, an alternative port can be defined for the Wireguard configuration
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.1.0] - 2026-02-23

- ``New`` Switching from HTTP authentication to cookie authentication
- ``New`` You can now add your own allow and block lists to the DNS
- ``New`` DNS logs can now be deleted
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.0.2] - 2026-02-22

- ``New`` Update Dependencies (``fastapi``)
- ``Fix`` Changing the password had no effect
- ``Fix`` Unbound crashed unexpectedly when the blocklist was updated
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.0.1] - 2026-02-20

- ``New`` Internal DNS serve (Unbound) is now dual-stack capable
- ``New`` Custom DNS upstream servers added by the user are now checked before saving
- ``Fix`` The pie charts under DNS displayed incorrect values due to a race condition
- ``Fix`` In the front end, each block list was displayed with the same size (7 MB)
- ``Fix`` Various security hardening measures (e.g. brute force, IP spoofing)
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.0.0] - 2026-02-19
- Project initialization


