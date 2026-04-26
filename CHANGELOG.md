## [1.4.5] - 2026-04-26

- ``Fix`` Various improvements to the GUI and fixes for display errors
- ``Fix`` Peers connected via a node did not display traffic details in the statistics
- ``Fix`` After restarting the Docker container, the Speedtest results from the last run were gone
- ``Fix`` Numerous stability improvements in the Wirebuddy engine
- ``Fix`` Update Python dependencies


<details markdown="1">
<summary>Previous versions...</summary>

## [1.4.4] - 2026-04-20

- ``New`` SVG flags removed from the Docker image and replaced with CDN Load
- ``New`` "Recent Peer Activity" now only shows peers who have been active in the last 30 days
- ``Fix`` 🔥 A bug in the passkey validation process allowed users to log in even if their passkey had been deleted
- ``Fix`` When a token is regenerated for a node, the associated peer is left orphaned
- ``Fix`` Front-end performance improvements
- ``Fix`` Update Python dependencies

## [1.4.3] - 2026-04-10

- ``Fix`` 🔥 Node re-enrollment loop when state file was lost (certificate-based recovery)
- ``Fix`` Traffic analysis queries now cached for 30s (faster page loads)
- ``Fix`` Peer names now support apostrophes (e.g., "John's iPhone")
- ``Fix`` API validation consistency improved for peer updates
- ``Fix`` Reduced unnecessary warnings in logs during normal operation
- ``Fix`` Various stability improvements in the Wirebuddy engine

## [1.4.2] - 2026-04-10

- ``New`` Update multiple Python dependencies
- ``Fix`` Metrics from the nodes were not reliably transmitted to the master 
- ``Fix`` No Speedtest results for the master were displayed on the dashboard
- ``Fix`` Various stability improvements in the Wirebuddy engine

## [1.4.1] - 2026-04-02

- ``New`` Switching the speed test to ``librespeed-cli`` for more reliable results [↗](https://gill-bates.github.io/wirebuddy/features/speedtest/)
- ``New`` Speed tests are now also conducted regularly on nodes with real-time progress updates [↗](https://gill-bates.github.io/wirebuddy/features/speedtest/)
- ``New`` Time range filters added to DNS trend chart (7d, 30d, 90d, 180d, 1y) [↗](https://gill-bates.github.io/wirebuddy/features/dns/#time-range-filter)
- ``New`` Dashboard speedtest chart now shows upload/download for all nodes with time range selection [↗](https://gill-bates.github.io/wirebuddy/features/speedtest/#viewing-history)
- ``New`` DNS metrics are now also available via TSDB for faster display in the GUI
- ``Fix`` When a ``docker stop`` command is executed, the SQLite database is now closed correctly
- ``Fix`` Dashboard node counter displayed 0 even when nodes existed
- ``Fix`` DNS query logs not displayed correctly on mobile devices
- ``Fix`` Restarting a node triggered a 503 error
- ``Fix`` 🔥 Nodes deleted themselves when master was unavailable
- ``Fix`` Improved security against host header injection attacks
- ``Fix`` General stability improvements in WireBuddy engine
- ``Fix`` DNS module: Improved thread-safety and performance
- ``Fix`` Better error handling during application shutdown
- ``Fix`` Optimized retry logic to prevent load spikes

## [1.4.0] - 2026-03-30

- ``New`` Node mode is here! 🎉 WIrebuddy can now run on multiple instances at the same time! [↗](https://gill-bates.github.io/wirebuddy/features/multi-node/)
- ``New`` DNS logging can be enabled or disabled for each peer [↗](https://gill-bates.github.io/wirebuddy/features/dns/#per-peer-dns-query-logging)
- ``New`` Added the ``tzdata`` package to support time zones [↗](https://gill-bates.github.io/wirebuddy/configuration/environment/#tz)
- ``New`` PSK is now enabled by default [↗](https://gill-bates.github.io/wirebuddy/configuration/wireguard/#preshared-keys)
- ``Fix`` Python dependencies updated
- ``Fix`` Fixed an issue with the test server selection for the speed test
- ``Fix`` Improved caching behavior for graphs
- ``Fix`` Several design improvements in the GUI

## [1.3.3] - 2026-03-23

- ``New`` The dashboard now also displays the network load for each interface [↗](https://gill-bates.github.io/wirebuddy/features/monitoring/#dashboard-overview)
- ``Fix`` Design optimized for iPad display
- ``Fix`` The DNS ad blocker could be launched even if Unbound wasn't installed
- ``Fix`` The changes to the downstream and upstream values were not saved
- ``Fix`` In some cases, the peer name was not displayed in the DNS logs
- ``Fix`` If a DNS blocklist has been disabled, the filter has not been updated
- ``Fix`` Several design improvements in the GUI

## [1.3.2] - 2026-03-16

- ``New`` A documentary is now available online: https://gill-bates.github.io/wirebuddy/ [↗](https://gill-bates.github.io/wirebuddy/)
- ``New`` Search filter for peers
- ``New`` Connection animation on the status page [↗](https://gill-bates.github.io/wirebuddy/configuration/status-page/#connection-flow)
- ``Fix`` Hardening the TDSB Engine for Handling Compressed Files
- ``Fix`` Improved stability in the Unbound Watchdog process
- ``Fix`` Improved stability in the speed test engine
- ``Fix`` Sessions expired after 1 hour, despite user interaction
- ``Fix`` A validation routine in the DNS Leak Indicator produced incorrect results
- ``Fix`` Several design improvements

## [1.3.1] - 2026-03-13

- ``New`` New ``health`` endpoint for a Docker health check [↗](https://gill-bates.github.io/wirebuddy/getting-started/docker/#health-checks)
- ``New`` Added speed test to monitor server performance [↗](https://gill-bates.github.io/wirebuddy/features/speedtest/)
- ``Fix`` An incorrectly entered password did not generate an error message
- ``Fix`` The charts for traffic metrics provided some contradictory information
- ``Fix`` When logged in, several error messages appeared in the GUI under Settings
- ``Fix`` A timeout occurred while saving DNS custom rules
- ``Fix`` Security hardening in the MFA routine & Credential handling
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.3.0] - 2026-03-07

- ``New`` Introducing Passkey for Users to Signin [↗](https://gill-bates.github.io/wirebuddy/security/passkeys/)
- ``New`` A global quick filter for peers has been introduced under DNS
- ``New`` The Swagger endpoint can now be disabled in the settings [↗](https://gill-bates.github.io/wirebuddy/configuration/environment/#swagger_enabled)
- ``Fix`` Security hardening of settings endpoints
- ``Fix`` The adaptive calculation of measurement points optimizes
- ``Fix`` Fixed display issues on tablets
- ``Fix`` The retention policy for DNS logs did not apply correctly
- ``Fix`` Fixed a bug that caused Unbound to crash on startup

## [1.2.2] - 2026-03-05

- ``New`` The ad blocker can now be temporarily disabled on a time-based basis [↗](https://gill-bates.github.io/wirebuddy/features/dns/)
- ``New`` Added a ``/swagger`` endpoint [↗](https://gill-bates.github.io/wirebuddy/api/overview/)
- ``New`` Metrics can now be saved and deleted in a more differentiated manner
- ``New`` Traffic statistics are now also grouped by ASN [↗](https://gill-bates.github.io/wirebuddy/features/geoip/#traffic-by-asn)
- ``New`` Users without admin rights can log in with read-only rights [↗](https://gill-bates.github.io/wirebuddy/features/users/#read-only-users)
- ``Fix`` The logs now show the real IP addresses and not those from the reverse proxy
- ``Fix`` Various stability improvements in the backend and GUI
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.2.1] - 2026-03-02

- ``New`` Passwords for users now require a minimum level of complexity [↗](https://gill-bates.github.io/wirebuddy/security/authentication/#password-requirements)
- ``New`` The DNS ad blocker can now be enabled and disabled globally [↗](https://gill-bates.github.io/wirebuddy/features/dns/)
- ``New`` A new "Traffic" section now bundles all network activities in an overview [↗](https://gill-bates.github.io/wirebuddy/features/monitoring/#traffic-analytics)
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

- ``New`` Introducing MFA to provide an additional layer of access restriction [↗](https://gill-bates.github.io/wirebuddy/security/authentication/#multi-factor-authentication-mfa)
- ``New`` Easylist has been replaced by the significantly more comprehensive HaGeZi Pro [↗](https://gill-bates.github.io/wirebuddy/features/dns/#blocklists)
- ``New`` Update Dependencies (``fastapi``)
- ``New`` A new status page now allows you to check the configuration on the client side [↗](https://gill-bates.github.io/wirebuddy/configuration/status-page/)
- ``New`` You can now define your own filter rules for each client [↗](https://gill-bates.github.io/wirebuddy/features/dns/#per-client-rules)
- ``Fix`` The ``bleach`` package has been replaced by ``nh3``
- ``Fix`` The creation of new peers also automatically created a new PSK
- ``Fix`` The blocklists are no longer downloaded again each time the container is restarted
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.1.1] - 2026-02-24

- ``New`` When Wirebuddy is running in bridge mode, an alternative port can be defined for the Wireguard configuration
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.1.0] - 2026-02-23

- ``New`` Switching from HTTP authentication to cookie authentication [↗](https://gill-bates.github.io/wirebuddy/security/authentication/#session-management)
- ``New`` You can now add your own allow and block lists to the DNS [↗](https://gill-bates.github.io/wirebuddy/features/dns/#custom-rules)
- ``New`` DNS logs can now be deleted [↗](https://gill-bates.github.io/wirebuddy/configuration/dns/#query-logging)
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.0.2] - 2026-02-22

- ``New`` Update Dependencies (``fastapi``)
- ``Fix`` Changing the password had no effect
- ``Fix`` Unbound crashed unexpectedly when the blocklist was updated
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.0.1] - 2026-02-20

- ``New`` Internal DNS serve (Unbound) is now dual-stack capable
- ``New`` Custom DNS upstream servers added by the user are now checked before saving [↗](https://gill-bates.github.io/wirebuddy/features/dns/#validate-servers)
- ``Fix`` The pie charts under DNS displayed incorrect values due to a race condition
- ``Fix`` In the front end, each block list was displayed with the same size (7 MB)
- ``Fix`` Various security hardening measures (e.g. brute force, IP spoofing)
- ``Fix`` And as always: Several design improvements to make the front end more mobile-friendly

## [1.0.0] - 2026-02-19
- Project initialization


