# Changelog

## [0.5.2](https://github.com/shigechika/cloudarmor-mcp/compare/v0.5.1...v0.5.2) (2026-09-25)


### Bug Fixes

* **client:** deny-export fails on the real API; pace entries.list by actual pages ([#28](https://github.com/shigechika/cloudarmor-mcp/issues/28)) ([77dc16a](https://github.com/shigechika/cloudarmor-mcp/commit/77dc16a36bd6856b2407e6bd67fb01de3731b0d9))

## [0.5.1](https://github.com/shigechika/cloudarmor-mcp/compare/v0.5.0...v0.5.1) (2026-09-24)


### Bug Fixes

* **client:** pace deny-export page fetches under the entries.list quota ([#26](https://github.com/shigechika/cloudarmor-mcp/issues/26)) ([9115206](https://github.com/shigechika/cloudarmor-mcp/commit/911520635e781cc4368fd6fa3abb0cf8ded69575))

## [0.5.0](https://github.com/shigechika/cloudarmor-mcp/compare/v0.4.0...v0.5.0) (2026-09-23)


### Features

* **cli:** add deny-export subcommand for one-day per-entry DENY JSON ([#24](https://github.com/shigechika/cloudarmor-mcp/issues/24)) ([07423a9](https://github.com/shigechika/cloudarmor-mcp/commit/07423a91daa96101a9978f9fceb62247d8e05e1d))

## [0.4.0](https://github.com/shigechika/cloudarmor-mcp/compare/v0.3.1...v0.4.0) (2026-08-15)


### Features

* package the server as a Claude Code plugin ([#19](https://github.com/shigechika/cloudarmor-mcp/issues/19)) ([f995f0c](https://github.com/shigechika/cloudarmor-mcp/commit/f995f0c2dbc89f057e8dd284589807aad85bec0c))

## [0.3.1](https://github.com/shigechika/cloudarmor-mcp/compare/v0.3.0...v0.3.1) (2026-08-11)


### Bug Fixes

* add explicit workflow permissions to ci.yml and release.yml ([#14](https://github.com/shigechika/cloudarmor-mcp/issues/14)) ([4fed0c2](https://github.com/shigechika/cloudarmor-mcp/commit/4fed0c2849928f11189115359614aab6d92b975e))

## [0.3.0](https://github.com/shigechika/cloudarmor-mcp/compare/v0.2.0...v0.3.0) (2026-08-08)


### Features

* add pr-gate.yml admission control caller ([#12](https://github.com/shigechika/cloudarmor-mcp/issues/12)) ([2dd3dd6](https://github.com/shigechika/cloudarmor-mcp/commit/2dd3dd631e83e8067d33fbd83ca2fb26c65cfc1b))

## [0.2.0](https://github.com/shigechika/cloudarmor-mcp/compare/v0.1.2...v0.2.0) (2026-08-06)


### Features

* add live smoke test (scripts/smoke_test.py) for the fleet smoke runner ([#8](https://github.com/shigechika/cloudarmor-mcp/issues/8)) ([dd52ffe](https://github.com/shigechika/cloudarmor-mcp/commit/dd52ffe87c989724b1511624e4c7a9d793e44122))

## [0.1.2](https://github.com/shigechika/cloudarmor-mcp/compare/v0.1.1...v0.1.2) (2026-08-06)


### Bug Fixes

* add mcp-name marker to README for MCP Registry ownership validation ([#6](https://github.com/shigechika/cloudarmor-mcp/issues/6)) ([ad596fc](https://github.com/shigechika/cloudarmor-mcp/commit/ad596fc15218d4cf8d63a4c0d43918754328892d))

## [0.1.1](https://github.com/shigechika/cloudarmor-mcp/compare/v0.1.0...v0.1.1) (2026-08-06)


### Bug Fixes

* shorten server.json description to satisfy MCP Registry limit ([#4](https://github.com/shigechika/cloudarmor-mcp/issues/4)) ([fb70b9c](https://github.com/shigechika/cloudarmor-mcp/commit/fb70b9c4088483504cc73718393d43b12c53fc55))

## 0.1.0 (2026-08-06)


### Features

* initial cloudarmor-mcp — Google Cloud Armor WAF log patrol MCP server ([e129495](https://github.com/shigechika/cloudarmor-mcp/commit/e129495a805c9baf7ceb1f88446d1a359c35c447))


### Bug Fixes

* **deps:** ignore mcp major version updates in Dependabot ([#2](https://github.com/shigechika/cloudarmor-mcp/issues/2)) ([e7b58dc](https://github.com/shigechika/cloudarmor-mcp/commit/e7b58dcfb138fdcecbc5797831296d3619cdcb18))
