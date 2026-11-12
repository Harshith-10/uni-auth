# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - 2026-11-12

### Features
- feat(xtask): explicitly push active branch name and tags to remote on release
- feat: rename workspace crates to uni-auth-* and setup auto-versioning release automation
- feat: decouple plugins, wire axum endpoint hooks, and harden security
- feat: overhaul rust client with better-fetch transport and plugins
- feat: extract admin operations into decoupled AdminPlugin with full RBAC parity
- feat: extract bearer and one-time-token into standalone plugins
- feat: implement server plugin ecosystem and database hook pipeline
- feat: modernize desktop gpui and web clients with dialogs and ui parity
- feat: migrate web-react example to shadcn ui and admin plugin
- feat: seed demo accounts and refactor gpui example to default theme
- feat: implement admin plugin across workspace crates
- feat: setup OAuth2 providers across server, web, and desktop examples
- feat: implement scrypt compatibility, loopback timeout, auth plugins, and expanded tests
- feat: implement sliding session refresh, security middleware, and auth lifecycle hooks
- feat: implement live OAuth2/PKCE exchange and user account management endpoints
- feat: implement core hardening, strict token signatures, and wire parity
- feat: implement BetterAuth-compatible Rust workspace and GPUI desktop

### Bug Fixes
- fix(xtask): handle --help and -h flags in release subcommand
- fix: resolve change-email verification, mount csrf middleware, and harden proxy validation
- fix: correct session transport detection and timestamp formatting
- fix: establish wire parity and resolve security vulnerabilities
- fix: harden oauth callback security and upstream crypto parity

### Other Changes
- docs(readme): add installation guide and finalize uni-auth-* crate references
- refactor: remove branding across workspace and add project readme
- ﻿feat: implement remaining review findings, parity endpoints, and ergonomics
- ﻿fix: resolve audit findings, harden auth flows, and improve interop
- chore: bump rust-version to 1.99.1 and update workspace dependencies
- refactor: consolidate core domain logic, SQL query builder, and error handling

