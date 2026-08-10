# suSSHi Gateway

This repository contains the **suSSHi Gateway** (`susshid`) and the optional **suSSHi Proxy** (`susshi-proxyd`) — the SSH gateway and proxy daemons of the suSSHi Suite.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL%203.0+-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Overview

suSSHi is an enterprise-grade SSH gateway suite that makes SSH access auditable, policy-driven and centrally managed across data center and cloud environments. It places a single, RFC-compliant entry point in front of your SSH infrastructure and adds centralized authentication, fine-grained access control, protocol inspection and full session recording — without requiring changes to SSH clients or target servers.

Because every connection passes through the gateway, firewall rules stay simple and target servers never need to be exposed to clients directly.

- **Centralized SSH gateway** — one point of access for SSH connections to many targets
- **Session management** — full session recording, live monitoring and replay
- **Authentication** — public key, agent forwarding, multi-factor and OIDC
- **Protocol inspection** — deep inspection of SSH, SCP, SFTP, X11 and TCP forwarding
- **Access control** — users, roles and access policies managed centrally
- **REST API** — full programmatic control over configuration and session context

## Components

The suSSHi Suite consists of the following components:

| Component | Role | Repository |
| --- | --- | --- |
| **suSSHi Gateway** (`susshid`) | The SSH gateway daemon. Central entry point between SSH clients and target servers, and the only component end users interact with. Ships with the `susshi-last`, `susshi-who` and `susshi-play` session utilities. | [susshi](https://github.com/wasabi-elements/susshi) |
| **suSSHi Chef** | Administration UI, REST API and policy decision point. Central user account, access and configuration management for the whole suite. | [susshi-chef](https://github.com/wasabi-elements/susshi-chef) |
| **suSSHi Database** | PostgreSQL database holding all configuration, accounts and access rules. Not shipped with suSSHi; can run in any redundancy setup. | — |
| **suSSHi Sous Chef** (optional) | Self-service portal that authenticates SSH users via OpenID Connect and lets them manage their own SSH public keys. | [susshi-sous-chef](https://github.com/wasabi-elements/susshi-sous-chef) |
| **suSSHi Proxy** (`susshi-proxyd`) (optional) | Proxy component installed at the edge of a protected environment, acting as a single point of contact for targets inside it. | [susshi](https://github.com/wasabi-elements/susshi) |

## Architecture

![Architecture](https://docs.susshi.io/_images/susshi_architecture.png)

## Documentation

The complete suSSHi manual — installation, configuration, administration and troubleshooting — is published **online only**:

**https://docs.susshi.io**

This repository deliberately keeps no separate documentation. The online manual is the single source of truth and always reflects the current release.

## Release Notes

There is no changelog in this repository. Release notes for all suSSHi components, including the recommended upgrade paths, are published online:

**https://docs.susshi.io/release_notes/index.html**

## Reporting Bugs & Security Issues

### Bugs and feature requests

Please open an issue in the repository of the affected component (see [Components](#components)). Include the component version, your deployment setup and, where possible, steps to reproduce.

### Security vulnerabilities

Please **do not** report security vulnerabilities through public issues.

Instead, send an e-mail to **security@susshi.io** with:

- A description of the vulnerability
- Steps to reproduce or a proof of concept
- Your assessment of the potential impact

We aim to acknowledge reports within two business days and will keep you informed while we work on a fix. We follow coordinated disclosure: once a fix is available we publish a security advisory and credit the reporter, unless they prefer to remain anonymous. Security fixes are applied to the latest release, so we recommend always running the most recent version.

## Enterprise Edition & Subscription

suSSHi Gateway, suSSHi Proxy, the suSSHi Chef core and suSSHi Sous Chef are fully open source under the AGPL-3.0-or-later — fully transparent, and complete enough to run standalone without a subscription.

Beyond that, suSSHi Chef can load a separate, **proprietary Enterprise Edition** — a Rails engine that is **not** part of these repositories and is **not** licensed under the AGPL.

The Enterprise Edition and commercial support are **not sold separately**: a single suSSHi subscription covers both. It is issued per installation, valid for a fixed term, and unlocks the licensed features along with the user and target limits it was signed for.

**But production environments require more than code.** A subscription includes:

- The Enterprise Edition with additional features like suSSHi Proxy, Audit log file encryption, dynamic OTP target authentication (DOTP) and target fusions.
- Priority e-mail support and issue handling
- Direct access to core maintainers
- Bug investigation and guidance
- Custom feature development
- Long-term stability and roadmap influence

If you use suSSHi commercially, a subscription also helps ensure its long-term sustainability. Open source gives you freedom. Our subscription gives you certainty.

**View our subscription plans**: https://susshi.io/pricing

## License

Copyright (C) 2026 Wasabi Elements GmbH

SPDX-License-Identifier: AGPL-3.0-or-later

This project is free software: you can redistribute it and/or modify it under the terms of the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.html) as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

As required by AGPL §13, if you run a modified version of this software as a network service, you must make the corresponding source available to users of that service.

**Source code**: https://github.com/wasabi-elements/susshi

## Trademarks

"suSSHi", "suSSHi Gateway", "suSSHi Proxy", "suSSHi Chef", "suSSHi Sous Chef" and the suSSHi logo are trademarks of Wasabi Elements GmbH. The AGPL license grants rights in the software's copyright only; it does **not** grant any right to use these names or logos. If you distribute a modified version, you must use a different name and remove the suSSHi branding to avoid confusion.
