# Threat model and explicit boundaries

## Intended use

A developer knowingly routes a supported JSON chat request through an authenticated loopback process, which locally detects selected sensitive spans, applies policy, and forwards the transformed body to a preconfigured endpoint. This reduces some accidental disclosures; it does not establish confidentiality for every possible input.

## Trust assumptions

- The host, Python interpreter, runtime dependencies, model weights and configuration are trusted.
- The application actually uses this proxy. Direct API clients, plugins, telemetry, browsers, attachments in other channels and other processes can bypass it.
- Provider API credentials intentionally reach the configured provider in an authorization header. They are not part of text filtering; the client-facing local token must be distinct.
- Loopback is not an authentication boundary by itself. The local bearer token is required; compromised local users/processes remain outside the threat model.
- The detector is fallible. False negatives can leak data even though transport enforcement is working exactly as implemented.

## Enforced in the supported path

Strict request schema, supported-role/content validation, local authentication, explicit destination, no environment HTTP proxy, no redirects, bounded requests/responses, generic upstream errors, no raw HTTP access logs, detected-secret blocking, and no silent fallback when model inference fails.

Names, unlabelled addresses, indirect identifiers, uncommon phone formats, transliteration, steganography, encrypted/base64 values, deliberate secret obfuscation, links to external files, and attributes that identify someone in combination may escape detection. Pseudonymization preserves semantic/contextual information. An `allow` decision means no blocking detection under this policy; it is **not** a declaration that content is public or safe.

## Restoration

Placeholders are random per vault and consistent for identical values/categories within that vault. The proxy creates one vault per request and clears it after use. Vaults have capacity/TTL limits; cross-vault or malformed tokens fail strict restoration. Restoring visible assistant text is opt-in and local; no tool-argument restoration is supported. A malicious provider can echo or repeat valid placeholders, so the output is untrusted even when the values are restored. Revalidate any downstream action; never treat restored prose as authorization.

Restoration is a single bounded substitution pass. Clearing Python mappings does not securely zero memory. OS swap, core dumps, debugger inspection, shell history, the calling application's logs and provider-generated responses are not controlled.

## Receipts

Receipts intentionally omit text, values and content-derived hashes. Category/length metadata can still be sensitive. Local hash chains are not signatures. Full-chain rewriting or deletion cannot be detected without an independently trusted head; even an anchored chain is no proof of total egress coverage.

## Not shipped in v0.1

OS/network firewall enforcement; production multi-user hosting; streaming; tools or MCP interception; image/audio/PDF/OCR handling; general file upload; Anthropic or Responses API adapters; cross-request memory; automatic local model routing; regulatory compliance certification; independent security audit. No such capability is implied by the project name or roadmap.
