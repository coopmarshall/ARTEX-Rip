---
name: mobile-security
description: "Invoke this skill when the task is authorized security testing of an Android (.apk) or iOS (.ipa) application: static analysis of the app package (manifest/entitlements, hardcoded secrets, insecure storage), reverse engineering obfuscated or packed code, dynamic instrumentation (Frida) of a running app, and the mobile-specific issues an API-focused skill would miss — insecure local storage, certificate-pinning bypass, IPC/deep-link abuse, and WebView bridge exposure."
---

# Mobile Security Testing (Android / iOS)

Under an **authorized** engagement, assess a mobile application's own
attack surface — the installed package and the device-side runtime — as
distinct from the backend API it talks to (that is api-recon/api-security's
job; use this skill for what only exists because the code runs on the user's
device). The standing finding quality gates and the adversarial gate in your
system prompt apply throughout: a permission or string found in static
analysis is a lead until a dynamic observation confirms it is reachable and
actually behaves as suspected.

Attribution: original to this repository, written for ARTEX's existing
verified-findings pipeline (`poe_level`, `verification_status`,
`verification_note`) and the same boundary conventions as the other new
skills added this session (secrets-hunting, exploit-intel, cloud-recon,
container-k8s).

## Boundaries and authorization

| Allowed | Prohibited |
|---|---|
| Static/dynamic analysis of an app binary you were given or legitimately installed for the engagement | Testing an app pulled from a device you do not have authorization to test, or belonging to a real third-party user |
| Instrumenting your own test device/emulator and your own test account | Modifying or redistributing the vendor's app binary beyond the engagement's test copies |
| Bypassing client-side controls (root/jailbreak detection, certificate pinning) to reach and test the API underneath | Treating a client-side bypass itself as the finding — root detection existing or not existing is a design choice, not a vulnerability, unless it is the *only* control standing between a user and a real impact |
| Reading obfuscated/packed code to understand behavior | Redistributing or reusing proprietary obfuscated code outside the engagement |

A client-side control (pinning, root detection, jailbreak detection) is
depth-in-defense, not the security boundary; report its absence as a
hardening note, not a standalone finding, unless bypassing it is the step
that reaches an otherwise-unreachable server-side bug — in which case the
finding is the server-side bug, with the bypass as the access method.

## Phase 1: static analysis

Android (`.apk`):

- [ ] unpack: `apktool d app.apk` (resources + smali) and `jadx app.apk` (Java-like decompile, better for logic reading).
- [ ] `AndroidManifest.xml`: exported `Activity`/`Service`/`BroadcastReceiver`/`ContentProvider` with no permission guard (IPC attack surface), `android:debuggable="true"`, overly broad `<uses-permission>`.
- [ ] hardcoded secrets in resources/strings/smali: API keys, embedded private keys, hardcoded backend URLs with credentials — reuse secrets-hunting's regex set.
- [ ] `network_security_config.xml`: `trust-anchors` accepting user/system CAs in release builds (MITM-friendly by design), cleartext traffic permitted.
- [ ] insecure storage: `SharedPreferences` with `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` (deprecated but still seen), unencrypted SQLite databases under `/data/data/<pkg>/databases/`, secrets written to external storage.
- [ ] WebView configuration: `setJavaScriptEnabled(true)` combined with `addJavascriptInterface` exposing a native bridge to any loaded page, `setAllowFileAccess(true)` combined with JS enabled (local file read via a malicious page).

iOS (`.ipa`):

- [ ] unpack: `.ipa` is a zip; `Payload/*.app/Info.plist` for `NSAppTransportSecurity` exceptions (`NSAllowsArbitraryLoads`), URL scheme / Universal Link declarations.
- [ ] entitlements (`codesign -d --entitlements :- app`): keychain access groups, associated domains, background modes broader than the app needs.
- [ ] binary strings/symbols (`strings`, `nm`, or `class-dump`/`Hopper`/`Ghidra` for Objective-C/Swift metadata) for hardcoded secrets and internal endpoint names.
- [ ] insecure storage: files written outside the Keychain with `NSFileProtectionNone`, plist files holding tokens/credentials in plaintext.

Both platforms:

- [ ] dependency/SDK inventory (third-party SDKs bundled, their known-vulnerable versions) — hand off to exploit-intel once a name/version is in hand.
- [ ] deep link / custom URL scheme handlers: can an untrusted page or another app trigger a sensitive action (auth, payment, account change) via a crafted link with no additional confirmation?

## Phase 2: dynamic analysis

- [ ] **Certificate-pinning bypass**: Frida (`frida-trace`, or a published universal-unpinning script reviewed before use) or Objection, on a rooted/jailbroken test device or emulator, to route traffic through an intercepting proxy and test the API underneath exactly like a web target.
- [ ] **Root/jailbreak detection bypass**: only as a means to continue testing, not as the finding itself (see Boundaries).
- [ ] **Runtime instrumentation**: hook sensitive methods (crypto, auth checks, license/entitlement checks) to observe actual values and control flow rather than inferring them from static analysis alone.
- [ ] **IPC fuzzing (Android)**: `am start`/`am broadcast`/content-provider queries against exported components with crafted intents, from a second app or adb, to probe for logic bypasses or injection (`ContentProvider` SQL injection via unsensitized query parameters is still common).
- [ ] **Clipboard and inter-app data leakage**: sensitive data (tokens, OTPs) copied to the system clipboard or shared via `Intent`/`UIActivityViewController` without scoping.

## Phase 3: verification before reporting

- [ ] a hardcoded-secret finding needs the actual extracted value's type and scope confirmed live (tie into secrets-hunting Phase 4) — a string that merely matches a key-shaped regex is a lead.
- [ ] an exported-component finding needs a reproduced IPC call demonstrating the bypass or logic flaw, not just "the component has no permission attribute".
- [ ] a pinning-bypass-enabled API finding is really an API finding — apply api-security's verification bar to whatever was reached, not to the bypass itself.
- [ ] record `poe_level`/`verification_status` per the existing finding workflow; `counterevidence` when a control-flow path you suspected turns out to be dead code or behind a feature flag the build you tested does not exercise.

## Tools

| Tool | Use | Notes |
|---|---|---|
| `apktool`, `jadx` | Android unpack/decompile | always verify availability before promising a full decompile |
| `class-dump`, `Hopper`/`Ghidra` | iOS binary/Objective-C metadata | `rea` (this platform's read-only binary-inspection MCP) can answer structure/strings/symbol questions without executing the binary |
| Frida, Objection | dynamic instrumentation, pinning bypass | needs a rooted/jailbroken device or emulator; verify the environment before promising dynamic testing |
| `adb` | Android IPC testing, log access, file pull from a test device | always available where an Android test device/emulator exists |
| an intercepting proxy (this platform's traffic capture) | inspecting unpinned traffic once bypass is in place | reuse the existing traffic store rather than a separate tool |

## Completion self-check

- [ ] every finding is backed by a concrete artifact (decompiled snippet, Frida hook output, captured request) in the work dir, not an assumption from the manifest alone
- [ ] no proprietary binary or decompiled source left the engagement's own storage
- [ ] a client-side-only control's absence was reported as hardening guidance, not inflated into a standalone finding, unless it gated access to a real server-side bug
- [ ] dynamic testing used only your own test device/emulator and test account
