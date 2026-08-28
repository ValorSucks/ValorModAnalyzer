
# Valor Mod Analyzer

**Version:** 3.0 Enhanced
**Developed by:** DrValor
**Platform:** PowerShell (Windows)

---

## Overview

Valor Mod Analyzer is a multi-layered static and runtime-aware analysis tool designed to detect malicious, suspicious, and unauthorized Minecraft mods.

Unlike basic signature scanners, it prioritizes **execution capability detection, bytecode analysis, and environment-level manipulation**, enabling identification of advanced threats including injection loaders, obfuscated payloads, and external mod bypass techniques.

---

## Detection Architecture

The analyzer operates as a **layered detection pipeline**, ordered from hardest-to-bypass to simplest heuristic checks.

---

### 1. Bypass & Injection Detection (Runtime-Level Threats)

Identifies mods capable of executing code outside normal Minecraft constraints or bypassing client restrictions.

#### Capabilities Detected

* **Runtime.exec() usage**
  → Arbitrary OS command execution

* **HTTP Download Mechanisms**
  → Remote payload retrieval

* **HTTP POST / Exfiltration Patterns**
  → Data leakage to external servers

* **JavaAgent Injection (`-javaagent`)**
  → JVM-level code injection before game initialization

* **Fabric AddMods Argument (`-Dfabric.addMods`)**
  → Loading mods from external/unmonitored directories

* **JVM Argument Inspection**
  → Detection of suspicious runtime flags and launch modifications

#### Why This Matters

These represent **actual execution vectors**, not indicators.
If triggered, the mod has **direct capability to bypass or control runtime behavior**.

---

### 2. Bytecode Analysis & Obfuscation Detection

Performs static inspection of compiled Java classes to identify concealment techniques and malicious structure.

#### Obfuscation Heuristics

* ≥25% single-letter package paths (e.g., `a/b/c`)
* Excessive single-character class names (>15)
* Numeric-only class names (`1234.class`)
* Unicode / non-ASCII identifiers

#### Structural Anomalies

* Hollow wrapper mods (minimal outer layer + payload)
* Fake mod identity (spoofed mod metadata)
* Suspicious class distributions

#### Why This Matters

Targets **evasion techniques used by real cheat clients**, not surface-level indicators.

---

### 3. External Mod Loading Detection

Detects mods that bypass the standard `.minecraft/mods` directory.

#### Detection Vectors

* Fabric `-Dfabric.addMods` usage
* External directory loading
* Argument file (`argfile`) parsing
* Direct JAR path injection

#### Why This Matters

This is a **common anti-cheat bypass method**, allowing mods to remain invisible to standard scans.

---

### 4. Mod Integrity Verification

Validates mods against trusted public databases.

#### Verification Methods

* **SHA1 Hash Matching** (primary)
* **ModID & Version Lookup**
* **Filename Matching (fallback)**
* **File Size Validation**

#### Data Sources

* Modrinth API
* Megabase API (fallback)

#### Integrity Results

* **Verified** — exact match
* **Modified** — signature match but altered size
* **Tampered** — significant deviation
* **Unknown** — no match found

#### Why This Matters

Distinguishes **legitimate mods from altered or repackaged versions**.

---

### 5. Nested JAR Scanning

Recursively analyzes embedded archives within mods.

#### Capabilities

* Extraction of nested JAR contents
* Detection of multi-stage loaders
* Identification of hidden payloads
* Analysis of internal class structures and configs

#### Why This Matters

Advanced mods often **hide payloads inside secondary archives** to evade direct inspection.

---

### 6. File Attribute Manipulation Detection

Detects attempts to hide or protect mod files using filesystem tricks.

#### Attributes Checked

* Hidden (`+h`)
* System (`+s`)
* Read-only (`+r`)

#### Additional Checks

* Prefetch file anomalies
* Recursive attribute scanning across mod directories

#### Why This Matters

Indicates **stealth behavior**, often used alongside malicious mods.

---

### 7. Signature & Heuristic Pattern Detection

Fast detection layer using known cheat indicators.

#### Detection Categories

**Combat**

* AimAssist, KillAura, TriggerBot, AutoClicker, Criticals

**Movement**

* Velocity, Flight, Speed, NoFall, Timer, PingSpoof

**Visual**

* ESP, Wallhack, Freecam, Xray, FullBright

**Inventory / Utility**

* ChestSteal, AutoTotem, AutoEat, FastPlace, AutoMine

**Exploits**

* Reach, Hitboxes, SilentAim, SelfDestruct, AuthBypass

**Known Clients**

* Chainlibs signatures
* Dqrkis, Hadron, Prestige, Doomsday references

---

#### Deep String Extraction (Technique)

Uses `strings.exe` to extract embedded strings from compiled JARs.

Detects:

* Obfuscated fragments
* Hidden references
* URLs and endpoints
* Encoded payload indicators

#### Important Note

This layer is **fast but bypassable** through:

* String fragmentation
* Runtime construction
* Encryption/encoding

---

### 8. Disallowed Mods Detection (Policy Layer)

Flags mods commonly banned on servers.

#### Examples

* Xero’s Minimap
* Freecam
* Health Indicators
* Tweakeroo
* Item Scroller

#### Note

This is **policy-based**, not a security threat classification.

---

## Detection Output

### Console Output

* Real-time progress indicators
* Severity-based color coding
* Live detection summaries

---

### HTML Security Report

Generated on Desktop with structured analysis:

#### Executive Summary

* Total mods analyzed
* Verified / Unknown / Suspicious counts
* Tampered files
* Hidden files
* Injection detections
* Disallowed mods

#### Detailed Sections

1. Runtime / Injection Findings
2. External Mod Loading
3. JVM Argument Analysis
4. Attribute Manipulation
5. Verified Mods
6. Unknown Mods
7. Suspicious Patterns
8. Tampered Files
9. Disallowed Mods

---

## Technical Specifications

### Supported Loaders

* Fabric
* Forge / NeoForge

### Analysis Methods

* SHA1 hashing
* JAR/ZIP parsing
* `fabric.mod.json` extraction
* `mods.toml` parsing
* MANIFEST analysis
* Mixin detection
* Access widener inspection

---

## System Requirements

* Windows 10/11
* PowerShell 5.1+
* .NET Framework 4.7+
* Git for Windows (optional, for `strings.exe`)
* Internet (for verification APIs)

---

## Usage

```powershell
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process; Invoke-Expression (Invoke-RestMethod -UseBasicParsing 'https://raw.githubusercontent.com/ValorSucks/ValorModAnalyzer/main/ValorModAnalyzer.ps1')"

```

1. Run script
2. Enter mods folder path
3. Default:
   `%USERPROFILE%\AppData\Roaming\.minecraft\mods`
4. Review console output
5. Open HTML report (Desktop)

---

## Limitations

* Pattern detection can produce false positives
* Obfuscation may evade signature-based checks
* API rate limits affect verification speed
* Offline mode disables integrity validation
* Requires `strings.exe` for deep extraction layer

---

## Security Model

* Read-only analysis (no file modification)
* No file uploads
* Local report generation only
* Requires standard filesystem and process read access

---

## Disclaimer

This tool is intended for security analysis and educational use.

The developer is not responsible for:

* False positives or negatives
* Actions taken based on results
* Compatibility issues
* External API changes

Manual verification is recommended before enforcement decisions.

---

## Version History

### v3.0 Enhanced

* Added injection & runtime detection
* JavaAgent and Fabric AddMods analysis
* Bytecode obfuscation heuristics
* Nested JAR scanning
* HTML reporting overhaul
* Attribute manipulation detection

---

## Credits

**Development:** DrValor

**Special Thanks:**

* Hadron
* TonyNoh
* YarpLepstan

---
