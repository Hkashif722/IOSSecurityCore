#!/bin/bash
#
# build-phase-audit.sh
#
# A compile-time gate for the *host app*. It inspects the linked binary the way an auditor would —
# `strings`, `otool`, `nm`, without ever running the app — and fails the build when a name you declared
# off-limits is visible, or (advisory) when the Swift reflection/symbol-stripping settings did not take.
#
# This is the half a runtime library cannot do: class and selector names are written into __TEXT by the
# compiler before the app ever launches, so nothing IOSSecurityCore does at runtime can remove them. This
# script runs after linking, sees exactly what class-dump/strings would, and stops a leak from shipping.
#
# It does NOT rename anything. It is a gate, not an obfuscator: it tells you which sensitive names reached
# the binary so you can rename those few at the source, or accept them deliberately.
#
# ─── Xcode setup ──────────────────────────────────────────────────────────────────────────────────────
#   Target → Build Phases → + → New Run Script Phase, placed AFTER "Compile Sources" and
#   "Embed Frameworks". Point it at this script:
#
#       "${SRCROOT}/Scripts/build-phase-audit.sh"
#
#   Uncheck "Based on dependency analysis" so it runs every build. By default it audits Release only
#   (set AUDIT_CONFIGURATIONS to change that).
#
# ─── Denylist ─────────────────────────────────────────────────────────────────────────────────────────
#   App-specific names to forbid live in a file (one extended-regex per line, '#' comments). Resolution:
#     1. $SECURITY_AUDIT_DENYLIST, if set
#     2. $SRCROOT/security-audit.denylist
#     3. the directory of this script / security-audit.denylist
#   See security-audit.denylist.sample for the format. The built-in indicator list below always applies.
#
# ─── CLI / CI use ─────────────────────────────────────────────────────────────────────────────────────
#   Run it by hand against an exported binary (no Xcode env needed):
#       Scripts/build-phase-audit.sh path/to/MyApp.app/MyApp
#
# Exit: 0 clean · 1 forbidden name found · 2 usage/IO error.

set -euo pipefail

# ── Tool resolution (prefer the active toolchain's copies) ────────────────────────────────────────────
_tool() {
    if command -v xcrun >/dev/null 2>&1 && xcrun --find "$1" >/dev/null 2>&1; then
        xcrun --find "$1"
    else
        command -v "$1" || { echo "error: required tool not found: $1" >&2; exit 2; }
    fi
}
STRINGS="$(_tool strings)"
OTOOL="$(_tool otool)"
NM="$(_tool nm)"

# ── Built-in indicators: plain-text tells that should never reach a shipping binary ───────────────────
# These are the strings an attacker greps for to find (and neuter) your protection. Keep them out.
FORBIDDEN_INDICATORS='Cydia|Sileo|MobileSubstrate|FridaGadget|frida-server|SSLKillSwitch|libhooker|/var/jb|cycript|substitute'

# ── Resolve the binary to audit ───────────────────────────────────────────────────────────────────────
BINARY=""
if [ "$#" -gt 0 ]; then
    BINARY="$1"
elif [ -n "${CODESIGNING_FOLDER_PATH:-}" ] && [ -n "${EXECUTABLE_PATH:-}" ]; then
    # Inside Xcode: CODESIGNING_FOLDER_PATH is the .app, EXECUTABLE_NAME its main binary.
    BINARY="${CODESIGNING_FOLDER_PATH}/${EXECUTABLE_NAME:-}"
    [ -f "$BINARY" ] || BINARY="${TARGET_BUILD_DIR:-}/${EXECUTABLE_PATH}"
else
    echo "error: no binary given and no Xcode build environment detected" >&2
    echo "usage: $(basename "$0") [path/to/binary]" >&2
    exit 2
fi

if [ ! -f "$BINARY" ]; then
    echo "error: cannot read binary: $BINARY" >&2
    exit 2
fi

# ── Skip configurations we are not asked to gate (keeps day-to-day Debug builds fast) ─────────────────
AUDIT_CONFIGURATIONS="${AUDIT_CONFIGURATIONS:-Release}"
if [ -n "${CONFIGURATION:-}" ]; then
    case " $AUDIT_CONFIGURATIONS " in
        *" $CONFIGURATION "*) : ;;
        *) echo "note: build-phase-audit skipped for configuration '$CONFIGURATION'"; exit 0 ;;
    esac
fi

# ── Load the app-specific denylist ────────────────────────────────────────────────────────────────────
DENYLIST_FILE=""
for candidate in \
    "${SECURITY_AUDIT_DENYLIST:-}" \
    "${SRCROOT:-}/security-audit.denylist" \
    "$(cd "$(dirname "$0")" && pwd)/security-audit.denylist"
do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then DENYLIST_FILE="$candidate"; break; fi
done

APP_PATTERNS=""
if [ -n "$DENYLIST_FILE" ]; then
    # Strip comments and blank lines, join the rest into one alternation.
    APP_PATTERNS="$(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$DENYLIST_FILE" | grep -v '^[[:space:]]*$' | paste -sd '|' -)"
fi

PATTERN="$FORBIDDEN_INDICATORS"
[ -n "$APP_PATTERNS" ] && PATTERN="$PATTERN|$APP_PATTERNS"

echo "build-phase-audit: $BINARY"
[ -n "$DENYLIST_FILE" ] && echo "  denylist: $DENYLIST_FILE"

# ── The gate: any forbidden name visible to `strings` fails the build ─────────────────────────────────
status=0
HITS="$("$STRINGS" -a "$BINARY" | grep -E "$PATTERN" | sort -u || true)"
if [ -n "$HITS" ]; then
    # 'error:' makes Xcode surface each line in the Issue navigator and stop the build.
    echo "error: build-phase-audit found forbidden name(s) in the shipping binary:"
    echo "$HITS" | sed 's/^/error:     /'
    echo "error:   Rename these at the source, or remove them from the denylist if intended."
    status=1
fi

# ── Advisory: did the safe-layer settings take? (warnings only, never fails the build) ────────────────
# Swift field names live in __TEXT,__swift5_fieldmd. Present + non-trivial => reflection not stripped.
# otool -l prints a hex `size 0x...`; bash arithmetic reads the 0x form directly (no gawk strtonum).
if "$OTOOL" -l "$BINARY" 2>/dev/null | grep -q 'sectname __swift5_fieldmd'; then
    SIZE_HEX="$("$OTOOL" -l "$BINARY" 2>/dev/null \
        | awk '/sectname __swift5_fieldmd/{f=1} f&&$1=="size"{print $2;exit}')"
    FIELDMD_BYTES=0
    [ -n "${SIZE_HEX:-}" ] && { FIELDMD_BYTES=$(( SIZE_HEX )) 2>/dev/null || FIELDMD_BYTES=0; }
    if [ "${FIELDMD_BYTES:-0}" -gt 0 ]; then
        echo "warning: __swift5_fieldmd present (~${FIELDMD_BYTES} bytes of Swift field names). Set"
        echo "warning:   SWIFT_REFLECTION_METADATA_LEVEL = none to strip them (breaks Mirror; Codable is fine)."
    fi
fi

# A large symbol table in a release binary means stripping did not run.
SYMBOL_COUNT="$("$NM" "$BINARY" 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
if [ "${SYMBOL_COUNT:-0}" -gt 2000 ] 2>/dev/null; then
    echo "warning: $SYMBOL_COUNT symbols in the binary. For release, set DEPLOYMENT_POSTPROCESSING = YES,"
    echo "warning:   STRIP_INSTALLED_PRODUCT = YES, STRIP_STYLE = all, STRIP_SWIFT_SYMBOLS = YES."
fi

if [ "$status" -eq 0 ]; then
    echo "build-phase-audit: OK — no forbidden names in $(basename "$BINARY")"
fi
exit "$status"
