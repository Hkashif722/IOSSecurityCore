#!/bin/bash
#
# audit-symbols.sh
#
# Created by Kashif Hussain on 2026-11-10.
# Copyright © 2026 Kashif Hussain. MIT License.
#
# Verifies that the compiled package contains none of Apple's "required reason" APIs (so its privacy
# manifest can honestly declare nothing) and none of the plain-text indicators the obfuscation macros are
# meant to hide.
#
# Usage:  Scripts/audit-symbols.sh [object-or-binary ...]
# Default: builds the package for iOS (arm64, release) and audits the ObjC layer's object files.

set -euo pipefail

cd "$(dirname "$0")/.."

# Imported symbols that fall under Apple's required-reason API categories.
FORBIDDEN_SYMBOLS='_stat$|_lstat$|_fstat$|_fstatat$|_getattrlist$|_NSFileCreationDate|_NSFileModificationDate|_systemUptime|_mach_absolute_time|_NSUserDefaults|_statfs|_statvfs|_volumeAvailableCapacity|_activeInputModes'

# Plain-text indicators that must not be visible to `strings`.
FORBIDDEN_STRINGS='Cydia|Sileo|MobileSubstrate|frida|FridaGadget|SSLKillSwitch|libhooker|/var/jb|substitute|ShadowRuleset|ABypass|FlyJB|HTTPProxy|ProxyAutoConfig'

# Exported symbols that would name the checks: the package's own C functions and Objective-C classes.
EXPORTED_NAME_PATTERN='^_ISC[A-Z]|^_OBJC_(CLASS|METACLASS)_\$_ISC'

if [ "$#" -gt 0 ]; then
    FILES=("$@")
else
    DERIVED="$(mktemp -d)"
    trap 'rm -rf "$DERIVED"' EXIT
    xcodebuild build -scheme IOSSecurityCoreObjC -configuration Release \
        -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED" -quiet \
        CODE_SIGNING_ALLOWED=NO >/dev/null
    FILES=()
    while IFS= read -r object; do FILES+=("$object"); done < <(find "$DERIVED" -name '*.o' -path '*IOSSecurityCoreObjC*')
fi

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "error: nothing to audit" >&2
    exit 2
fi

status=0
for file in "${FILES[@]}"; do
    # An input that cannot be read must fail the audit, never pass it.
    if [ ! -f "$file" ]; then
        echo "error: cannot read $file" >&2
        exit 2
    fi
    if nm -u "$file" 2>/dev/null | grep -E "$FORBIDDEN_SYMBOLS" >/dev/null; then
        echo "FAIL  required-reason API imported by $file:"
        nm -u "$file" | grep -E "$FORBIDDEN_SYMBOLS" | sed 's/^/        /'
        status=1
    fi
    # Internal C functions have hidden visibility and public ones opaque names: nothing exported may name a check.
    # `private external` (hidden) symbols become local at link time and are stripped; only real exports count.
    exported="$(nm -mgU "$file" 2>/dev/null | grep -v 'private external' | awk '{print $NF}' | grep -E "$EXPORTED_NAME_PATTERN" || true)"
    if [ -n "$exported" ]; then
        echo "FAIL  readable exported symbol in $file:"
        echo "$exported" | sed 's/^/        /'
        status=1
    fi
    if strings -a "$file" | grep -E "$FORBIDDEN_STRINGS" >/dev/null; then
        echo "FAIL  plain-text indicator in $file:"
        strings -a "$file" | grep -E "$FORBIDDEN_STRINGS" | sed 's/^/        /'
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "OK    audited ${#FILES[@]} file(s): no required-reason APIs, no plain-text indicators"
fi
exit "$status"
