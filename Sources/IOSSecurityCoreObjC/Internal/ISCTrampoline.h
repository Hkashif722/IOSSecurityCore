//
//  ISCTrampoline.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Recognises the branch sequences inline-hooking frameworks write over the start of a function.
//

#import <Foundation/Foundation.h>
#import "ISCVisibility.h"
#include <stdbool.h>

NS_ASSUME_NONNULL_BEGIN


/// If the code at `function` begins with an absolute or long branch, stores its destination (with any
/// pointer-authentication signature removed) in `outTarget` and returns `true`.
///
/// Recognised, after at most one leading `bti` / `paciasp` / `pacibsp`:
/// - `b <label>`
/// - `ldr xN, <literal>` + `br xN`                   (Substrate, Frida, Dobby)
/// - `adrp xN, <page>` + `add xN, xN, #off` + `br xN` (Frida, ElleKit)
/// - `adrp xN, <page>` + `ldr xN, [xN, #off]` + `br xN`
/// - `movz xN` + up to three `movk xN` + `br xN`
///
/// `br` also matches the arm64e forms `braaz`, `brabz`, `braa` and `brab`.
///
/// A match is not proof of a hook: the OS has legitimate thunks too. The caller decides by looking at
/// where the branch lands. Memory is read with `vm_read_overwrite`, so an unmapped, unaligned or
/// garbage address returns `false` instead of crashing. Always `false` on architectures other than arm64.
ISC_HIDDEN bool ISCDecodeTrampoline(const void *_Nullable function, const void *_Nullable *_Nonnull outTarget);

NS_ASSUME_NONNULL_END
