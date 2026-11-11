//
//  ISCSystemFunctionProbe.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Verifies the OS functions the detectors call before their answers are trusted.
//

#import <Foundation/Foundation.h>
#import "ISCVisibility.h"
#import "ISCCodeTrust.h"
#import "ISCFinding.h"

NS_ASSUME_NONNULL_BEGIN


/// Findings for the libc, dyld, Mach and Objective-C runtime functions the detectors rely on that were
/// rebound to code outside the OS (`ISCFindingCodeHookReboundSymbol`) or inline-patched to branch there
/// (`ISCFindingCodeHookInlinePatchedFunction`). `trust` says which images count as legitimate destinations.
ISC_HIDDEN NSArray<ISCFinding *> *ISCSystemFunctionFindings(const ISCCodeTrust *trust);

NS_ASSUME_NONNULL_END
