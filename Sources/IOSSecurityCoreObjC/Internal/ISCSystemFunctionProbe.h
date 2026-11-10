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
#import "ISCFinding.h"

NS_ASSUME_NONNULL_BEGIN

/// Findings for the libc, dyld, Mach and Objective-C runtime functions the detectors rely on that were
/// rebound to code outside the OS (`ISCFindingCodeHookReboundSymbol`) or inline-patched to branch there
/// (`ISCFindingCodeHookInlinePatchedFunction`). `extraTrustedPrefixes` are host-trusted image locations.
NSArray<ISCFinding *> *ISCSystemFunctionFindings(NSArray<NSString *> *extraTrustedPrefixes);

NS_ASSUME_NONNULL_END
