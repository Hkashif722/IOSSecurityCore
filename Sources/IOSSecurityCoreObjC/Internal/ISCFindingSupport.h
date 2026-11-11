//
//  ISCFindingSupport.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  How the detectors create findings.
//

#import <Foundation/Foundation.h>
#import "ISCVisibility.h"
#import "ISCFinding.h"

NS_ASSUME_NONNULL_BEGIN


/// A finding with `code` and `detail`, filled in by a plain C function rather than by `-initWithCode:detail:`.
/// A swizzled initializer would otherwise let a tweak drop or rewrite every finding the package makes,
/// including the one that reports the swizzle.
ISC_HIDDEN ISCFinding *ISCMakeFinding(ISCFindingCode code, NSString *_Nullable detail);

NS_ASSUME_NONNULL_END
