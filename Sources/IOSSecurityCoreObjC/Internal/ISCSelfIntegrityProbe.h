//
//  ISCSelfIntegrityProbe.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Checks that this package's own code has not been hooked.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"

NS_ASSUME_NONNULL_BEGIN

/// One `ISCFindingCodeHookSelfIntegrity` finding when any of `ISCSelfIntegrityTargets()` is implemented
/// outside this package's image or starts with a branch out of it. Empty otherwise.
NSArray<ISCFinding *> *ISCSelfIntegrityFindings(void);

NS_ASSUME_NONNULL_END
