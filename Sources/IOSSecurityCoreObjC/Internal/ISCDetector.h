//
//  ISCDetector.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  The contract every detector family implements, so the scanner can treat them uniformly.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCTypes.h"

NS_ASSUME_NONNULL_BEGIN

/// One detector family (jailbreak, debugger, ...). Detectors are stateless; every method is a class method.
///
/// `ISCSecurityScanner` runs the detectors in `ISCDetectorClasses()` and only those whose `check` bit is
/// set in `ISCScanOptions.checks`. A detector also applies that test itself, so calling it directly with
/// options that exclude its family returns no findings.
@protocol ISCDetector <NSObject>

/// The single `ISCChecks` bit this detector implements.
@property (class, nonatomic, readonly) ISCChecks check;

/// Runs the family's checks enabled in `options` and returns what they found.
+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options;

@end

/// Every detector the scanner runs, in scan order. Adding a family means adding it here and nowhere
/// else in the scanner.
NSArray<Class<ISCDetector>> *ISCDetectorClasses(void);

/// `YES` when `options.checks` includes `detector`'s family.
static inline BOOL ISCDetectorIsEnabled(Class<ISCDetector> detector, ISCScanOptions *options) {
    return (options.checks & [detector check]) != 0;
}

NS_ASSUME_NONNULL_END
