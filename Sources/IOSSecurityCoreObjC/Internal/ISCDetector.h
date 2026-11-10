//
//  ISCDetector.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  The contract every detector family implements, and the registry the scanner runs them from.
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
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

/// `YES` when `options.checks` includes `detector`'s family.
static inline BOOL ISCDetectorIsEnabled(Class<ISCDetector> detector, ISCScanOptions *options) {
    return (options.checks & [detector check]) != 0;
}

// MARK: - Registry
//
// Both functions are defined in ISCDetectorRegistry.m, the one file that knows every detector and the
// scanner. Detectors depend on this header only, never on each other or on the scanner.

/// Every detector the scanner runs, in scan order. Adding a family means adding it there and nowhere else.
NSArray<Class<ISCDetector>> *ISCDetectorClasses(void);

/// A method whose implementation must stay inside this package's image.
typedef struct {
    __unsafe_unretained Class cls;
    SEL selector;
    BOOL isClassMethod;
} ISCMethodTarget;

/// The methods the self-integrity check watches: every registered detector's entry point, the scanner's
/// `scan`, and the finding initializer. `outCount` receives how many. The storage is static.
const ISCMethodTarget *ISCSelfIntegrityTargets(size_t *outCount);

NS_ASSUME_NONNULL_END
