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
#import "ISCVisibility.h"
#import <objc/runtime.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCTypes.h"

NS_ASSUME_NONNULL_BEGIN


/// A detector family's scan: the checks of that family enabled in `options`, and what they found. Each
/// one checks `options.checks` itself, so it returns nothing when its family is excluded.
///
/// The scanner calls these C functions, never the `+scanWithOptions:` methods that wrap them, so a
/// swizzled method cannot change what a scan finds.
typedef NSArray<ISCFinding *> *_Nonnull (*ISCDetectorScanFunction)(ISCScanOptions *options);

ISC_HIDDEN NSArray<ISCFinding *> *ISCJailbreakScan(ISCScanOptions *options);
ISC_HIDDEN NSArray<ISCFinding *> *ISCDebuggerScan(ISCScanOptions *options);
ISC_HIDDEN NSArray<ISCFinding *> *ISCHookingScan(ISCScanOptions *options);
ISC_HIDDEN NSArray<ISCFinding *> *ISCIntegrityScan(ISCScanOptions *options);
ISC_HIDDEN NSArray<ISCFinding *> *ISCNetworkScan(ISCScanOptions *options);

/// `YES` when `options.checks` includes `check`.
static inline BOOL ISCChecksInclude(ISCScanOptions *options, ISCChecks check) {
    return (options.checks & check) != 0;
}

// MARK: - Registry
//
// Defined in ISCDetectorRegistry.m, the one file that knows every detector and the scanner. Detectors
// depend on this header only, never on each other or on the scanner.

/// A detector family: its bit and its scan function. Both are data, so no method stands between the
/// scanner and the checks.
typedef struct {
    ISCChecks check;
    ISCDetectorScanFunction scan;
} ISCDetectorEntry;

/// Every detector the scanner runs, in scan order. `outCount` receives how many. The storage is static.
ISC_HIDDEN const ISCDetectorEntry *ISCDetectorEntries(size_t *outCount);

/// A method whose implementation must stay inside this package's image.
typedef struct {
    __unsafe_unretained Class cls;
    SEL selector;
    BOOL isClassMethod;
} ISCMethodTarget;

/// The methods the self-integrity check watches, as boxed `ISCMethodTarget` values: every public method,
/// since hosts and `IntegritySignals` call them directly, plus the getters a report is read through.
ISC_HIDDEN NSArray<NSValue *> *ISCSelfIntegrityTargets(void);

/// Calls `visit` with a readable name and the address of each C function a scan runs through: the scan
/// entry point, every detector, the probes and the finding factory. Self-integrity checks each for an
/// inline patch. The names are decoded on each call and only for this use.
ISC_HIDDEN void ISCForEachSelfIntegrityFunction(void (NS_NOESCAPE ^visit)(NSString *name, const void *function));

NS_ASSUME_NONNULL_END
