//
//  ISCSecurityScanner.h
//  IOSSecurityCoreObjC
//
//  Runs every enabled detector and aggregates the result.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// The one object most hosts need: run the detectors selected in `ISCScanOptions` and get one result.
///
/// On the Simulator, on macOS and under Mac Catalyst the scan is skipped and the result contains a
/// single informational finding, unless `scansUnsupportedEnvironments` is set.
///
/// Typical Objective-C use:
///
///     ISCSecurityScanner *scanner = [[ISCSecurityScanner alloc] initWithOptions:ISCScanOptions.defaultOptions];
///     [scanner scanOnQueue:dispatch_get_global_queue(QOS_CLASS_UTILITY, 0)
///               completion:^(ISCScanResult *result) {
///         if (result.isCompromised) { /* react */ }
///     }];
ISC_RN_SECURITY_SCANNER
@interface ISCSecurityScanner : NSObject

/// A snapshot of the options this scanner was created with.
@property (nonatomic, copy, readonly) ISCScanOptions *options;

- (instancetype)initWithOptions:(ISCScanOptions *)options NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

/// Runs the scan on the calling thread and blocks until it finishes. Typically a few milliseconds,
/// plus up to ~150 ms per loopback port probe (three by default) when a port is filtered.
/// **Never call this on the main thread.**
- (ISCScanResult *)scan;

/// Runs the scan on `queue` and calls `completion` there. Returns immediately.
- (void)scanOnQueue:(dispatch_queue_t)queue
         completion:(void (^)(ISCScanResult *result))completion;

@end

NS_ASSUME_NONNULL_END
