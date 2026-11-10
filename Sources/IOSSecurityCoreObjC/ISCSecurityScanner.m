//
//  ISCSecurityScanner.m
//  IOSSecurityCoreObjC
//

#import "ISCSecurityScanner.h"
#import "ISCDebuggerDetector.h"
#import "ISCEnvironment.h"
#import "ISCHookDetector.h"
#import "ISCIntegrityChecker.h"
#import "ISCJailbreakDetector.h"

#include <CoreFoundation/CoreFoundation.h>

/// Why a scan was skipped, as the single informational finding the result carries.
static ISCFindingCode ISCSkipReason(void) {
    if (ISCEnvironment.isSimulator) {
        return ISCFindingCodeSimulator;
    }
    if (ISCEnvironment.isMacCatalystApp || ISCEnvironment.isiOSAppOnMac) {
        return ISCFindingCodeMacRuntime;
    }
    return ISCFindingCodeUnsupportedPlatform;
}

@implementation ISCSecurityScanner

- (instancetype)initWithOptions:(ISCScanOptions *)options {
    self = [super init];
    if (self != nil) {
        // Snapshot: later mutation of the caller's object must not change a scan in flight.
        _options = [options copy];
    }
    return self;
}

- (ISCScanResult *)scan {
    NSDate *startedAt = [NSDate date];
    CFAbsoluteTime started = CFAbsoluteTimeGetCurrent();
    ISCScanOptions *options = self.options;

    if (!options.scansUnsupportedEnvironments && !ISCEnvironment.isSupportedDevicePlatform) {
        ISCFinding *reason = [[ISCFinding alloc] initWithCode:ISCSkipReason() detail:nil];
        return [[ISCScanResult alloc] initWithFindings:@[reason]
                                       performedChecks:0
                                             startedAt:startedAt
                                              duration:CFAbsoluteTimeGetCurrent() - started];
    }

    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    ISCChecks performed = 0;

    if (options.checks & ISCChecksJailbreak) {
        [findings addObjectsFromArray:[ISCJailbreakDetector scanWithOptions:options]];
        performed |= ISCChecksJailbreak;
    }
    if (options.checks & ISCChecksDebugger) {
        [findings addObjectsFromArray:[ISCDebuggerDetector scanWithOptions:options]];
        performed |= ISCChecksDebugger;
    }
    if (options.checks & ISCChecksHooking) {
        [findings addObjectsFromArray:[ISCHookDetector scanWithOptions:options]];
        performed |= ISCChecksHooking;
    }
    if (options.checks & ISCChecksIntegrity) {
        [findings addObjectsFromArray:[ISCIntegrityChecker scanWithOptions:options]];
        performed |= ISCChecksIntegrity;
    }

    // Most severe first; equal severities keep a stable order by code.
    [findings sortUsingComparator:^NSComparisonResult(ISCFinding *left, ISCFinding *right) {
        if (left.severity != right.severity) {
            return left.severity > right.severity ? NSOrderedAscending : NSOrderedDescending;
        }
        if (left.code != right.code) {
            return left.code < right.code ? NSOrderedAscending : NSOrderedDescending;
        }
        return NSOrderedSame;
    }];

    return [[ISCScanResult alloc] initWithFindings:findings
                                   performedChecks:performed
                                         startedAt:startedAt
                                          duration:CFAbsoluteTimeGetCurrent() - started];
}

- (void)scanOnQueue:(dispatch_queue_t)queue completion:(void (^)(ISCScanResult *))completion {
    dispatch_async(queue, ^{
        completion([self scan]);
    });
}

@end
