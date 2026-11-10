//
//  ISCSecurityScanner.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCSecurityScanner.h"
#import "ISCDebuggerDetector.h"
#import "ISCDetector.h"
#import "ISCEnvironment.h"
#import "ISCHookDetector.h"
#import "ISCIntegrityChecker.h"
#import "ISCJailbreakDetector.h"
#import "ISCNetworkDetector.h"

#include <CoreFoundation/CoreFoundation.h>

NSArray<Class<ISCDetector>> *ISCDetectorClasses(void) {
    // Scan order. Jailbreak first because its findings give the later ones context; network last because
    // it is the weakest signal.
    return @[
        ISCJailbreakDetector.class,
        ISCDebuggerDetector.class,
        ISCHookDetector.class,
        ISCIntegrityChecker.class,
        ISCNetworkDetector.class,
    ];
}

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

    for (Class<ISCDetector> detector in ISCDetectorClasses()) {
        if (!ISCDetectorIsEnabled(detector, options)) {
            continue;
        }
        [findings addObjectsFromArray:[detector scanWithOptions:options]];
        performed |= [detector check];
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
