//
//  ISCSecurityScanner.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCSecurityScanner.h"
#import "ISCFindingSupport.h"
#import "ISCDetector.h"
#import "ISCPlatform.h"

#include <CoreFoundation/CoreFoundation.h>

/// Why a scan was skipped, as the single informational finding the result carries.
static ISCFindingCode ISCSkipReason(void) {
    if (ISCPlatformIsSimulator()) {
        return ISCFindingCodeSimulator;
    }
    if (ISCPlatformIsMacCatalyst() || ISCPlatformIsiOSAppOnMac()) {
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

ISCScanResult *ISCPerformScan(ISCScanOptions *options) {
    NSDate *startedAt = [NSDate date];
    CFAbsoluteTime started = CFAbsoluteTimeGetCurrent();

    if (!options.scansUnsupportedEnvironments && !ISCPlatformIsSupportedDevice()) {
        ISCFinding *reason = ISCMakeFinding(ISCSkipReason(), nil);
        return [[ISCScanResult alloc] initWithFindings:@[reason]
                                       performedChecks:0
                                             startedAt:startedAt
                                              duration:CFAbsoluteTimeGetCurrent() - started];
    }

    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    ISCChecks performed = 0;

    size_t count = 0;
    const ISCDetectorEntry *entries = ISCDetectorEntries(&count);
    for (size_t index = 0; index < count; index++) {
        if (!ISCChecksInclude(options, entries[index].check)) {
            continue;
        }
        [findings addObjectsFromArray:entries[index].scan(options)];
        performed |= entries[index].check;
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

- (ISCScanResult *)scan {
    return ISCPerformScan(self.options);
}

- (void)scanOnQueue:(dispatch_queue_t)queue completion:(void (^)(ISCScanResult *))completion {
    dispatch_async(queue, ^{
        completion([self scan]);
    });
}

@end
