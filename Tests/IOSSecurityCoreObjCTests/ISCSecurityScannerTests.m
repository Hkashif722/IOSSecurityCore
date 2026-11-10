//
//  ISCSecurityScannerTests.m
//  IOSSecurityCoreObjCTests
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

#include <sys/sysctl.h>
#include <unistd.h>

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

static const void *ISCQueueKey = &ISCQueueKey;

@interface ISCSecurityScannerTests : XCTestCase
@end

@implementation ISCSecurityScannerTests

// MARK: - Environment handling

- (void)testUnsupportedEnvironmentsAreSkippedWithOneInformationalFinding {
    if (ISCEnvironment.isSupportedDevicePlatform) {
        XCTSkip(@"This is a real device; the scan is not skipped here.");
    }
    ISCScanOptions *options = [ISCScanOptions defaultOptions];
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan];

    XCTAssertEqual(result.performedChecks, (ISCChecks)0);
    XCTAssertEqual(result.findings.count, 1u);
    XCTAssertEqual(result.findings.firstObject.severity, ISCSeverityInfo);
    XCTAssertEqual(result.findings.firstObject.category, ISCCategoryEnvironment);
    XCTAssertFalse(result.isCompromised, @"a skipped scan must never look like an attack");
    if (ISCEnvironment.isSimulator) {
        XCTAssertEqual(result.findings.firstObject.code, ISCFindingCodeSimulator);
    }
}

- (void)testScansUnsupportedEnvironmentsWhenForced {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksJailbreak | ISCChecksDebugger;
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan];
    XCTAssertEqual(result.performedChecks, ISCChecksJailbreak | ISCChecksDebugger);
}

- (void)testOnlyTheRequestedFamiliesRun {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksHooking;
    options.additionalSuspiciousPaths = @[NSTemporaryDirectory()]; // a jailbreak hit, if jailbreak ran
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan];

    XCTAssertEqual(result.performedChecks, ISCChecksHooking);
    XCTAssertFalse(ISCContainsCode(result.findings, ISCFindingCodeJailbreakArtifact));
}

- (void)testTheNetworkFamilyRunsOnItsOwn {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksNetwork;
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan];
    XCTAssertEqual(result.performedChecks, ISCChecksNetwork);
    for (ISCFinding *finding in result.findings) {
        XCTAssertEqual(finding.category, ISCCategoryNetwork, @"%@", finding);
    }
}

- (void)testNoFamiliesMeansNothingRuns {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = 0;
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan];
    XCTAssertEqual(result.performedChecks, (ISCChecks)0);
    XCTAssertEqual(result.findings.count, 0u);
}

// MARK: - Result shape

- (void)testFindingsAreOrderedMostSevereFirst {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksJailbreak | ISCChecksHooking | ISCChecksIntegrity;
    options.additionalSuspiciousPaths = @[NSTemporaryDirectory()];          // High
    options.additionalSuspiciousLibraries = @[@"Foundation.framework"];     // Critical
    options.expectedBundleIdentifier = @"com.definitely.not.this.app";      // Critical
    options.protectedMethods = @[[[ISCProtectedMethod alloc] initWithTargetClassName:@"NoSuchClass"
                                                                        selectorName:@"x"
                                                                       isClassMethod:NO
                                                            allowedImagePathPrefixes:@[]]]; // Low

    NSArray<ISCFinding *> *findings = [[[ISCSecurityScanner alloc] initWithOptions:options] scan].findings;
    XCTAssertGreaterThanOrEqual(findings.count, 4u);
    for (NSUInteger index = 1; index < findings.count; index++) {
        XCTAssertGreaterThanOrEqual(findings[index - 1].severity, findings[index].severity,
                                    @"%@ must not come before %@", findings[index - 1], findings[index]);
    }
    XCTAssertEqual(findings.firstObject.severity, ISCSeverityCritical);
    XCTAssertEqual(findings.lastObject.severity, ISCSeverityLow);
}

- (void)testResultCarriesTimingAndIsCompromisedFollowsSeverity {
    ISCScanOptions *clean = ISCTestOptions();
    ISCScanResult *cleanResult = [[[ISCSecurityScanner alloc] initWithOptions:clean] scan];
    XCTAssertGreaterThanOrEqual(cleanResult.duration, 0);
    XCTAssertLessThan(cleanResult.duration, 5);
    XCTAssertLessThanOrEqual(fabs(cleanResult.startedAt.timeIntervalSinceNow), 5);

    ISCScanOptions *dirty = ISCTestOptions();
    dirty.additionalSuspiciousPaths = @[NSTemporaryDirectory()];
    XCTAssertTrue([[[ISCSecurityScanner alloc] initWithOptions:dirty] scan].isCompromised);
}

// MARK: - Debugger

- (void)testDebuggerFindingMatchesAnIndependentKernelQuery {
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t size = sizeof(info);
    XCTAssertEqual(sysctl(name, 4, &info, &size, NULL, 0), 0);
    BOOL attached = (info.kp_proc.p_flag & P_TRACED) != 0;

    XCTAssertEqual(ISCDebuggerDetector.isDebuggerAttached, attached);

    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksDebugger;
    NSArray<ISCFinding *> *findings = [ISCDebuggerDetector scanWithOptions:options];
    XCTAssertEqual(ISCContainsCode(findings, ISCFindingCodeDebuggerAttached), attached);
}

- (void)testDebuggerScanHonoursTheCheckSelection {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksJailbreak;
    XCTAssertEqual([ISCDebuggerDetector scanWithOptions:options].count, 0u);
}

// MARK: - Concurrency

- (void)testScanOnQueueCompletesOnThatQueue {
    dispatch_queue_t queue = dispatch_queue_create("isc.test.scan", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(queue, ISCQueueKey, (void *)ISCQueueKey, NULL);

    XCTestExpectation *completed = [self expectationWithDescription:@"completion"];
    [[[ISCSecurityScanner alloc] initWithOptions:ISCTestOptions()]
        scanOnQueue:queue
         completion:^(ISCScanResult *result) {
        XCTAssertNotNil(result);
        XCTAssertEqual(dispatch_get_specific(ISCQueueKey), ISCQueueKey, @"must run on the requested queue");
        XCTAssertFalse(NSThread.isMainThread);
        [completed fulfill];
    }];
    [self waitForExpectations:@[completed] timeout:10];
}

- (void)testScanOnQueueReturnsBeforeTheWorkRuns {
    dispatch_queue_t queue = dispatch_queue_create("isc.test.blocked", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t gate = dispatch_semaphore_create(0);
    dispatch_async(queue, ^{ dispatch_semaphore_wait(gate, DISPATCH_TIME_FOREVER); }); // hold the queue

    __block BOOL completed = NO;
    [[[ISCSecurityScanner alloc] initWithOptions:ISCTestOptions()]
        scanOnQueue:queue completion:^(ISCScanResult *result) { completed = YES; }];

    // If scanOnQueue: had run the scan synchronously it would have completed (or blocked) by now.
    XCTAssertFalse(completed);

    XCTestExpectation *drained = [self expectationWithDescription:@"drained"];
    dispatch_async(queue, ^{ [drained fulfill]; });
    dispatch_semaphore_signal(gate);
    [self waitForExpectations:@[drained] timeout:10];
    XCTAssertTrue(completed);
}

- (void)testScannerSnapshotsItsOptions {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousPaths = @[NSTemporaryDirectory()];
    ISCSecurityScanner *scanner = [[ISCSecurityScanner alloc] initWithOptions:options];

    options.additionalSuspiciousPaths = @[]; // changed after the scanner was made
    XCTAssertTrue(ISCContainsCode([scanner scan].findings, ISCFindingCodeJailbreakArtifact));
}

- (void)testConcurrentScansAreSafe {
    ISCSecurityScanner *scanner = [[ISCSecurityScanner alloc] initWithOptions:ISCTestOptions()];
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    XCTestExpectation *finished = [self expectationWithDescription:@"all scans finished"];
    finished.expectedFulfillmentCount = 24;

    for (int index = 0; index < 24; index++) {
        [scanner scanOnQueue:queue completion:^(ISCScanResult *result) {
            XCTAssertNotNil(result);
            [finished fulfill];
        }];
    }
    [self waitForExpectations:@[finished] timeout:30];
}

- (void)testAScanIsFastEnoughForLaunchTime {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES; // the full built-in lists
    options.reportsUnknownLibraries = YES;
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan];
    XCTAssertLessThan(result.duration, 1.0, @"a full scan took %.3f s", result.duration);
}

@end
