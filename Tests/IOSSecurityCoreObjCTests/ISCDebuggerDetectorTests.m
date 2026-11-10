//
//  ISCDebuggerDetectorTests.m
//  IOSSecurityCoreObjCTests
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

#include <mach/mach.h>
#include <pthread.h>
#include <unistd.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#define ISC_TEST_STRIP(function) ptrauth_strip((void *)(function), ptrauth_key_function_pointer)
#else
#define ISC_TEST_STRIP(function) ((void *)(function))
#endif

/// Never called: a hardware breakpoint is armed on it, and it must never fire.
__attribute__((noinline, unused)) static void ISCBreakpointTarget(void) {
    __asm__ volatile("");
}

/// A thread that does nothing until told to exit, so a test can arm its debug registers.
__attribute__((unused)) static void *ISCParkedThreadMain(void *semaphore) {
    dispatch_semaphore_wait((__bridge dispatch_semaphore_t)semaphore, DISPATCH_TIME_FOREVER);
    return NULL;
}

@interface ISCDebuggerDetectorTests : XCTestCase
@end

@implementation ISCDebuggerDetectorTests

// MARK: - Hardware breakpoints

- (void)testAnOrdinaryProcessHasNoHardwareBreakpoints {
    if (ISCDebuggerDetector.isDebuggerAttached) {
        XCTSkip(@"A debugger is attached and may own the debug registers.");
    }
    XCTAssertFalse(ISCDebuggerDetector.hasHardwareBreakpoints);

    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksDebugger;
    XCTAssertFalse(ISCContainsCode([ISCDebuggerDetector scanWithOptions:options], ISCFindingCodeDebuggerHardwareBreakpoint));
}

- (void)testAnArmedHardwareBreakpointIsReportedAndDisarmingClearsIt {
#if defined(__arm64__)
    if (ISCDebuggerDetector.isDebuggerAttached) {
        XCTSkip(@"A debugger is attached and may own the debug registers.");
    }
    dispatch_semaphore_t release = dispatch_semaphore_create(0);
    pthread_t thread;
    XCTAssertEqual(pthread_create(&thread, NULL, ISCParkedThreadMain, (__bridge void *)release), 0);
    thread_act_t port = pthread_mach_thread_np(thread);

    // What LLDB does for `breakpoint set -H`: an execute breakpoint, enabled, for EL0, all four bytes.
    arm_debug_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__bvr[0] = (uint64_t)(uintptr_t)ISC_TEST_STRIP(ISCBreakpointTarget);
    state.__bcr[0] = (0xFu << 5) | (2u << 1) | 1u;
    kern_return_t armed = thread_set_state(port, ARM_DEBUG_STATE64, (thread_state_t)&state, ARM_DEBUG_STATE64_COUNT);

    BOOL detected = NO;
    NSArray<ISCFinding *> *findings = @[];
    if (armed == KERN_SUCCESS) {
        detected = ISCDebuggerDetector.hasHardwareBreakpoints;
        ISCScanOptions *options = ISCTestOptions();
        options.checks = ISCChecksDebugger;
        findings = [ISCDebuggerDetector scanWithOptions:options];

        memset(&state, 0, sizeof(state));
        thread_set_state(port, ARM_DEBUG_STATE64, (thread_state_t)&state, ARM_DEBUG_STATE64_COUNT);
    }
    dispatch_semaphore_signal(release);
    pthread_join(thread, NULL);

    if (armed != KERN_SUCCESS) {
        XCTSkip(@"This system does not let a process set its own debug registers (%d).", armed);
    }
    XCTAssertTrue(detected);
    ISCFinding *finding = ISCFindingWithCode(findings, ISCFindingCodeDebuggerHardwareBreakpoint);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityHigh);
    XCTAssertFalse(ISCDebuggerDetector.hasHardwareBreakpoints, @"the disarmed thread has exited");
#else
    XCTSkip(@"Debug registers are read on arm64 only.");
#endif
}

// MARK: - Parent process

- (void)testParentProcessCheckMatchesTheKernel {
    XCTAssertEqual(ISCDebuggerDetector.isParentProcessUnexpected, getppid() != 1);
}

- (void)testUnexpectedParentIsAMediumHeuristic {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksDebugger;
    options.includesBuiltInIndicators = YES;
    ISCFinding *finding = ISCFindingWithCode([ISCDebuggerDetector scanWithOptions:options],
                                             ISCFindingCodeDebuggerUnexpectedParent);
    if (getppid() == 1) {
        XCTAssertNil(finding);
    } else {
        // A test runner is never started by launchd, so this is the branch that normally runs.
        XCTAssertNotNil(finding);
        XCTAssertEqual(finding.severity, ISCSeverityMedium);
        XCTAssertEqualObjects(finding.detail, ([NSString stringWithFormat:@"%d", (int)getppid()]));
    }

    options.includesBuiltInIndicators = NO;
    XCTAssertFalse(ISCContainsCode([ISCDebuggerDetector scanWithOptions:options], ISCFindingCodeDebuggerUnexpectedParent),
                   @"heuristics are off without the built-in indicators");
}

@end
