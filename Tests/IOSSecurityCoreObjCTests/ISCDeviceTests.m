//
//  ISCDeviceTests.m
//  IOSSecurityCoreObjCTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Runs only on a physical device: the real scan, with every built-in check, against the real OS. The
//  Mac and the Simulator load system libraries differently, so they cannot stand in for this.
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

#import <objc/runtime.h>
#include <dlfcn.h>
#include <stdlib.h>

@interface ISCDeviceTests : XCTestCase
@end

@implementation ISCDeviceTests

- (void)testTheFullScanOnARealDeviceRaisesNoHookingFalsePositives {
    if (!ISCEnvironment.isSupportedDevicePlatform) {
        XCTSkip(@"Physical iOS devices only.");
    }
    ISCScanResult *result = [[[ISCSecurityScanner alloc] initWithOptions:[ISCScanOptions defaultOptions]] scan];

    // The whole report, kept with the test results for review.
    NSMutableString *report = [NSMutableString stringWithFormat:@"duration=%.3fs performed=%lu findings=%lu\n",
                               result.duration, (unsigned long)result.performedChecks,
                               (unsigned long)result.findings.count];
    for (ISCFinding *finding in result.findings) {
        [report appendFormat:@"%@\n", finding];
    }
    printf("[ISC device report]\n%s[/ISC device report]\n", report.UTF8String);
    XCTAttachment *attachment = [XCTAttachment attachmentWithString:report];
    attachment.name = @"ISC device report";
    attachment.lifetime = XCTAttachmentLifetimeKeepAlways;
    [self addAttachment:attachment];

    // On a stock device the OS's own functions must verify clean.
    XCTAssertFalse(ISCContainsCode(result.findings, ISCFindingCodeHookReboundSymbol), @"%@", report);
    XCTAssertFalse(ISCContainsCode(result.findings, ISCFindingCodeHookInlinePatchedFunction), @"%@", report);
    XCTAssertFalse(ISCContainsCode(result.findings, ISCFindingCodeHookSelfIntegrity), @"%@", report);
    XCTAssertEqual(result.performedChecks, ISCChecksAll);
}

- (void)testRealSystemFunctionsAreNotInlineHookedOnADevice {
    if (!ISCEnvironment.isSupportedDevicePlatform) {
        XCTSkip(@"Physical iOS devices only.");
    }
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:(const void *)getenv]);
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:(const void *)dlsym]);
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:(const void *)objc_lookUpClass]);
}

@end
