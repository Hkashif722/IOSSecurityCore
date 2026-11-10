//
//  ISCFindingTests.m
//  IOSSecurityCoreObjCTests
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

/// Every defined code, so adding one without updating the tests and docs is caught.
static NSArray<NSNumber *> *ISCAllCodes(void) {
    return @[
        @(ISCFindingCodeSimulator), @(ISCFindingCodeUnsupportedPlatform), @(ISCFindingCodeMacRuntime),
        @(ISCFindingCodeJailbreakArtifact), @(ISCFindingCodeJailbreakSymlink),
        @(ISCFindingCodeJailbreakSandboxEscape), @(ISCFindingCodeJailbreakForkAllowed),
        @(ISCFindingCodeJailbreakInjectedLibrary), @(ISCFindingCodeJailbreakInjectionEnvironment),
        @(ISCFindingCodeJailbreakBypassTool), @(ISCFindingCodeJailbreakRemoteShellPort),
        @(ISCFindingCodeDebuggerAttached), @(ISCFindingCodeDebuggerHardwareBreakpoint),
        @(ISCFindingCodeDebuggerUnexpectedParent),
        @(ISCFindingCodeHookInstrumentationLibrary), @(ISCFindingCodeHookInstrumentationPort),
        @(ISCFindingCodeHookInstrumentationThread), @(ISCFindingCodeHookInstrumentationArtifact),
        @(ISCFindingCodeHookUnknownLibrary), @(ISCFindingCodeHookSwizzledMethod),
        @(ISCFindingCodeHookProtectedMethodUnresolved), @(ISCFindingCodeHookSelfIntegrity),
        @(ISCFindingCodeHookUnexpectedBundleLibrary), @(ISCFindingCodeHookInlinePatchedFunction),
        @(ISCFindingCodeHookReboundSymbol),
        @(ISCFindingCodeIntegrityBundleIdentifierMismatch), @(ISCFindingCodeIntegrityTeamIdentifierMismatch),
        @(ISCFindingCodeIntegrityBinaryDecrypted), @(ISCFindingCodeIntegrityTextSegmentModified),
        @(ISCFindingCodeIntegrityDebuggableBuild), @(ISCFindingCodeIntegrityUnexpectedProvisioningProfile),
        @(ISCFindingCodeIntegrityTeamIdentifierUnavailable), @(ISCFindingCodeIntegrityTextSegmentUnavailable),
        @(ISCFindingCodeIntegrityImageModified), @(ISCFindingCodeIntegrityImageUnavailable),
        @(ISCFindingCodeNetworkProxy),
    ];
}

@interface ISCFindingTests : XCTestCase
@end

@implementation ISCFindingTests

- (void)testEveryCodeHasAUniqueNonEmptyIdentifier {
    NSMutableSet<NSString *> *identifiers = [NSMutableSet set];
    for (NSNumber *number in ISCAllCodes()) {
        ISCFinding *finding = [[ISCFinding alloc] initWithCode:(ISCFindingCode)number.integerValue detail:nil];
        XCTAssertGreaterThan(finding.identifier.length, 0u, @"code %@", number);
        XCTAssertNotEqualObjects(finding.identifier, @"unknown", @"code %@ is missing from the table", number);
        XCTAssertFalse([identifiers containsObject:finding.identifier], @"duplicate identifier %@", finding.identifier);
        [identifiers addObject:finding.identifier];
    }
    XCTAssertEqual(identifiers.count, ISCAllCodes().count);
}

- (void)testIdentifiersAreNamespacedByCategory {
    NSDictionary<NSNumber *, NSString *> *prefixes = @{
        @(ISCCategoryEnvironment): @"environment.",
        @(ISCCategoryJailbreak): @"jailbreak.",
        @(ISCCategoryDebugger): @"debugger.",
        @(ISCCategoryHooking): @"hooking.",
        @(ISCCategoryIntegrity): @"integrity.",
        @(ISCCategoryNetwork): @"network.",
    };
    for (NSNumber *number in ISCAllCodes()) {
        ISCFinding *finding = [[ISCFinding alloc] initWithCode:(ISCFindingCode)number.integerValue detail:nil];
        NSString *prefix = prefixes[@(finding.category)];
        XCTAssertNotNil(prefix);
        XCTAssertTrue([finding.identifier hasPrefix:prefix], @"%@ is not under %@", finding.identifier, prefix);
    }
}

- (void)testSeverityPolicy {
    // Environment findings never matter on their own.
    NSArray<NSNumber *> *informational = @[@(ISCFindingCodeSimulator), @(ISCFindingCodeUnsupportedPlatform),
                                           @(ISCFindingCodeMacRuntime)];
    for (NSNumber *number in informational) {
        ISCFinding *finding = [[ISCFinding alloc] initWithCode:(ISCFindingCode)number.integerValue detail:nil];
        XCTAssertEqual(finding.severity, ISCSeverityInfo);
    }
    // The conclusive signals.
    NSArray<NSNumber *> *conclusive = @[@(ISCFindingCodeJailbreakSandboxEscape),
                                        @(ISCFindingCodeHookInstrumentationLibrary),
                                        @(ISCFindingCodeHookSelfIntegrity),
                                        @(ISCFindingCodeIntegrityBundleIdentifierMismatch),
                                        @(ISCFindingCodeIntegrityTeamIdentifierMismatch),
                                        @(ISCFindingCodeIntegrityTextSegmentModified),
                                        @(ISCFindingCodeIntegrityImageModified),
                                        @(ISCFindingCodeHookInlinePatchedFunction),
                                        @(ISCFindingCodeHookReboundSymbol)];
    for (NSNumber *number in conclusive) {
        ISCFinding *finding = [[ISCFinding alloc] initWithCode:(ISCFindingCode)number.integerValue detail:nil];
        XCTAssertEqual(finding.severity, ISCSeverityCritical, @"code %@", number);
    }
    // "Could not verify" must be weaker than "verified wrong": unreadable data is not proof of tampering.
    NSArray<NSNumber *> *weak = @[@(ISCFindingCodeIntegrityTeamIdentifierUnavailable),
                                  @(ISCFindingCodeIntegrityTextSegmentUnavailable),
                                  @(ISCFindingCodeIntegrityImageUnavailable),
                                  // A heuristic, or something legitimate software also produces, must not
                                  // compromise a device by itself.
                                  @(ISCFindingCodeHookUnknownLibrary),
                                  @(ISCFindingCodeHookInstrumentationThread),
                                  @(ISCFindingCodeDebuggerUnexpectedParent),
                                  @(ISCFindingCodeNetworkProxy)];
    for (NSNumber *number in weak) {
        ISCFinding *finding = [[ISCFinding alloc] initWithCode:(ISCFindingCode)number.integerValue detail:nil];
        XCTAssertLessThan(finding.severity, ISCSeverityHigh, @"code %@", number);
    }
}

- (void)testCodeValuesAreStable {
    // These numbers are API: backends store them. Renumbering is a breaking change.
    XCTAssertEqual((NSInteger)ISCFindingCodeSimulator, 100);
    XCTAssertEqual((NSInteger)ISCFindingCodeJailbreakArtifact, 200);
    XCTAssertEqual((NSInteger)ISCFindingCodeDebuggerAttached, 300);
    XCTAssertEqual((NSInteger)ISCFindingCodeHookInstrumentationLibrary, 400);
    XCTAssertEqual((NSInteger)ISCFindingCodeIntegrityBundleIdentifierMismatch, 500);
    XCTAssertEqual((NSInteger)ISCFindingCodeIntegrityTextSegmentUnavailable, 507);
    XCTAssertEqual((NSInteger)ISCFindingCodeJailbreakBypassTool, 206);
    XCTAssertEqual((NSInteger)ISCFindingCodeJailbreakRemoteShellPort, 207);
    XCTAssertEqual((NSInteger)ISCFindingCodeDebuggerHardwareBreakpoint, 301);
    XCTAssertEqual((NSInteger)ISCFindingCodeDebuggerUnexpectedParent, 302);
    XCTAssertEqual((NSInteger)ISCFindingCodeHookInlinePatchedFunction, 409);
    XCTAssertEqual((NSInteger)ISCFindingCodeHookReboundSymbol, 410);
    XCTAssertEqual((NSInteger)ISCFindingCodeIntegrityImageModified, 508);
    XCTAssertEqual((NSInteger)ISCFindingCodeIntegrityImageUnavailable, 509);
    XCTAssertEqual((NSInteger)ISCFindingCodeNetworkProxy, 600);
}

- (void)testFindingIsImmutableAndCopyReturnsSelf {
    ISCFinding *finding = [[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakArtifact detail:@"/var/jb"];
    XCTAssertEqual([finding copy], finding);
    XCTAssertEqualObjects(finding.detail, @"/var/jb");
    XCTAssertEqual(finding.category, ISCCategoryJailbreak);
}

- (void)testEqualityConsidersCodeAndDetail {
    ISCFinding *left = [[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakArtifact detail:@"a"];
    ISCFinding *same = [[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakArtifact detail:@"a"];
    ISCFinding *otherDetail = [[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakArtifact detail:@"b"];
    ISCFinding *otherCode = [[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakSymlink detail:@"a"];
    XCTAssertEqualObjects(left, same);
    XCTAssertEqual(left.hash, same.hash);
    XCTAssertNotEqualObjects(left, otherDetail);
    XCTAssertNotEqualObjects(left, otherCode);
}

- (void)testScanResultIsCompromisedOnlyForHighOrCritical {
    NSDate *now = [NSDate date];
    ISCFinding *info = [[ISCFinding alloc] initWithCode:ISCFindingCodeSimulator detail:nil];
    ISCFinding *medium = [[ISCFinding alloc] initWithCode:ISCFindingCodeHookUnknownLibrary detail:nil];
    ISCFinding *high = [[ISCFinding alloc] initWithCode:ISCFindingCodeDebuggerAttached detail:nil];

    ISCScanResult *weak = [[ISCScanResult alloc] initWithFindings:@[info, medium] performedChecks:ISCChecksAll
                                                        startedAt:now duration:0];
    ISCScanResult *strong = [[ISCScanResult alloc] initWithFindings:@[info, medium, high] performedChecks:ISCChecksAll
                                                          startedAt:now duration:0];
    XCTAssertFalse(weak.isCompromised);
    XCTAssertTrue(strong.isCompromised);
    XCTAssertFalse([[ISCScanResult alloc] initWithFindings:@[] performedChecks:0 startedAt:now duration:0].isCompromised);
}

- (void)testOptionsCopyIsIndependent {
    ISCScanOptions *original = [ISCScanOptions defaultOptions];
    original.expectedBundleIdentifier = @"com.example";
    original.additionalSuspiciousPaths = @[@"/a"];
    original.additionalSuspiciousClasses = @[@"A"];
    original.probesRemoteShellPorts = NO;
    original.expectedImageTextDigests = @{@"A.framework/A": @[@"aa"]};

    ISCScanOptions *copy = [original copy];
    original.expectedBundleIdentifier = @"com.changed";
    original.additionalSuspiciousPaths = @[@"/b"];
    original.additionalSuspiciousClasses = @[@"B"];
    original.probesRemoteShellPorts = YES;
    original.expectedImageTextDigests = @{};

    XCTAssertEqualObjects(copy.expectedBundleIdentifier, @"com.example");
    XCTAssertEqualObjects(copy.additionalSuspiciousPaths, @[@"/a"]);
    XCTAssertEqualObjects(copy.additionalSuspiciousClasses, @[@"A"]);
    XCTAssertFalse(copy.probesRemoteShellPorts);
    XCTAssertEqualObjects(copy.expectedImageTextDigests, (@{@"A.framework/A": @[@"aa"]}));
}

- (void)testOptionsDefaults {
    ISCScanOptions *options = [ISCScanOptions defaultOptions];
    XCTAssertEqual(options.checks, ISCChecksAll);
    XCTAssertTrue(options.includesBuiltInIndicators);
    XCTAssertFalse(options.scansUnsupportedEnvironments);
    XCTAssertTrue(options.performsSandboxWriteProbe);
    XCTAssertTrue(options.performsForkProbe);
    XCTAssertTrue(options.reportsUnknownLibraries);
    XCTAssertTrue(options.probesInstrumentationPorts);
    XCTAssertTrue(options.probesRemoteShellPorts);
    XCTAssertEqual(options.expectedDistribution, ISCDistributionAny);
    XCTAssertEqual(options.allowedBundleLibraries.count, 0u);
    XCTAssertEqual(options.additionalSuspiciousClasses.count, 0u);
    XCTAssertEqual(options.expectedTextSegmentDigests.count, 0u);
    XCTAssertEqual(options.expectedImageTextDigests.count, 0u);
    XCTAssertTrue((options.checks & ISCChecksNetwork) != 0, @"the network family is part of a default scan");
    XCTAssertNil(options.expectedBundleIdentifier);
    XCTAssertNil(options.expectedTeamIdentifier);
}

@end
