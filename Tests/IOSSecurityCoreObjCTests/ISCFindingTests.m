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
        @(ISCFindingCodeDebuggerAttached),
        @(ISCFindingCodeHookInstrumentationLibrary), @(ISCFindingCodeHookInstrumentationPort),
        @(ISCFindingCodeHookInstrumentationThread), @(ISCFindingCodeHookInstrumentationArtifact),
        @(ISCFindingCodeHookUnknownLibrary), @(ISCFindingCodeHookSwizzledMethod),
        @(ISCFindingCodeHookProtectedMethodUnresolved), @(ISCFindingCodeHookSelfIntegrity),
        @(ISCFindingCodeHookUnexpectedBundleLibrary),
        @(ISCFindingCodeIntegrityBundleIdentifierMismatch), @(ISCFindingCodeIntegrityTeamIdentifierMismatch),
        @(ISCFindingCodeIntegrityBinaryDecrypted), @(ISCFindingCodeIntegrityTextSegmentModified),
        @(ISCFindingCodeIntegrityDebuggableBuild), @(ISCFindingCodeIntegrityUnexpectedProvisioningProfile),
        @(ISCFindingCodeIntegrityTeamIdentifierUnavailable), @(ISCFindingCodeIntegrityTextSegmentUnavailable),
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
                                        @(ISCFindingCodeIntegrityTextSegmentModified)];
    for (NSNumber *number in conclusive) {
        ISCFinding *finding = [[ISCFinding alloc] initWithCode:(ISCFindingCode)number.integerValue detail:nil];
        XCTAssertEqual(finding.severity, ISCSeverityCritical, @"code %@", number);
    }
    // "Could not verify" must be weaker than "verified wrong": unreadable data is not proof of tampering.
    XCTAssertLessThan([[ISCFinding alloc] initWithCode:ISCFindingCodeIntegrityTeamIdentifierUnavailable detail:nil].severity,
                      ISCSeverityHigh);
    XCTAssertLessThan([[ISCFinding alloc] initWithCode:ISCFindingCodeIntegrityTextSegmentUnavailable detail:nil].severity,
                      ISCSeverityHigh);
    // A heuristic must not compromise a device by itself.
    XCTAssertLessThan([[ISCFinding alloc] initWithCode:ISCFindingCodeHookUnknownLibrary detail:nil].severity, ISCSeverityHigh);
    XCTAssertLessThan([[ISCFinding alloc] initWithCode:ISCFindingCodeHookInstrumentationThread detail:nil].severity,
                      ISCSeverityHigh);
}

- (void)testCodeValuesAreStable {
    // These numbers are API: backends store them. Renumbering is a breaking change.
    XCTAssertEqual((NSInteger)ISCFindingCodeSimulator, 100);
    XCTAssertEqual((NSInteger)ISCFindingCodeJailbreakArtifact, 200);
    XCTAssertEqual((NSInteger)ISCFindingCodeDebuggerAttached, 300);
    XCTAssertEqual((NSInteger)ISCFindingCodeHookInstrumentationLibrary, 400);
    XCTAssertEqual((NSInteger)ISCFindingCodeIntegrityBundleIdentifierMismatch, 500);
    XCTAssertEqual((NSInteger)ISCFindingCodeIntegrityTextSegmentUnavailable, 507);
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

    ISCScanOptions *copy = [original copy];
    original.expectedBundleIdentifier = @"com.changed";
    original.additionalSuspiciousPaths = @[@"/b"];

    XCTAssertEqualObjects(copy.expectedBundleIdentifier, @"com.example");
    XCTAssertEqualObjects(copy.additionalSuspiciousPaths, @[@"/a"]);
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
    XCTAssertEqual(options.expectedDistribution, ISCDistributionAny);
    XCTAssertEqual(options.allowedBundleLibraries.count, 0u);
    XCTAssertEqual(options.expectedTextSegmentDigests.count, 0u);
    XCTAssertNil(options.expectedBundleIdentifier);
    XCTAssertNil(options.expectedTeamIdentifier);
}

@end
