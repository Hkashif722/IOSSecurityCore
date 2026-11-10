//
//  ISCRobustnessTests.m
//  IOSSecurityCoreObjCTests
//
//  The scan configuration comes from the host app and, through it, from remote configuration, plists and
//  user input. A security SDK that crashes the app on a malformed entry is worse than none, so no value
//  may ever raise or crash.
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

/// Strings that have broken path and string APIs before.
static NSArray<NSString *> *ISCHostileStrings(void) {
    unichar loneSurrogate = 0xD800;
    unichar embeddedNul[] = {'/', 'a', 0, 'b'};
    return @[
        @"",
        @" ",
        @"\n",
        @"/",
        @"//",
        @".",
        @"..",
        @"relative/path",
        @"/trailing/slash/",
        @"/with space/and\ttab",
        @"/tmp/é中\U0001F510",
        [NSString stringWithCharacters:&loneSurrogate length:1],
        [NSString stringWithCharacters:embeddedNul length:4],
        [@"" stringByPaddingToLength:10000 withString:@"a" startingAtIndex:0],
        [@"/" stringByAppendingString:[@"" stringByPaddingToLength:5000 withString:@"d/" startingAtIndex:0]],
        @"%s%n%@",
    ];
}

@interface ISCRobustnessTests : XCTestCase
@end

@implementation ISCRobustnessTests

- (void)testHostilePathsNeverRaiseOrCrash {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousPaths = ISCHostileStrings();
    options.checks = ISCChecksJailbreak;
    XCTAssertNoThrow([ISCJailbreakDetector scanWithOptions:options]);
    XCTAssertNoThrow([ISCJailbreakDetector existingPathsAmong:ISCHostileStrings()]);
}

- (void)testEmptyPathIsSimplyNotThere {
    XCTAssertEqual([ISCJailbreakDetector existingPathsAmong:@[@""]].count, 0u);
}

- (void)testHostileLibraryNamesAndPrefixesNeverRaiseOrCrash {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.reportsUnknownLibraries = YES;
    options.additionalSuspiciousLibraries = ISCHostileStrings();
    options.allowedImagePathPrefixes = ISCHostileStrings();
    options.allowedBundleLibraries = ISCHostileStrings();
    XCTAssertNoThrow([ISCHookDetector scanWithOptions:options]);
}

- (void)testEmptyLibraryNeedleDoesNotMatchEverything {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousLibraries = @[@""];
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookInstrumentationLibrary),
                   @"a blank entry must be ignored, not treated as a wildcard");
}

- (void)testEmptyAllowedPrefixDoesNotTrustEverything {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.reportsUnknownLibraries = YES;
    options.allowedImagePathPrefixes = @[@""];
    XCTAssertTrue(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookUnknownLibrary),
                  @"a blank entry must be ignored, not treated as a wildcard");
}

- (void)testHostileProtectedMethodsNeverRaiseOrCrash {
    NSMutableArray<ISCProtectedMethod *> *methods = [NSMutableArray array];
    for (NSString *hostile in ISCHostileStrings()) {
        for (NSNumber *isClassMethod in @[@NO, @YES]) {
            [methods addObject:[[ISCProtectedMethod alloc] initWithTargetClassName:hostile
                                                                      selectorName:hostile
                                                                     isClassMethod:isClassMethod.boolValue
                                                          allowedImagePathPrefixes:ISCHostileStrings()]];
        }
    }
    XCTAssertNoThrow([ISCHookDetector verifyProtectedMethods:methods]);

    NSArray<ISCFinding *> *findings = [ISCHookDetector verifyProtectedMethods:methods];
    for (ISCFinding *finding in findings) {
        XCTAssertEqual(finding.code, ISCFindingCodeHookProtectedMethodUnresolved,
                       @"nothing named like that exists, so each must be 'unresolved', not a swizzle: %@", finding);
    }
}

- (void)testHostileIntegrityExpectationsNeverRaiseOrCrash {
    for (NSString *hostile in ISCHostileStrings()) {
        ISCScanOptions *options = ISCTestOptions();
        options.expectedBundleIdentifier = hostile;
        options.expectedTeamIdentifier = hostile;
        options.expectedTextSegmentDigests = @[hostile];
        options.expectedDistribution = ISCDistributionAppStore;
        XCTAssertNoThrow([ISCIntegrityChecker scanWithOptions:options]);
    }
}

- (void)testHostileSuspiciousClassesNeverRaiseOrCrash {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousClasses = ISCHostileStrings();
    XCTAssertNoThrow([ISCJailbreakDetector scanWithOptions:options]);
    XCTAssertNoThrow([ISCJailbreakDetector registeredClassesAmong:ISCHostileStrings()]);
}

- (void)testHostileImageDigestExpectationsNeverRaiseOrCrash {
    NSMutableDictionary *expectations = [NSMutableDictionary dictionary];
    for (NSString *hostile in ISCHostileStrings()) {
        expectations[hostile] = ISCHostileStrings();
    }
    // What a careless Objective-C caller or a decoded plist can put in a typed dictionary.
    NSDictionary *malformed = @{
        @1: @[@"00"],
        NSNull.null: @[],
        @"NotAnArray.framework/NotAnArray": @"00",
        @"NumbersInside.framework/NumbersInside": @[@1, NSNull.null],
    };
    [expectations addEntriesFromDictionary:malformed];

    ISCScanOptions *options = ISCTestOptions();
    options.expectedImageTextDigests = expectations;
    XCTAssertNoThrow([ISCIntegrityChecker scanWithOptions:options]);
    for (NSString *hostile in ISCHostileStrings()) {
        XCTAssertNoThrow([ISCIntegrityChecker textSegmentDigestOfImageNamed:hostile]);
    }
}

- (void)testBlankExpectationsMeanNotConfigured {
    ISCScanOptions *options = ISCTestOptions();
    options.expectedBundleIdentifier = @"";
    options.expectedTeamIdentifier = @"";
    XCTAssertEqual([ISCIntegrityChecker scanWithOptions:options].count, 0u,
                   @"an empty string is how an unset value often arrives from configuration");
}

- (void)testTheWholeScannerSurvivesEverythingAtOnce {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.reportsUnknownLibraries = YES;
    options.additionalSuspiciousPaths = ISCHostileStrings();
    options.additionalSuspiciousLibraries = ISCHostileStrings();
    options.allowedImagePathPrefixes = ISCHostileStrings();
    options.allowedBundleLibraries = ISCHostileStrings();
    options.expectedBundleIdentifier = ISCHostileStrings().lastObject;
    options.expectedTeamIdentifier = ISCHostileStrings()[11];
    options.expectedTextSegmentDigests = ISCHostileStrings();
    options.additionalSuspiciousClasses = ISCHostileStrings();
    options.expectedImageTextDigests = @{ISCHostileStrings()[11]: ISCHostileStrings(), @"": @[@""]};
    options.protectedMethods = @[[[ISCProtectedMethod alloc] initWithTargetClassName:@""
                                                                        selectorName:@""
                                                                       isClassMethod:NO
                                                            allowedImagePathPrefixes:@[]]];
    __block ISCScanResult *result = nil;
    XCTAssertNoThrow(result = [[[ISCSecurityScanner alloc] initWithOptions:options] scan]);
    XCTAssertNotNil(result);
}

- (void)testObfuscationHelpersTolerateEdgeInputs {
    char output[1];
    ISCDeobfuscateBytes((const uint8_t *)"", 0, 0, output); // zero length still terminates the output
    XCTAssertEqual(output[0], 0);

    // Lengths beyond the macro limit are clamped, never overflowing the internal buffer.
    uint8_t long_input[200];
    memset(long_input, 0x41, sizeof(long_input));
    NSString *clamped = ISCStringFromObfuscatedBytes(long_input, sizeof(long_input), 3);
    XCTAssertLessThanOrEqual(clamped.length, (NSUInteger)ISC_OBF_MAX_LENGTH);
}

@end
