//
//  ISCJailbreakDetectorTests.m
//  IOSSecurityCoreObjCTests
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

@interface ISCJailbreakDetectorTests : XCTestCase
@property (nonatomic, copy) NSString *scratchDirectory;
@end

@implementation ISCJailbreakDetectorTests

- (void)setUp {
    [super setUp];
    self.scratchDirectory = [NSTemporaryDirectory() stringByAppendingPathComponent:
                             [NSString stringWithFormat:@"isc-jb-%@", NSUUID.UUID.UUIDString]];
    XCTAssertTrue([NSFileManager.defaultManager createDirectoryAtPath:self.scratchDirectory
                                          withIntermediateDirectories:YES
                                                           attributes:nil
                                                                error:NULL]);
}

- (void)tearDown {
    [NSFileManager.defaultManager removeItemAtPath:self.scratchDirectory error:NULL];
    [super tearDown];
}

- (NSString *)createMarkerNamed:(NSString *)name {
    NSString *path = [self.scratchDirectory stringByAppendingPathComponent:name];
    XCTAssertTrue([@"x" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
    return path;
}

// MARK: - File artifacts

- (void)testReportsACustomPathThatExists {
    NSString *marker = [self createMarkerNamed:@"Cydia.app"];
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousPaths = @[marker];

    NSArray<ISCFinding *> *findings = [ISCJailbreakDetector scanWithOptions:options];
    ISCFinding *finding = ISCFindingWithCode(findings, ISCFindingCodeJailbreakArtifact);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityHigh);
    XCTAssertTrue([finding.detail containsString:marker]);
}

- (void)testIgnoresACustomPathThatDoesNotExist {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousPaths = @[[self.scratchDirectory stringByAppendingPathComponent:@"absent"]];
    XCTAssertEqual([ISCJailbreakDetector scanWithOptions:options].count, 0u);
}

- (void)testDirectoriesCountAsExisting {
    NSArray<NSString *> *existing = [ISCJailbreakDetector existingPathsAmong:@[self.scratchDirectory]];
    XCTAssertEqualObjects(existing, @[self.scratchDirectory]);
}

- (void)testExistingPathsAmongKeepsOnlyThePresentOnes {
    NSString *present = [self createMarkerNamed:@"present"];
    NSString *absent = [self.scratchDirectory stringByAppendingPathComponent:@"absent"];
    // A local keeps the commas of the array literal out of the XCTAssert macro's argument list.
    NSArray<NSString *> *candidates = @[absent, present, @"", @"/definitely/not/here"];
    NSArray<NSString *> *expected = @[present];
    XCTAssertEqualObjects([ISCJailbreakDetector existingPathsAmong:candidates], expected);
}

- (void)testWithoutBuiltInsAndCustomEntriesNothingIsFound {
    XCTAssertEqual([ISCJailbreakDetector scanWithOptions:ISCTestOptions()].count, 0u);
}

- (void)testSeveralMatchesBecomeOneFindingWithASummary {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for (int index = 0; index < 8; index++) {
        [paths addObject:[self createMarkerNamed:[NSString stringWithFormat:@"m%d", index]]];
    }
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousPaths = paths;

    NSArray<ISCFinding *> *findings = [ISCJailbreakDetector scanWithOptions:options];
    XCTAssertEqual(findings.count, 1u, @"one finding per code, not one per path");
    XCTAssertTrue([findings.firstObject.detail containsString:@"(+3 more)"], @"%@", findings.firstObject.detail);
}

- (void)testSymlinkedCustomPathIsStillAnExistingPath {
    NSString *target = [self createMarkerNamed:@"target"];
    NSString *link = [self.scratchDirectory stringByAppendingPathComponent:@"link"];
    XCTAssertTrue([NSFileManager.defaultManager createSymbolicLinkAtPath:link withDestinationPath:target error:NULL]);
    XCTAssertEqualObjects([ISCJailbreakDetector existingPathsAmong:@[link]], @[link]);
}

// MARK: - Probes

- (void)testSandboxWriteProbeFindsNothingWithoutPrivileges {
    if (geteuid() == 0) {
        XCTSkip(@"Running as root, so writing to /private legitimately succeeds.");
    }
    ISCScanOptions *options = ISCTestOptions();
    options.performsSandboxWriteProbe = YES;
    XCTAssertFalse(ISCContainsCode([ISCJailbreakDetector scanWithOptions:options], ISCFindingCodeJailbreakSandboxEscape));
}

- (void)testForkProbeReapsItsChildAndReportsHighSeverity {
    ISCScanOptions *options = ISCTestOptions();
    options.performsForkProbe = YES;

    NSArray<ISCFinding *> *findings = [ISCJailbreakDetector scanWithOptions:options];
    ISCFinding *finding = ISCFindingWithCode(findings, ISCFindingCodeJailbreakForkAllowed);
    if (finding != nil) {
        // fork() is allowed here (a Mac, or the Simulator), which is exactly what the probe reports.
        XCTAssertEqual(finding.severity, ISCSeverityHigh);
    }

    // Whether or not fork succeeded, no zombie child may remain.
    int status = 0;
    pid_t leftover = waitpid(-1, &status, WNOHANG);
    XCTAssertTrue(leftover <= 0, @"the probe left child %d unreaped", leftover);
}

- (void)testRepeatedScansDoNotLeakDescriptors {
    int (^openDescriptorCount)(void) = ^int {
        int count = 0;
        for (int descriptor = 0; descriptor < 1024; descriptor++) {
            if (fcntl(descriptor, F_GETFD) != -1) {
                count++;
            }
        }
        return count;
    };

    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousPaths = @[self.scratchDirectory, @"/definitely/not/here"];
    [ISCJailbreakDetector scanWithOptions:options]; // warm up lazily created descriptors
    int before = openDescriptorCount();
    for (int iteration = 0; iteration < 200; iteration++) {
        [ISCJailbreakDetector scanWithOptions:options];
    }
    XCTAssertEqual(openDescriptorCount(), before);
}

// MARK: - Bypass tools

- (void)testARegisteredSuspiciousClassIsABypassTool {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousClasses = @[NSStringFromClass(self.class)];

    ISCFinding *finding = ISCFindingWithCode([ISCJailbreakDetector scanWithOptions:options], ISCFindingCodeJailbreakBypassTool);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityHigh);
    XCTAssertEqual(finding.category, ISCCategoryJailbreak);
    XCTAssertTrue([finding.detail containsString:NSStringFromClass(self.class)], @"%@", finding.detail);
}

- (void)testAnUnregisteredClassIsNotReported {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousClasses = @[@"ISCNoSuchClassAnywhere_XYZ"];
    XCTAssertFalse(ISCContainsCode([ISCJailbreakDetector scanWithOptions:options], ISCFindingCodeJailbreakBypassTool));
}

- (void)testRegisteredClassesAmongKeepsOnlyRegisteredOnes {
    NSArray<NSString *> *registered =
        [ISCJailbreakDetector registeredClassesAmong:@[@"NSObject", @"ISCNoSuchClassAnywhere_XYZ", @"", @"NSString"]];
    XCTAssertEqualObjects(registered, (@[@"NSObject", @"NSString"]));
}

- (void)testBuiltInBypassIndicatorsDoNotFlagTheTestProcess {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    XCTAssertFalse(ISCContainsCode([ISCJailbreakDetector scanWithOptions:options], ISCFindingCodeJailbreakBypassTool));
}

// MARK: - Remote shell ports

- (void)testDetectsAListenerOnARemoteShellPort {
    // 44 rather than 22: a developer Mac with Remote Login on already listens on 22.
    int listener = ISCOpenLoopbackListener(44);
    if (listener < 0) {
        XCTSkip(@"Port 44 cannot be bound on this machine.");
    }
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.probesRemoteShellPorts = YES;

    ISCFinding *finding = ISCFindingWithCode([ISCJailbreakDetector scanWithOptions:options],
                                             ISCFindingCodeJailbreakRemoteShellPort);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityHigh);
    XCTAssertTrue([[finding.detail componentsSeparatedByString:@", "] containsObject:@"44"], @"%@", finding.detail);

    close(listener);
    ISCFinding *after = ISCFindingWithCode([ISCJailbreakDetector scanWithOptions:options],
                                           ISCFindingCodeJailbreakRemoteShellPort);
    XCTAssertFalse([[after.detail componentsSeparatedByString:@", "] containsObject:@"44"],
                   @"a closed port must not be reported: %@", after.detail);
}

- (void)testRemoteShellProbeCanBeSwitchedOff {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.probesRemoteShellPorts = NO;
    XCTAssertFalse(ISCContainsCode([ISCJailbreakDetector scanWithOptions:options], ISCFindingCodeJailbreakRemoteShellPort));
}

@end
