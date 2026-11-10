//
//  ISCHookDetectorTests.m
//  IOSSecurityCoreObjCTests
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

#import <objc/runtime.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// MARK: - A class whose methods the tests swizzle

@interface ISCTestVictim : NSObject
- (NSInteger)secret;
+ (NSInteger)classSecret;
@end

@implementation ISCTestVictim
- (NSInteger)secret { return 42; }
+ (NSInteger)classSecret { return 7; }
@end

/// The path of the image that contains `method`'s implementation.
static NSString *ISCImagePathOfMethod(Method method) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    dladdr((const void *)(uintptr_t)method_getImplementation(method), &info);
    return info.dli_fname != NULL ? @(info.dli_fname) : @"";
}

@interface ISCHookDetectorTests : XCTestCase
@end

@implementation ISCHookDetectorTests

// MARK: - Loaded images

- (void)testLoadedImagePathsIncludeFoundation {
    NSArray<NSString *> *paths = [ISCHookDetector loadedImagePaths];
    XCTAssertGreaterThan(paths.count, 10u);
    BOOL hasFoundation = NO;
    for (NSString *path in paths) {
        hasFoundation = hasFoundation || [path containsString:@"Foundation.framework"];
    }
    XCTAssertTrue(hasFoundation);
}

- (void)testCustomSuspiciousLibraryIsReportedCaseInsensitively {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousLibraries = @[@"fOuNdAtIoN.framework"];

    ISCFinding *finding = ISCFindingWithCode([ISCHookDetector scanWithOptions:options],
                                             ISCFindingCodeHookInstrumentationLibrary);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityCritical);
    XCTAssertTrue([finding.detail containsString:@"Foundation"]);
}

- (void)testNoSuspiciousLibraryMeansNoFinding {
    ISCScanOptions *options = ISCTestOptions();
    options.additionalSuspiciousLibraries = @[@"definitely-not-a-loaded-library-xyz"];
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookInstrumentationLibrary));
}

- (void)testBuiltInListsDoNotFlagTheTestProcess {
    // The built-in lists must not produce false positives in an ordinary process.
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    NSArray<ISCFinding *> *findings = [ISCHookDetector scanWithOptions:options];
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookInstrumentationLibrary));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookInstrumentationArtifact));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookInstrumentationThread));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookSelfIntegrity));
}

// MARK: - Unknown images

- (void)testUnknownImagesAreReportedAndCanBeAllowedByPrefix {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.reportsUnknownLibraries = YES;

    ISCFinding *unknown = ISCFindingWithCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookUnknownLibrary);
    XCTAssertNotNil(unknown, @"the test bundle itself lives outside the trusted locations");
    XCTAssertEqual(unknown.severity, ISCSeverityMedium, @"a heuristic must not compromise a device on its own");

    // Trusting every loaded image leaves nothing unknown.
    options.allowedImagePathPrefixes = [ISCHookDetector loadedImagePaths];
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookUnknownLibrary));
}

- (void)testUnknownImageCheckCanBeSwitchedOff {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.reportsUnknownLibraries = NO;
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookUnknownLibrary));
}

// MARK: - Unexpected bundle libraries

- (void)testUnexpectedBundleLibrariesAreReportedWhenAnAllowListIsGiven {
    ISCScanOptions *options = ISCTestOptions();
    options.allowedBundleLibraries = @[@"definitely-not-loaded.dylib"];

    ISCFinding *finding = ISCFindingWithCode([ISCHookDetector scanWithOptions:options],
                                             ISCFindingCodeHookUnexpectedBundleLibrary);
    XCTAssertNotNil(finding, @"some image under the bundle root is not on the allow-list");
    XCTAssertEqual(finding.severity, ISCSeverityHigh);
}

- (void)testBundleLibraryCheckIsOffWithoutAnAllowList {
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:ISCTestOptions()],
                                   ISCFindingCodeHookUnexpectedBundleLibrary));
}

- (void)testAllowListMatchesWholePathComponentsOnly {
    // Every image under the bundle root, allowed by file name, leaves nothing unexpected...
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    for (NSString *path in [ISCHookDetector loadedImagePaths]) {
        [names addObject:path.lastPathComponent];
    }
    ISCScanOptions *options = ISCTestOptions();
    options.allowedBundleLibraries = names;
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookUnexpectedBundleLibrary));

    // ...but a name that is merely a suffix of a component ("ation" of "Foundation") allows nothing.
    options.allowedBundleLibraries = @[@"ndation"];
    XCTAssertTrue(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookUnexpectedBundleLibrary));
}

// MARK: - Instrumentation server

- (void)testDetectsAListenerOnTheInstrumentationPort {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    XCTAssertGreaterThanOrEqual(listener, 0);
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(27042);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 4) != 0) {
        close(listener);
        XCTSkip(@"Port 27042 is already in use on this machine.");
    }

    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.probesInstrumentationPorts = YES;
    ISCFinding *finding = ISCFindingWithCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookInstrumentationPort);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityHigh);
    XCTAssertEqualObjects(finding.detail, @"27042");

    close(listener);
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookInstrumentationPort),
                   @"a closed port must not be reported");
}

- (void)testPortProbeCanBeSwitchedOff {
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.probesInstrumentationPorts = NO;
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookInstrumentationPort));
}

// MARK: - Protected methods

- (void)testUntouchedProtectedMethodsAreClean {
    NSString *home = ISCImagePathOfMethod(class_getInstanceMethod(ISCTestVictim.class, @selector(secret)));
    NSArray<ISCProtectedMethod *> *methods = @[
        [[ISCProtectedMethod alloc] initWithTargetClassName:@"ISCTestVictim" selectorName:@"secret"
                                              isClassMethod:NO allowedImagePathPrefixes:@[home]],
        [[ISCProtectedMethod alloc] initWithTargetClassName:@"ISCTestVictim" selectorName:@"classSecret"
                                              isClassMethod:YES allowedImagePathPrefixes:@[home]],
    ];
    XCTAssertEqual([ISCHookDetector verifyProtectedMethods:methods].count, 0u);
}

- (void)testAMethodOutsideItsAllowedImagesIsReported {
    ISCProtectedMethod *method = [[ISCProtectedMethod alloc] initWithTargetClassName:@"ISCTestVictim"
                                                                        selectorName:@"secret"
                                                                       isClassMethod:NO
                                                            allowedImagePathPrefixes:@[@"/nonexistent/"]];
    ISCFinding *finding = ISCFindingWithCode([ISCHookDetector verifyProtectedMethods:@[method]],
                                             ISCFindingCodeHookSwizzledMethod);
    XCTAssertNotNil(finding);
    XCTAssertTrue([finding.detail containsString:@"-[ISCTestVictim secret]"], @"%@", finding.detail);
}

- (void)testARuntimeSwizzleIsDetectedAndRestoreIsClean {
    Method method = class_getInstanceMethod(ISCTestVictim.class, @selector(secret));
    NSString *home = ISCImagePathOfMethod(method);
    ISCProtectedMethod *protectedMethod = [[ISCProtectedMethod alloc] initWithTargetClassName:@"ISCTestVictim"
                                                                                 selectorName:@"secret"
                                                                                isClassMethod:NO
                                                                     allowedImagePathPrefixes:@[home]];
    XCTAssertEqual([ISCHookDetector verifyProtectedMethods:@[protectedMethod]].count, 0u);

    // What a tweak does: install an implementation that lives somewhere else.
    IMP original = method_getImplementation(method);
    IMP hook = imp_implementationWithBlock(^NSInteger(id _self) { return 0; });
    method_setImplementation(method, hook);
    [self addTeardownBlock:^{
        method_setImplementation(method, original);
        imp_removeBlock(hook);
    }];

    XCTAssertTrue(ISCContainsCode([ISCHookDetector verifyProtectedMethods:@[protectedMethod]], ISCFindingCodeHookSwizzledMethod),
                  @"an implementation installed at runtime must be caught");

    method_setImplementation(method, original);
    XCTAssertEqual([ISCHookDetector verifyProtectedMethods:@[protectedMethod]].count, 0u);
}

- (void)testAnUnresolvableMethodIsALowSeverityConfigurationFinding {
    ISCProtectedMethod *missingClass = [[ISCProtectedMethod alloc] initWithTargetClassName:@"NoSuchClassAnywhere"
                                                                              selectorName:@"secret"
                                                                             isClassMethod:NO
                                                                  allowedImagePathPrefixes:@[]];
    ISCProtectedMethod *missingSelector = [[ISCProtectedMethod alloc] initWithTargetClassName:@"ISCTestVictim"
                                                                                 selectorName:@"noSuchSelector"
                                                                                isClassMethod:NO
                                                                     allowedImagePathPrefixes:@[]];
    NSArray<ISCFinding *> *findings = [ISCHookDetector verifyProtectedMethods:@[missingClass, missingSelector]];
    XCTAssertEqual(findings.count, 2u);
    for (ISCFinding *finding in findings) {
        XCTAssertEqual(finding.code, ISCFindingCodeHookProtectedMethodUnresolved);
        XCTAssertEqual(finding.severity, ISCSeverityLow);
    }
}

- (void)testProtectedMethodsInScanOptionsAreChecked {
    ISCScanOptions *options = ISCTestOptions();
    options.protectedMethods = @[[[ISCProtectedMethod alloc] initWithTargetClassName:@"ISCTestVictim"
                                                                        selectorName:@"classSecret"
                                                                       isClassMethod:YES
                                                            allowedImagePathPrefixes:@[@"/nonexistent/"]]];
    XCTAssertTrue(ISCContainsCode([ISCHookDetector scanWithOptions:options], ISCFindingCodeHookSwizzledMethod));
}

// MARK: - Self-integrity

- (void)testHookingTheDetectorsThemselvesIsCritical {
    Method method = class_getClassMethod(ISCDebuggerDetector.class, @selector(isDebuggerAttached));
    XCTAssertTrue(method != NULL);
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:ISCTestOptions()], ISCFindingCodeHookSelfIntegrity),
                   @"untouched detectors must verify clean");

    // What a bypass tweak does first: make the debugger check always say "no debugger".
    IMP original = method_getImplementation(method);
    IMP hook = imp_implementationWithBlock(^BOOL(id _self) { return NO; });
    method_setImplementation(method, hook);
    [self addTeardownBlock:^{
        method_setImplementation(method, original);
        imp_removeBlock(hook);
    }];

    ISCFinding *finding = ISCFindingWithCode([ISCHookDetector scanWithOptions:ISCTestOptions()], ISCFindingCodeHookSelfIntegrity);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityCritical);
    XCTAssertTrue([finding.detail containsString:@"isDebuggerAttached"], @"%@", finding.detail);

    method_setImplementation(method, original);
    XCTAssertFalse(ISCContainsCode([ISCHookDetector scanWithOptions:ISCTestOptions()], ISCFindingCodeHookSelfIntegrity));
}

@end
