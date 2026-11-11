//
//  ISCHookDetectorTests.m
//  IOSSecurityCoreObjCTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

#import <objc/runtime.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
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

// MARK: - A64 encoders for hand-built trampolines

static uint32_t ISCEncodeLdrLiteral(uint32_t reg, int32_t byteOffset) {
    return 0x58000000u | ((((uint32_t)(byteOffset / 4)) & 0x7FFFFu) << 5) | reg;
}
static uint32_t ISCEncodeBr(uint32_t reg) { return 0xD61F0000u | (reg << 5); }
static uint32_t ISCEncodeBraaz(uint32_t reg) { return 0xD61F081Fu | (reg << 5); }
static uint32_t ISCEncodeB(int32_t byteOffset) { return 0x14000000u | (((uint32_t)(byteOffset / 4)) & 0x03FFFFFFu); }
static uint32_t ISCEncodeAdrp(uint32_t reg, uintptr_t pc, uintptr_t target) {
    int64_t pages = ((int64_t)(target & ~(uintptr_t)0xFFF) - (int64_t)(pc & ~(uintptr_t)0xFFF)) >> 12;
    uint32_t immediate = (uint32_t)pages & 0x1FFFFFu;
    return 0x90000000u | ((immediate & 3u) << 29) | (((immediate >> 2) & 0x7FFFFu) << 5) | reg;
}
static uint32_t ISCEncodeAddImmediate(uint32_t reg, uint32_t immediate) {
    return 0x91000000u | ((immediate & 0xFFFu) << 10) | (reg << 5) | reg;
}
static uint32_t ISCEncodeMovz(uint32_t reg, uint64_t value, unsigned halfword) {
    return 0xD2800000u | (halfword << 21) | ((uint32_t)((value >> (16 * halfword)) & 0xFFFFu) << 5) | reg;
}
static uint32_t ISCEncodeMovk(uint32_t reg, uint64_t value, unsigned halfword) {
    return 0xF2800000u | (halfword << 21) | ((uint32_t)((value >> (16 * halfword)) & 0xFFFFu) << 5) | reg;
}
static const uint32_t ISCPacibsp = 0xD503237Fu;
static const uint32_t ISCNop = 0xD503201Fu;
static const uint32_t ISCRet = 0xD65F03C0u;

/// `ldr x16, #8 ; br x16 ; .quad target`, the trampoline Substrate's MSHookFunction writes.
static void ISCWriteLiteralTrampoline(uint32_t *code, const void *target) {
    code[0] = ISCEncodeLdrLiteral(16, 8);
    code[1] = ISCEncodeBr(16);
    uint64_t address = (uint64_t)(uintptr_t)target;
    memcpy(&code[2], &address, sizeof(address));
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
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookInlinePatchedFunction),
                   @"%@", ISCFindingWithCode(findings, ISCFindingCodeHookInlinePatchedFunction));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookReboundSymbol),
                   @"%@", ISCFindingWithCode(findings, ISCFindingCodeHookReboundSymbol));
}

- (void)testListingBundleLibrariesKeepsTheSystemFunctionCheckClean {
    // With a list, only listed bundle images may stand in for a system function. A clean process binds
    // every one of them to the OS, so narrowing the trust must not produce a finding.
    for (NSString *image in ISCHookDetector.loadedImagePaths) {
        if ([image containsString:@"libclang_rt."]) {
            // A sanitizer interposes readlink, sysctl and friends: a real rebinding, correctly reported.
            XCTSkip(@"A sanitizer runtime is loaded (%@).", image.lastPathComponent);
        }
    }
    ISCScanOptions *options = ISCTestOptions();
    options.includesBuiltInIndicators = YES;
    options.allowedBundleLibraries = @[@"NothingWeShip.framework/NothingWeShip"];
    NSArray<ISCFinding *> *findings = [ISCHookDetector scanWithOptions:options];
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookReboundSymbol),
                   @"%@", ISCFindingWithCode(findings, ISCFindingCodeHookReboundSymbol));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookInlinePatchedFunction),
                   @"%@", ISCFindingWithCode(findings, ISCFindingCodeHookInlinePatchedFunction));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeHookSelfIntegrity));
}

// MARK: - Inline hooks

- (void)testRealSystemFunctionsAreNotInlineHooked {
    // Genuine OS code includes syscall stubs and thunks; none of it may look like a hook.
    const void *functions[] = {(const void *)getenv, (const void *)access, (const void *)open,
                               (const void *)dladdr, (const void *)dlsym, (const void *)objc_lookUpClass,
                               (const void *)method_getImplementation, (const void *)socket};
    for (size_t index = 0; index < sizeof(functions) / sizeof(functions[0]); index++) {
        XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:functions[index]], @"function %zu", index);
    }
}

- (void)testTrampolinesIntoAnonymousMemoryAreHooks {
#if defined(__arm64__)
    uint32_t *code = calloc(16, sizeof(uint32_t));
    void *payload = malloc(64); // no image owns heap memory, exactly like a hook's trampoline page
    [self addTeardownBlock:^{
        free(code);
        free(payload);
    }];
    uintptr_t pc = (uintptr_t)code;

    // ldr x16, #8 ; br x16 (Substrate, Frida, Dobby)
    ISCWriteLiteralTrampoline(code, payload);
    XCTAssertTrue([ISCHookDetector isFunctionInlineHooked:code]);

    // The same behind a pacibsp, with the arm64e authenticated branch.
    memset(code, 0, 16 * sizeof(uint32_t));
    code[0] = ISCPacibsp;
    code[1] = ISCEncodeLdrLiteral(17, 8);
    code[2] = ISCEncodeBraaz(17);
    uint64_t address = (uint64_t)(uintptr_t)payload;
    memcpy(&code[3], &address, sizeof(address));
    XCTAssertTrue([ISCHookDetector isFunctionInlineHooked:code]);

    // adrp x17 ; add x17, x17, #off ; br x17 (Frida, ElleKit)
    memset(code, 0, 16 * sizeof(uint32_t));
    code[0] = ISCEncodeAdrp(17, pc, (uintptr_t)payload);
    code[1] = ISCEncodeAddImmediate(17, (uint32_t)((uintptr_t)payload & 0xFFF));
    code[2] = ISCEncodeBr(17);
    XCTAssertTrue([ISCHookDetector isFunctionInlineHooked:code]);

    // movz/movk x16 ; br x16
    memset(code, 0, 16 * sizeof(uint32_t));
    code[0] = ISCEncodeMovz(16, address, 0);
    code[1] = ISCEncodeMovk(16, address, 1);
    code[2] = ISCEncodeMovk(16, address, 2);
    code[3] = ISCEncodeMovk(16, address, 3);
    code[4] = ISCEncodeBr(16);
    XCTAssertTrue([ISCHookDetector isFunctionInlineHooked:code]);

    // b <label>, landing in heap memory too
    memset(code, 0, 16 * sizeof(uint32_t));
    code[0] = ISCEncodeB(32);
    XCTAssertTrue([ISCHookDetector isFunctionInlineHooked:code]);
#else
    XCTSkip(@"Inline-hook decoding is arm64 only.");
#endif
}

- (void)testBranchesIntoTheOperatingSystemAreNotHooks {
#if defined(__arm64__)
    uint32_t *code = calloc(16, sizeof(uint32_t));
    [self addTeardownBlock:^{ free(code); }];

    // A thunk into libc is legitimate; what makes a hook is where the branch lands.
    ISCWriteLiteralTrampoline(code, (const void *)getenv);
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:code]);

    uint64_t address = (uint64_t)(uintptr_t)(const void *)getenv;
    memset(code, 0, 16 * sizeof(uint32_t));
    code[0] = ISCEncodeMovz(16, address, 0);
    code[1] = ISCEncodeMovk(16, address, 1);
    code[2] = ISCEncodeMovk(16, address, 2);
    code[3] = ISCEncodeMovk(16, address, 3);
    code[4] = ISCEncodeBr(16);
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:code]);
#else
    XCTSkip(@"Inline-hook decoding is arm64 only.");
#endif
}

- (void)testOrdinaryAndNearMissCodeIsNotAHook {
#if defined(__arm64__)
    uint32_t *code = calloc(16, sizeof(uint32_t));
    void *payload = malloc(64);
    [self addTeardownBlock:^{
        free(code);
        free(payload);
    }];

    code[0] = ISCNop;
    code[1] = ISCRet;
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:code]);

    // ldr into x16 but branch through x17: not a trampoline.
    ISCWriteLiteralTrampoline(code, payload);
    code[1] = ISCEncodeBr(17);
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:code]);

    // A syscall stub shape: movz x16, #n ; svc #0x80.
    memset(code, 0, 16 * sizeof(uint32_t));
    code[0] = ISCEncodeMovz(16, 0x21, 0);
    code[1] = 0xD4001001u;
    XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:code]);
#else
    XCTSkip(@"Inline-hook decoding is arm64 only.");
#endif
}

- (void)testGarbageAddressesAreNeverHooksAndNeverCrash {
    uint32_t *code = calloc(4, sizeof(uint32_t));
    [self addTeardownBlock:^{ free(code); }];
    const void *garbage[] = {NULL, (const void *)0x1, (const void *)0x10, (const void *)0x1000,
                             (const void *)(UINTPTR_MAX - 15), (const char *)code + 1};
    for (size_t index = 0; index < sizeof(garbage) / sizeof(garbage[0]); index++) {
        XCTAssertFalse([ISCHookDetector isFunctionInlineHooked:garbage[index]], @"address %p", garbage[index]);
    }
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
