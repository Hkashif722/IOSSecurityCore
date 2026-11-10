//
//  ISCHookDetector.m
//  IOSSecurityCoreObjC
//

#import "ISCHookDetector.h"
#import "ISCDebuggerDetector.h"
#import "ISCIntegrityChecker.h"
#import "ISCJailbreakDetector.h"
#import "ISCNetworkDetector.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"
#import "ISCSecurityScanner.h"
#import "ISCTrampoline.h"

#import <objc/runtime.h>
#import <TargetConditionals.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

/// Frida's default listening port.
static const uint16_t ISCInstrumentationPort = 27042;

// MARK: - System functions the detectors depend on
//
// Bypass tweaks (Shadow, A-Bypass, FlyJB, ...) do not patch this package; they hook the system calls
// its checks make, so files, libraries and debuggers simply "are not there". Before those answers are
// trusted, each function is checked twice:
// - Rebinding (fishhook, dyld interposing): the address this image calls must lie in the OS.
// - Inline patching (Substrate, ElleKit, Dobby, Frida's Interceptor): its first instructions must not
//   branch out of the OS.
//
// The address is re-read on every scan: caching it would freeze the value a later hook replaces.

#define ISC_SYSTEM_FUNCTIONS(X) \
    X(access)                   \
    X(open)                     \
    X(readlink)                 \
    X(getenv)                   \
    X(sysctl)                   \
    X(getppid)                  \
    X(dladdr)                   \
    X(dlsym)                    \
    X(_dyld_image_count)        \
    X(_dyld_get_image_name)     \
    X(_dyld_get_image_header)   \
    X(task_threads)             \
    X(thread_get_state)         \
    X(connect)                  \
    X(method_getImplementation) \
    X(objc_lookUpClass)

#define ISC_SYSTEM_FUNCTION_ADDRESS(function) (const void *)(function),
#define ISC_SYSTEM_FUNCTION_NAME(function) ISC_OBF_NSSTRING(#function),

/// Names of `ISC_SYSTEM_FUNCTIONS`, in the same order. Only needed when something is reported.
static NSArray<NSString *> *ISCSystemFunctionNames(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[ISC_SYSTEM_FUNCTIONS(ISC_SYSTEM_FUNCTION_NAME)];
    });
    return names;
}

// MARK: - Built-in indicators

/// Substrings of instrumentation-framework library paths.
///
/// Deliberately not just "frida": "Friday" contains it, and a framework called `BlackFridayDeals`
/// would be flagged as an attack.
static NSArray<NSString *> *ISCBuiltInInstrumentationLibraries(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            ISC_OBF_NSSTRING("FridaGadget"),
            ISC_OBF_NSSTRING("frida-gadget"),
            ISC_OBF_NSSTRING("frida-agent"),
            ISC_OBF_NSSTRING("frida-core"),
            ISC_OBF_NSSTRING("libfrida"),
            ISC_OBF_NSSTRING("re.frida"),
            ISC_OBF_NSSTRING("cynject"),
            ISC_OBF_NSSTRING("libcycript"),
            ISC_OBF_NSSTRING("SSLKillSwitch"),
        ];
    });
    return names;
}

/// Files that exist only where an instrumentation server was installed.
static NSArray<NSString *> *ISCBuiltInInstrumentationArtifacts(void) {
    static NSArray<NSString *> *paths;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        paths = @[
            ISC_OBF_NSSTRING("/usr/sbin/frida-server"),
            ISC_OBF_NSSTRING("/usr/bin/frida-server"),
            ISC_OBF_NSSTRING("/usr/local/bin/frida-server"),
            ISC_OBF_NSSTRING("/usr/lib/frida"),
            ISC_OBF_NSSTRING("/var/jb/usr/sbin/frida-server"),
            ISC_OBF_NSSTRING("/var/jb/usr/bin/frida-server"),
            ISC_OBF_NSSTRING("/var/jb/usr/lib/frida"),
        ];
    });
    return paths;
}

/// Thread names that identify Frida's agent on their own.
static NSArray<NSString *> *ISCStrongInstrumentationThreadNames(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            ISC_OBF_NSSTRING("gum-js-loop"),
            ISC_OBF_NSSTRING("pool-spawner"),
            ISC_OBF_NSSTRING("pool-frida"),
        ];
    });
    return names;
}

/// Thread names (GLib's main loop and D-Bus threads) that only mean something when both appear.
static NSArray<NSString *> *ISCWeakInstrumentationThreadNames(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            ISC_OBF_NSSTRING("gmain"),
            ISC_OBF_NSSTRING("gdbus"),
        ];
    });
    return names;
}

/// Locations a loaded image may come from without raising suspicion: the OS (including the cryptex
/// and developer disk images) and Apple-signed system support.
static NSArray<NSString *> *ISCTrustedSystemPrefixes(void) {
    return @[
        @"/System/",
        @"/usr/lib/",
        @"/Developer/",
        @"/Library/Apple/",
        @"/private/preboot/Cryptexes/",
    ];
}

// MARK: - Probes

/// The names of this process's threads, read with `thread_info` (not `pthread_from_mach_thread_np`,
/// whose result can dangle when a thread exits concurrently).
static NSArray<NSString *> *ISCCopyThreadNames(void) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS || threads == NULL) {
        return @[];
    }

    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:count];
    for (mach_msg_type_number_t index = 0; index < count; index++) {
        thread_extended_info_data_t info;
        mach_msg_type_number_t infoCount = THREAD_EXTENDED_INFO_COUNT;
        if (thread_info(threads[index], THREAD_EXTENDED_INFO, (thread_info_t)&info, &infoCount) == KERN_SUCCESS &&
            info.pth_name[0] != '\0') {
            NSString *name = [NSString stringWithUTF8String:info.pth_name];
            if (name != nil) {
                [names addObject:name];
            }
        }
        mach_port_deallocate(mach_task_self(), threads[index]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    return names;
}

// MARK: - Image classification

/// Images that live outside the OS and the app bundle.
static NSArray<NSString *> *ISCUnknownImages(NSArray<NSString *> *images, NSArray<NSString *> *extraTrustedPrefixes) {
    NSMutableArray<NSString *> *trusted = [NSMutableArray arrayWithArray:ISCTrustedSystemPrefixes()];
    [trusted addObjectsFromArray:ISCAppBundleRoots()];
    [trusted addObjectsFromArray:extraTrustedPrefixes];

    NSMutableArray<NSString *> *unknown = [NSMutableArray array];
    for (NSString *image in images) {
        if (!ISCPathMatchesAnyPrefix(image, trusted)) {
            [unknown addObject:image];
        }
    }
    return unknown;
}

/// Images inside the app bundle that are neither the main executable nor in `allowedNames`.
static NSArray<NSString *> *ISCUnexpectedBundleImages(NSArray<NSString *> *images, NSArray<NSString *> *allowedNames) {
    NSArray<NSString *> *roots = ISCAppBundleRoots();
    NSString *executable = NSBundle.mainBundle.executablePath;
    NSString *canonicalExecutable = executable != nil ? ISCCanonicalizePath(executable) : nil;

    NSMutableArray<NSString *> *unexpected = [NSMutableArray array];
    for (NSString *image in images) {
        if (!ISCPathMatchesAnyPrefix(image, roots)) {
            continue;
        }
        if (canonicalExecutable != nil && [ISCCanonicalizePath(image) isEqualToString:canonicalExecutable]) {
            continue;
        }
        BOOL isAllowed = NO;
        for (NSString *name in allowedNames) {
            // Whole path components only: "Auth.framework/Auth" must not match "EvilAuth.framework/Auth".
            if (ISCPathHasComponentSuffix(image, name)) {
                isAllowed = YES;
                break;
            }
        }
        if (!isAllowed) {
            [unexpected addObject:image];
        }
    }
    return unexpected;
}

// MARK: - Code locations

/// Where non-cached OS code lives: the developer disk image and cryptexes. Deliberately not `/usr/lib/`
/// on a device: every genuine library there is in the shared cache, and rootful tweak loaders install
/// into it. The Simulator is different: it loads some of `/usr/lib/system/` from outside its cache.
static NSArray<NSString *> *ISCTrustedCodePrefixes(void) {
    return @[
        @"/System/",
        @"/Developer/",
        @"/Library/Apple/",
        @"/private/preboot/Cryptexes/",
#if TARGET_OS_SIMULATOR
        @"/usr/lib/",
#endif
    ];
}

/// Whether `address` lies in code a system function may legitimately reach: the OS (shared cache,
/// dyld, developer and cryptex images), the app bundle, or a prefix the host trusts. `outImagePath`
/// receives the containing image, or nil for memory no image owns (a hook's trampoline page).
static BOOL ISCAddressIsTrustedCode(const void *address, NSArray<NSString *> *extraTrustedPrefixes,
                                    NSString **outImagePath) {
    *outImagePath = nil;
    NSString *path = nil;
    const void *base = NULL;
    if (!ISCImageForAddress(address, &path, &base)) {
        return NO;
    }
    *outImagePath = path;
    if (ISCImageIsInSharedCache(base) || [path isEqualToString:@"/usr/lib/dyld"]) {
        return YES;
    }
    NSMutableArray<NSString *> *trusted = [NSMutableArray arrayWithArray:ISCTrustedCodePrefixes()];
    [trusted addObjectsFromArray:ISCAppBundleRoots()];
    [trusted addObjectsFromArray:extraTrustedPrefixes];
    return ISCPathMatchesAnyPrefix(path, trusted);
}

/// `YES` when `function` starts with a branch into untrusted code. `outDestination` receives the
/// destination's image path, or nil for anonymous memory.
static BOOL ISCFunctionIsInlineHooked(const void *function, NSArray<NSString *> *extraTrustedPrefixes,
                                      NSString **outDestination) {
    *outDestination = nil;
    const void *target = NULL;
    if (!ISCDecodeTrampoline(function, &target)) {
        return NO;
    }
    NSString *path = nil;
    if (ISCAddressIsTrustedCode(target, extraTrustedPrefixes, &path)) {
        return NO;
    }
    *outDestination = path;
    return YES;
}

static NSString *ISCDescribeRedirect(NSString *name, NSString *destination) {
    return [NSString stringWithFormat:@"%@ -> %@", name, destination ?: ISC_OBF_NSSTRING("unknown image")];
}

/// Findings for the system functions that were rebound or inline-patched.
static NSArray<ISCFinding *> *ISCSystemFunctionFindings(NSArray<NSString *> *extraTrustedPrefixes) {
    const void *addresses[] = {ISC_SYSTEM_FUNCTIONS(ISC_SYSTEM_FUNCTION_ADDRESS)};
    size_t count = sizeof(addresses) / sizeof(addresses[0]);

    NSMutableArray<NSString *> *rebound = [NSMutableArray array];
    NSMutableArray<NSString *> *patched = [NSMutableArray array];
    for (size_t index = 0; index < count; index++) {
        const void *bound = (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(addresses[index]);
        if (bound == NULL) {
            continue;
        }
        NSString *path = nil;
        if (!ISCAddressIsTrustedCode(bound, extraTrustedPrefixes, &path)) {
            // Bound elsewhere: the code at `bound` is the hook itself, so there is no point decoding it.
            [rebound addObject:ISCDescribeRedirect(ISCSystemFunctionNames()[index], path)];
        } else if (ISCFunctionIsInlineHooked(bound, extraTrustedPrefixes, &path)) {
            [patched addObject:ISCDescribeRedirect(ISCSystemFunctionNames()[index], path)];
        }
    }

    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    if (rebound.count > 0) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookReboundSymbol
                                                      detail:ISCSummarizeValues(rebound, ISCDetailLimit)]];
    }
    if (patched.count > 0) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookInlinePatchedFunction
                                                      detail:ISCSummarizeValues(patched, ISCDetailLimit)]];
    }
    return findings;
}

// MARK: - Objective-C runtime checks

/// A function in this file, used to find the image this code was linked into.
static void ISCSelfAnchor(void) {}

static const void *ISCCodeAddress(void (*function)(void)) {
    return (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(function);
}

/// The address of a method's implementation with any pointer-authentication signature removed.
static const void *ISCImplementationAddress(Method method) {
    IMP implementation = method_getImplementation(method);
    return (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(implementation);
}

static Method ISCResolveMethod(Class cls, SEL selector, BOOL isClassMethod) {
    if (cls == Nil || selector == NULL) {
        return NULL;
    }
    return isClassMethod ? class_getClassMethod(cls, selector) : class_getInstanceMethod(cls, selector);
}

/// Detects that this package's own detectors were swizzled or hooked away from this image.
static NSArray<ISCFinding *> *ISCSelfIntegrityFindings(void) {
    const void *ownBase = NULL;
    if (!ISCImageForAddress(ISCCodeAddress(ISCSelfAnchor), NULL, &ownBase) || ownBase == NULL) {
        return @[];
    }

    struct Target {
        __unsafe_unretained Class cls;
        SEL selector;
        BOOL isClassMethod;
    };
    const struct Target targets[] = {
        {ISCJailbreakDetector.class, @selector(scanWithOptions:), YES},
        {ISCDebuggerDetector.class, @selector(scanWithOptions:), YES},
        {ISCDebuggerDetector.class, @selector(isDebuggerAttached), YES},
        {ISCHookDetector.class, @selector(scanWithOptions:), YES},
        {ISCIntegrityChecker.class, @selector(scanWithOptions:), YES},
        {ISCNetworkDetector.class, @selector(scanWithOptions:), YES},
        {ISCSecurityScanner.class, @selector(scan), NO},
        {ISCFinding.class, @selector(initWithCode:detail:), NO},
    };

    NSMutableArray<NSString *> *tampered = [NSMutableArray array];
    for (size_t index = 0; index < sizeof(targets) / sizeof(targets[0]); index++) {
        Method method = ISCResolveMethod(targets[index].cls, targets[index].selector, targets[index].isClassMethod);
        const void *base = NULL;
        BOOL isOurs = method != NULL &&
                      ISCImageForAddress(ISCImplementationAddress(method), NULL, &base) &&
                      base == ownBase;
        if (!isOurs) {
            [tampered addObject:[NSString stringWithFormat:@"%c[%@ %@]",
                                 targets[index].isClassMethod ? '+' : '-',
                                 NSStringFromClass(targets[index].cls),
                                 NSStringFromSelector(targets[index].selector)]];
        }
    }

    if (tampered.count == 0) {
        return @[];
    }
    return @[[[ISCFinding alloc] initWithCode:ISCFindingCodeHookSelfIntegrity
                                       detail:ISCSummarizeValues(tampered, ISCDetailLimit)]];
}

// MARK: - ISCHookDetector

@implementation ISCHookDetector

+ (NSArray<NSString *> *)loadedImagePaths {
    return ISCCopyLoadedImagePaths();
}

+ (BOOL)isFunctionInlineHooked:(const void *)function {
    NSString *destination = nil;
    return ISCFunctionIsInlineHooked(function, @[], &destination);
}

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    NSArray<NSString *> *images = ISCCopyLoadedImagePaths();

    // 1. Has someone hooked the detectors themselves?
    [findings addObjectsFromArray:ISCSelfIntegrityFindings()];

    // 1b. ...or the system functions their answers come from?
    if (options.includesBuiltInIndicators) {
        [findings addObjectsFromArray:ISCSystemFunctionFindings(options.allowedImagePathPrefixes)];
    }

    // 2. Instrumentation libraries that are already loaded.
    NSMutableArray<NSString *> *libraryNeedles = [NSMutableArray array];
    if (options.includesBuiltInIndicators) {
        [libraryNeedles addObjectsFromArray:ISCBuiltInInstrumentationLibraries()];
    }
    [libraryNeedles addObjectsFromArray:options.additionalSuspiciousLibraries];
    NSArray<NSString *> *instrumentation = ISCStringsContainingAny(images, libraryNeedles);
    if (instrumentation.count > 0) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookInstrumentationLibrary
                                                      detail:ISCSummarizeValues(instrumentation, ISCDetailLimit)]];
    }

    if (options.includesBuiltInIndicators) {
        // 3. An instrumentation server on disk, or listening on loopback.
        NSMutableArray<NSString *> *artifacts = [NSMutableArray array];
        for (NSString *path in ISCBuiltInInstrumentationArtifacts()) {
            if (ISCPathExists(ISCSafeCPath(path))) {
                [artifacts addObject:path];
            }
        }
        if (artifacts.count > 0) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookInstrumentationArtifact
                                                          detail:ISCSummarizeValues(artifacts, ISCDetailLimit)]];
        }
        if (options.probesInstrumentationPorts &&
            ISCLoopbackPortIsOpen(ISCInstrumentationPort, ISCPortProbeTimeoutMilliseconds)) {
            [findings addObject:[[ISCFinding alloc]
                initWithCode:ISCFindingCodeHookInstrumentationPort
                      detail:[NSString stringWithFormat:@"%u", (unsigned)ISCInstrumentationPort]]];
        }

        // 4. Threads started by an injected instrumentation agent.
        NSArray<NSString *> *threadNames = ISCCopyThreadNames();
        NSMutableArray<NSString *> *suspiciousThreads = [NSMutableArray array];
        for (NSString *name in threadNames) {
            if ([ISCStrongInstrumentationThreadNames() containsObject:name]) {
                [suspiciousThreads addObject:name];
            }
        }
        BOOL hasEveryWeakName = YES;
        for (NSString *weakName in ISCWeakInstrumentationThreadNames()) {
            hasEveryWeakName = hasEveryWeakName && [threadNames containsObject:weakName];
        }
        if (hasEveryWeakName) {
            [suspiciousThreads addObjectsFromArray:ISCWeakInstrumentationThreadNames()];
        }
        if (suspiciousThreads.count > 0) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookInstrumentationThread
                                                          detail:ISCSummarizeValues(suspiciousThreads, ISCDetailLimit)]];
        }

        // 5. Images from places no legitimate image comes from.
        if (options.reportsUnknownLibraries) {
            NSArray<NSString *> *unknown = ISCUnknownImages(images, options.allowedImagePathPrefixes);
            if (unknown.count > 0) {
                [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookUnknownLibrary
                                                              detail:ISCSummarizeValues(unknown, ISCDetailLimit)]];
            }
        }
    }

    // 6. A dylib injected into the app bundle itself.
    if (options.allowedBundleLibraries.count > 0) {
        NSArray<NSString *> *unexpected = ISCUnexpectedBundleImages(images, options.allowedBundleLibraries);
        if (unexpected.count > 0) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookUnexpectedBundleLibrary
                                                          detail:ISCSummarizeValues(unexpected, ISCDetailLimit)]];
        }
    }

    // 7. Methods the host asked us to watch.
    [findings addObjectsFromArray:[self verifyProtectedMethods:options.protectedMethods]];

    return findings;
}

+ (NSArray<ISCFinding *> *)verifyProtectedMethods:(NSArray<ISCProtectedMethod *> *)methods {
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];

    for (ISCProtectedMethod *protectedMethod in methods) {
        NSString *label = [NSString stringWithFormat:@"%c[%@ %@]",
                           protectedMethod.isClassMethod ? '+' : '-',
                           protectedMethod.targetClassName,
                           protectedMethod.selectorName];

        Method method = ISCResolveMethod(NSClassFromString(protectedMethod.targetClassName),
                                         NSSelectorFromString(protectedMethod.selectorName),
                                         protectedMethod.isClassMethod);
        if (method == NULL) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookProtectedMethodUnresolved
                                                          detail:label]];
            continue;
        }

        NSArray<NSString *> *allowed = protectedMethod.allowedImagePathPrefixes.count > 0
            ? protectedMethod.allowedImagePathPrefixes
            : ISCAppBundleRoots();

        NSString *imagePath = nil;
        BOOL hasImage = ISCImageForAddress(ISCImplementationAddress(method), &imagePath, NULL);
        if (!hasImage || !ISCPathMatchesAnyPrefix(imagePath, allowed)) {
            // No image at all is the signature of an implementation installed at runtime
            // (imp_implementationWithBlock, a Frida trampoline, ...).
            [findings addObject:[[ISCFinding alloc]
                initWithCode:ISCFindingCodeHookSwizzledMethod
                      detail:[NSString stringWithFormat:@"%@ -> %@", label, hasImage ? imagePath : @"unknown image"]]];
        }
    }
    return findings;
}

@end
