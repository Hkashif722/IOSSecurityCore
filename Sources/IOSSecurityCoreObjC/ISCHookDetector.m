//
//  ISCHookDetector.m
//  IOSSecurityCoreObjC
//

#import "ISCHookDetector.h"
#import "ISCDebuggerDetector.h"
#import "ISCIntegrityChecker.h"
#import "ISCJailbreakDetector.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"
#import "ISCSecurityScanner.h"

#import <objc/runtime.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/// Frida's default listening port.
static const uint16_t ISCInstrumentationPort = 27042;

/// Longest wait for the loopback probe to answer. A closed port refuses instantly; this bounds the
/// pathological case of a firewall that silently drops loopback traffic.
static const int ISCPortProbeTimeoutMilliseconds = 150;

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

/// Whether something is listening on the loopback interface at `port`. Never leaves the device.
static BOOL ISCLoopbackPortIsOpen(uint16_t port, int timeoutMilliseconds) {
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return NO;
    }

    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(descriptor);
        return NO;
    }
    int noSigPipe = 1;
    setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    BOOL isOpen = NO;
    if (connect(descriptor, (const struct sockaddr *)&address, sizeof(address)) == 0) {
        isOpen = YES;
    } else if (errno == EINPROGRESS) {
        struct pollfd waiting = {.fd = descriptor, .events = POLLOUT, .revents = 0};
        int ready;
        do {
            ready = poll(&waiting, 1, timeoutMilliseconds);
        } while (ready < 0 && errno == EINTR);

        if (ready > 0) {
            int socketError = 0;
            socklen_t length = sizeof(socketError);
            if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0 && socketError == 0) {
                isOpen = YES;
            }
        }
    }
    close(descriptor);
    return isOpen;
}

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
            if (name.length == 0) {
                continue;
            }
            // Match whole path components: "Auth.framework/Auth" must not match "EvilAuth.framework/Auth".
            if ([image isEqualToString:name] ||
                ([image hasSuffix:name] && [image characterAtIndex:image.length - name.length - 1] == '/')) {
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
        {ISCDebuggerDetector.class, @selector(isDebuggerAttached), YES},
        {ISCHookDetector.class, @selector(scanWithOptions:), YES},
        {ISCIntegrityChecker.class, @selector(scanWithOptions:), YES},
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

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    NSArray<NSString *> *images = ISCCopyLoadedImagePaths();

    // 1. Has someone hooked the detectors themselves?
    [findings addObjectsFromArray:ISCSelfIntegrityFindings()];

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
