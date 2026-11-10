//
//  ISCInstrumentationProbe.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCInstrumentationProbe.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"

#include <mach/mach.h>

/// Frida's default listening port.
static const uint16_t ISCInstrumentationPort = 27042;

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

/// Thread names that point at an injected agent: any strong name, or every weak name together.
static NSArray<NSString *> *ISCSuspiciousThreadNames(NSArray<NSString *> *threadNames) {
    NSMutableArray<NSString *> *suspicious = [NSMutableArray array];
    for (NSString *name in threadNames) {
        if ([ISCStrongInstrumentationThreadNames() containsObject:name]) {
            [suspicious addObject:name];
        }
    }
    BOOL hasEveryWeakName = YES;
    for (NSString *weakName in ISCWeakInstrumentationThreadNames()) {
        hasEveryWeakName = hasEveryWeakName && [threadNames containsObject:weakName];
    }
    if (hasEveryWeakName) {
        [suspicious addObjectsFromArray:ISCWeakInstrumentationThreadNames()];
    }
    return suspicious;
}

NSArray<ISCFinding *> *ISCInstrumentationFindings(NSArray<NSString *> *loadedImages, ISCScanOptions *options) {
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];

    // 1. Instrumentation libraries that are already loaded.
    NSMutableArray<NSString *> *libraryNeedles = [NSMutableArray array];
    if (options.includesBuiltInIndicators) {
        [libraryNeedles addObjectsFromArray:ISCBuiltInInstrumentationLibraries()];
    }
    [libraryNeedles addObjectsFromArray:options.additionalSuspiciousLibraries];
    NSArray<NSString *> *instrumentation = ISCStringsContainingAny(loadedImages, libraryNeedles);
    if (instrumentation.count > 0) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookInstrumentationLibrary
                                                      detail:ISCSummarizeValues(instrumentation, ISCDetailLimit)]];
    }

    if (!options.includesBuiltInIndicators) {
        return findings;
    }

    // 2. An instrumentation server on disk, or listening on loopback.
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

    // 3. Threads started by an injected instrumentation agent.
    NSArray<NSString *> *suspiciousThreads = ISCSuspiciousThreadNames(ISCCopyThreadNames());
    if (suspiciousThreads.count > 0) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookInstrumentationThread
                                                      detail:ISCSummarizeValues(suspiciousThreads, ISCDetailLimit)]];
    }

    return findings;
}
