//
//  ISCSystemFunctionProbe.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Bypass tweaks (Shadow, A-Bypass, FlyJB, ...) do not patch this package; they hook the system calls
//  its checks make, so files, libraries and debuggers simply "are not there". Before those answers are
//  trusted, each function is checked twice:
//  - Rebinding (fishhook, dyld interposing): the address this image calls must lie in the OS.
//  - Inline patching (Substrate, ElleKit, Dobby, Frida's Interceptor): its first instructions must not
//    branch out of the OS.
//
//  The address is re-read on every scan: caching it would freeze the value a later hook replaces.
//

#import "ISCSystemFunctionProbe.h"
#import "ISCFindingSupport.h"
#import "ISCCodeTrust.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"

#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

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

static NSString *ISCDescribeRedirect(NSString *name, NSString *destination) {
    return [NSString stringWithFormat:@"%@ -> %@", name, destination ?: ISC_OBF_NSSTRING("unknown image")];
}

NSArray<ISCFinding *> *ISCSystemFunctionFindings(const ISCCodeTrust *trust) {
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
        if (!ISCAddressIsTrustedCode(bound, trust, &path)) {
            // Bound elsewhere: the code at `bound` is the hook itself, so there is no point decoding it.
            [rebound addObject:ISCDescribeRedirect(ISCSystemFunctionNames()[index], path)];
        } else if (ISCFunctionIsInlineHooked(bound, trust, &path)) {
            [patched addObject:ISCDescribeRedirect(ISCSystemFunctionNames()[index], path)];
        }
    }

    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    if (rebound.count > 0) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeHookReboundSymbol, ISCSummarizeValues(rebound, ISCDetailLimit))];
    }
    if (patched.count > 0) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeHookInlinePatchedFunction, ISCSummarizeValues(patched, ISCDetailLimit))];
    }
    return findings;
}
