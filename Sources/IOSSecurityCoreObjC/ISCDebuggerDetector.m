//
//  ISCDebuggerDetector.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCDebuggerDetector.h"
#import "ISCFindingSupport.h"
#import "ISCDetector.h"
#import "ISCObfuscation.h"

#include <dlfcn.h>
#include <mach/mach.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

// P_TRACED comes from <sys/proc.h>, which is not always visible through the iOS SDK's sysctl header.
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

/// `PT_DENY_ATTACH` from <sys/ptrace.h>, which the iOS SDK does not ship.
static const int ISCPtraceDenyAttach = 31;

/// launchd, the parent of every app the system starts.
static const pid_t ISCLaunchdProcessIdentifier = 1;

typedef int (*ISCPtraceFunction)(int request, pid_t pid, char *address, int data);

// MARK: - Probes

static BOOL ISCProcessIsTraced(void) {
    // Apple's documented approach (Technical Q&A QA1361): ask the kernel for this process's flags.
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t size = sizeof(info);
    if (sysctl(name, 4, &info, &size, NULL, 0) != 0) {
        return NO;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

/// How many threads have an armed hardware breakpoint and an armed watchpoint.
///
/// A debugger sets these through the thread's debug registers; they keep working when `sysctl` is
/// hooked to hide `P_TRACED`. Only the enable bit (bit 0) of each control register counts: a value
/// register can hold a stale address while its control register is off.
static void ISCCountArmedDebugRegisters(unsigned *outBreakpointThreads, unsigned *outWatchpointThreads) {
    *outBreakpointThreads = 0;
    *outWatchpointThreads = 0;
#if defined(__arm64__)
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS || threads == NULL) {
        return;
    }
    for (mach_msg_type_number_t index = 0; index < count; index++) {
        arm_debug_state64_t state;
        memset(&state, 0, sizeof(state));
        mach_msg_type_number_t stateCount = ARM_DEBUG_STATE64_COUNT;
        if (thread_get_state(threads[index], ARM_DEBUG_STATE64, (thread_state_t)&state, &stateCount) == KERN_SUCCESS) {
            BOOL breakpoint = NO;
            BOOL watchpoint = NO;
            for (size_t slot = 0; slot < sizeof(state.__bcr) / sizeof(state.__bcr[0]); slot++) {
                breakpoint = breakpoint || (state.__bcr[slot] & 1u) != 0;
                watchpoint = watchpoint || (state.__wcr[slot] & 1u) != 0;
            }
            *outBreakpointThreads += breakpoint ? 1 : 0;
            *outWatchpointThreads += watchpoint ? 1 : 0;
        }
        mach_port_deallocate(mach_task_self(), threads[index]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
#endif
}

// MARK: - ISCDebuggerDetector

@implementation ISCDebuggerDetector

+ (BOOL)isDebuggerAttached {
    return ISCProcessIsTraced();
}

+ (BOOL)hasHardwareBreakpoints {
    unsigned breakpoints = 0;
    unsigned watchpoints = 0;
    ISCCountArmedDebugRegisters(&breakpoints, &watchpoints);
    return breakpoints + watchpoints > 0;
}

+ (BOOL)isParentProcessUnexpected {
    return getppid() != ISCLaunchdProcessIdentifier;
}

NSArray<ISCFinding *> *ISCDebuggerScan(ISCScanOptions *options) {
    if (!ISCChecksInclude(options, ISCChecksDebugger)) {
        return @[];
    }
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];

    // 1. The kernel's own answer.
    if (ISCProcessIsTraced()) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeDebuggerAttached, nil)];
    }

    // 2. Armed debug registers.
    unsigned breakpoints = 0;
    unsigned watchpoints = 0;
    ISCCountArmedDebugRegisters(&breakpoints, &watchpoints);
    if (breakpoints + watchpoints > 0) {
        NSString *detail = [NSString stringWithFormat:@"%@=%u, %@=%u",
                            ISC_OBF_NSSTRING("breakpoint threads"), breakpoints,
                            ISC_OBF_NSSTRING("watchpoint threads"), watchpoints];
        [findings addObject:ISCMakeFinding(ISCFindingCodeDebuggerHardwareBreakpoint, detail)];
    }

    // 3. Launched by something other than launchd: on a device that is almost always a debugger.
    if (options.includesBuiltInIndicators) {
        pid_t parent = getppid();
        if (parent != ISCLaunchdProcessIdentifier) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeDebuggerUnexpectedParent, [NSString stringWithFormat:@"%d", (int)parent])];
        }
    }

    return findings;
}

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    return ISCDebuggerScan(options);
}

+ (BOOL)denyDebuggerAttachment {
    ISC_OBF_CSTRING(symbol, "ptrace");
    ISCPtraceFunction ptraceFunction = (ISCPtraceFunction)dlsym(RTLD_DEFAULT, symbol);
    ISC_OBF_WIPE(symbol);
    if (ptraceFunction == NULL) {
        return NO;
    }
    return ptraceFunction(ISCPtraceDenyAttach, 0, NULL, 0) == 0;
}

@end
