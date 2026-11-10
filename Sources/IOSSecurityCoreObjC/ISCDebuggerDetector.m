//
//  ISCDebuggerDetector.m
//  IOSSecurityCoreObjC
//

#import "ISCDebuggerDetector.h"
#import "ISCObfuscation.h"

#include <dlfcn.h>
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

typedef int (*ISCPtraceFunction)(int request, pid_t pid, char *address, int data);

@implementation ISCDebuggerDetector

+ (BOOL)isDebuggerAttached {
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

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    if ((options.checks & ISCChecksDebugger) == 0 || !self.isDebuggerAttached) {
        return @[];
    }
    return @[[[ISCFinding alloc] initWithCode:ISCFindingCodeDebuggerAttached detail:nil]];
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
