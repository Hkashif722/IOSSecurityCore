//
//  ISCDetectorRegistry.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  The composition root: the only file that imports every detector and the scanner.
//

#import "ISCDetector.h"
#import "ISCDebuggerDetector.h"
#import "ISCHookDetector.h"
#import "ISCIntegrityChecker.h"
#import "ISCJailbreakDetector.h"
#import "ISCNetworkDetector.h"
#import "ISCSecurityScanner.h"

NSArray<Class<ISCDetector>> *ISCDetectorClasses(void) {
    static NSArray<Class<ISCDetector>> *classes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // Scan order. Jailbreak first because its findings give the later ones context; network last
        // because it is the weakest signal.
        classes = @[
            ISCJailbreakDetector.class,
            ISCDebuggerDetector.class,
            ISCHookDetector.class,
            ISCIntegrityChecker.class,
            ISCNetworkDetector.class,
        ];
    });
    return classes;
}

/// Room for every detector's `scanWithOptions:` plus the fixed extras below.
#define ISC_MAXIMUM_SELF_INTEGRITY_TARGETS 16

const ISCMethodTarget *ISCSelfIntegrityTargets(size_t *outCount) {
    static ISCMethodTarget targets[ISC_MAXIMUM_SELF_INTEGRITY_TARGETS];
    static size_t count;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        size_t index = 0;
        for (Class<ISCDetector> detector in ISCDetectorClasses()) {
            if (index == ISC_MAXIMUM_SELF_INTEGRITY_TARGETS) {
                break;
            }
            targets[index++] = (ISCMethodTarget){detector, @selector(scanWithOptions:), YES};
        }
        // The kernel's answer about tracing, the scanner that aggregates, and the type every finding
        // passes through: a hook on any of these silences the whole package.
        const ISCMethodTarget extras[] = {
            {ISCDebuggerDetector.class, @selector(isDebuggerAttached), YES},
            {ISCSecurityScanner.class, @selector(scan), NO},
            {ISCFinding.class, @selector(initWithCode:detail:), NO},
        };
        for (size_t extra = 0; extra < sizeof(extras) / sizeof(extras[0]) && index < ISC_MAXIMUM_SELF_INTEGRITY_TARGETS; extra++) {
            targets[index++] = extras[extra];
        }
        count = index;
    });
    *outCount = count;
    return targets;
}
