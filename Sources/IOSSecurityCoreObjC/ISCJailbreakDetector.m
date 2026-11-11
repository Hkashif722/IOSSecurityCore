//
//  ISCJailbreakDetector.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCJailbreakDetector.h"
#import "ISCFindingSupport.h"
#import "ISCDetector.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"

#import <objc/runtime.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

// MARK: - Built-in indicators
//
// Every literal goes through ISC_OBF_NSSTRING, so none of them exists in plain text in the binary.
// The lists are built once and cached.

/// Files and directories that exist only on jailbroken devices.
static NSArray<NSString *> *ISCBuiltInArtifactPaths(void) {
    static NSArray<NSString *> *paths;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        paths = @[
            // Package managers and jailbreak apps
            ISC_OBF_NSSTRING("/Applications/Cydia.app"),
            ISC_OBF_NSSTRING("/Applications/Sileo.app"),
            ISC_OBF_NSSTRING("/Applications/Zebra.app"),
            ISC_OBF_NSSTRING("/Applications/Installer.app"),
            ISC_OBF_NSSTRING("/Applications/Filza.app"),
            ISC_OBF_NSSTRING("/Applications/NewTerm.app"),
            ISC_OBF_NSSTRING("/Applications/blackra1n.app"),
            ISC_OBF_NSSTRING("/Applications/FakeCarrier.app"),
            ISC_OBF_NSSTRING("/Applications/Icy.app"),
            ISC_OBF_NSSTRING("/Applications/IntelliScreen.app"),
            ISC_OBF_NSSTRING("/Applications/MxTube.app"),
            ISC_OBF_NSSTRING("/Applications/RockApp.app"),
            ISC_OBF_NSSTRING("/Applications/SBSettings.app"),
            ISC_OBF_NSSTRING("/Applications/WinterBoard.app"),

            // Rootless and modern jailbreak roots and markers
            ISC_OBF_NSSTRING("/var/jb"),
            ISC_OBF_NSSTRING("/var/binpack"),
            ISC_OBF_NSSTRING("/var/containers/Bundle/tweaksupport"),
            ISC_OBF_NSSTRING("/var/LIB"),
            ISC_OBF_NSSTRING("/var/lib/undecimus"),
            ISC_OBF_NSSTRING("/private/var/lib/undecimus"),
            ISC_OBF_NSSTRING("/.installed_unc0ver"),
            ISC_OBF_NSSTRING("/.bootstrapped_electra"),
            ISC_OBF_NSSTRING("/.cydia_no_stash"),
            ISC_OBF_NSSTRING("/.mount_rw"),

            // Tweak injection
            ISC_OBF_NSSTRING("/Library/MobileSubstrate"),
            ISC_OBF_NSSTRING("/Library/MobileSubstrate/MobileSubstrate.dylib"),
            ISC_OBF_NSSTRING("/Library/MobileSubstrate/DynamicLibraries"),
            ISC_OBF_NSSTRING("/Library/Frameworks/CydiaSubstrate.framework"),
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/Cephei.bundle"),
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/SubstitutePrefs.bundle"),
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/libhbangprefs.bundle"),
            ISC_OBF_NSSTRING("/usr/lib/substrate"),
            ISC_OBF_NSSTRING("/usr/lib/libsubstrate.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libsubstitute.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/substitute-inserter.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libhooker.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libellekit.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/TweakInject"),
            ISC_OBF_NSSTRING("/usr/lib/TweakInject.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libcycript.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libjailbreak.dylib"),

            // Remote shells and package tooling
            ISC_OBF_NSSTRING("/bin/bash"),
            ISC_OBF_NSSTRING("/bin/sh"),
            ISC_OBF_NSSTRING("/usr/sbin/sshd"),
            ISC_OBF_NSSTRING("/usr/bin/sshd"),
            ISC_OBF_NSSTRING("/usr/bin/ssh"),
            ISC_OBF_NSSTRING("/usr/bin/cycript"),
            ISC_OBF_NSSTRING("/usr/local/bin/cycript"),
            ISC_OBF_NSSTRING("/usr/libexec/cydia"),
            ISC_OBF_NSSTRING("/usr/libexec/sftp-server"),
            ISC_OBF_NSSTRING("/usr/libexec/ssh-keysign"),
            ISC_OBF_NSSTRING("/etc/apt"),
            ISC_OBF_NSSTRING("/etc/ssh/sshd_config"),
            ISC_OBF_NSSTRING("/private/var/lib/apt"),
            ISC_OBF_NSSTRING("/private/var/lib/cydia"),
            ISC_OBF_NSSTRING("/private/var/stash"),
            ISC_OBF_NSSTRING("/private/var/tmp/cydia.log"),
            ISC_OBF_NSSTRING("/private/var/mobile/Library/SBSettings/Themes"),
            ISC_OBF_NSSTRING("/var/cache/apt"),
            ISC_OBF_NSSTRING("/var/lib/apt"),
            ISC_OBF_NSSTRING("/var/lib/cydia"),
            ISC_OBF_NSSTRING("/var/lib/dpkg"),
            ISC_OBF_NSSTRING("/var/log/apt"),
            ISC_OBF_NSSTRING("/var/log/syslog"),
            ISC_OBF_NSSTRING("/var/tmp/cydia.log"),
            ISC_OBF_NSSTRING("/System/Library/LaunchDaemons/com.ikey.bbot.plist"),
            ISC_OBF_NSSTRING("/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"),
        ];
    });
    return paths;
}

/// Directories that are real directories on a stock device and symlinks on classic jailbreaks.
static NSArray<NSString *> *ISCBuiltInSymlinkPaths(void) {
    static NSArray<NSString *> *paths;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        paths = @[
            ISC_OBF_NSSTRING("/Applications"),
            ISC_OBF_NSSTRING("/Library/Ringtones"),
            ISC_OBF_NSSTRING("/Library/Wallpaper"),
            ISC_OBF_NSSTRING("/usr/arm-apple-darwin9"),
            ISC_OBF_NSSTRING("/usr/include"),
            ISC_OBF_NSSTRING("/usr/libexec"),
            ISC_OBF_NSSTRING("/usr/share"),
        ];
    });
    return paths;
}

/// Substrings of tweak-injection library paths. Deliberately specific: a bare "substitute" or "hook"
/// would match innocent frameworks.
static NSArray<NSString *> *ISCBuiltInInjectionLibraries(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            ISC_OBF_NSSTRING("MobileSubstrate"),
            ISC_OBF_NSSTRING("CydiaSubstrate"),
            ISC_OBF_NSSTRING("libsubstrate"),
            ISC_OBF_NSSTRING("SubstrateLoader"),
            ISC_OBF_NSSTRING("SubstrateInserter"),
            ISC_OBF_NSSTRING("libsubstitute"),
            ISC_OBF_NSSTRING("substitute-inserter"),
            ISC_OBF_NSSTRING("substitute-loader"),
            ISC_OBF_NSSTRING("libhooker"),
            ISC_OBF_NSSTRING("TweakInject"),
            ISC_OBF_NSSTRING("ellekit"),
            ISC_OBF_NSSTRING("libjailbreak"),
            ISC_OBF_NSSTRING("libsandy"),
            ISC_OBF_NSSTRING("rocketbootstrap"),
            ISC_OBF_NSSTRING("pspawn_payload"),
            ISC_OBF_NSSTRING("PreferenceLoader"),
            ISC_OBF_NSSTRING("WeeLoader"),
            ISC_OBF_NSSTRING("Cephei"),
            ISC_OBF_NSSTRING("AppSyncUnified"),
            // Jailbreak-detection bypass tweaks
            ISC_OBF_NSSTRING("ABypass"),
            ISC_OBF_NSSTRING("FlyJB"),
            ISC_OBF_NSSTRING("/Shadow.dylib"),
        ];
    });
    return names;
}

/// Files that only a jailbreak-detection bypass tool installs. Someone running one is actively hiding
/// the device's state from apps, which is a stronger signal than the jailbreak itself.
static NSArray<NSString *> *ISCBuiltInBypassToolPaths(void) {
    static NSArray<NSString *> *paths;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        paths = @[
            // A-Bypass
            ISC_OBF_NSSTRING("/usr/lib/ABDYLD.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/ABSubLoader.dylib"),
            ISC_OBF_NSSTRING("/Library/BawAppie/ABypass"),
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/ABypassPrefs.bundle"),
            ISC_OBF_NSSTRING("/var/mobile/Library/Preferences/ABPattern"),
            // FlyJB
            ISC_OBF_NSSTRING("/Applications/FlyJB.app"),
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/FlyJBPrefs.bundle"),
            // Shadow
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/ShadowPreferences.bundle"),
            ISC_OBF_NSSTRING("/var/mobile/Library/Preferences/me.jjolano.shadow.plist"),
            // Liberty
            ISC_OBF_NSSTRING("/Library/PreferenceBundles/LibertyPref.bundle"),
        ];
    });
    return paths;
}

/// Objective-C classes that only a bypass tool registers. A tweak can hide its library from the
/// loaded-image list and its files from `access(2)`, but not its classes from the runtime.
static NSArray<NSString *> *ISCBuiltInBypassToolClasses(void) {
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = @[
            ISC_OBF_NSSTRING("ShadowRuleset"),
        ];
    });
    return names;
}

/// Loopback ports nothing listens on in a stock iOS install: OpenSSH (22) and checkra1n's shell (44).
static const uint16_t ISCRemoteShellPorts[] = {22, 44};

// MARK: - Probes

/// `DYLD_INSERT_LIBRARIES` entries that Xcode and Instruments add legitimately while debugging.
static BOOL ISCIsDeveloperToolingInjection(NSString *entry) {
    static NSArray<NSString *> *prefixes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        prefixes = @[
            @"/Developer/",
            @"/System/Developer/",
            @"/usr/lib/libMainThreadChecker",
            @"/usr/lib/libgmalloc",
            @"/usr/lib/libBacktraceRecording",
        ];
    });
    for (NSString *prefix in prefixes) {
        if ([entry hasPrefix:prefix]) {
            return YES;
        }
    }
    return NO;
}

/// The first `DYLD_INSERT_LIBRARIES` entry that is not developer tooling, or nil.
static NSString *ISCFirstSuspiciousInjectedLibrary(void) {
    ISC_OBF_CSTRING(variableName, "DYLD_INSERT_LIBRARIES");
    const char *value = getenv(variableName);
    ISC_OBF_WIPE(variableName);
    if (value == NULL || value[0] == '\0') {
        return nil;
    }
    NSString *list = [NSString stringWithUTF8String:value];
    for (NSString *entry in [list componentsSeparatedByString:@":"]) {
        if (entry.length > 0 && !ISCIsDeveloperToolingInjection(entry)) {
            return entry;
        }
    }
    return nil;
}

/// Tries to create a file outside the app sandbox. Possible only when the sandbox is broken.
static BOOL ISCSandboxWriteSucceeds(void) {
    ISC_OBF_CSTRING(prefix, "/private/.isc-");
    char path[64];
    snprintf(path, sizeof(path), "%s%08x%08x", prefix, arc4random(), arc4random());
    ISC_OBF_WIPE(prefix);

    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return NO;
    }
    close(descriptor);
    unlink(path);
    return YES;
}

typedef pid_t (*ISCForkFunction)(void);

/// `fork()` is denied by the stock iOS sandbox. A success means the sandbox is weakened.
static BOOL ISCForkSucceeds(void) {
    // Resolved at runtime so the binary carries no static reference to `fork`.
    ISC_OBF_CSTRING(symbol, "fork");
    ISCForkFunction forkFunction = (ISCForkFunction)dlsym(RTLD_DEFAULT, symbol);
    ISC_OBF_WIPE(symbol);
    if (forkFunction == NULL) {
        return NO;
    }

    pid_t child = forkFunction();
    if (child == 0) {
        // In the child: leave at once without touching the Objective-C runtime or any lock.
        _exit(0);
    }
    if (child < 0) {
        return NO;
    }

    int status = 0;
    pid_t reaped;
    do {
        reaped = waitpid(child, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    return YES;
}

/// The members of `classNames` registered with the Objective-C runtime. Blank or malformed names are skipped.
static NSArray<NSString *> *ISCRegisteredClasses(NSArray<NSString *> *classNames) {
    NSMutableArray<NSString *> *registered = [NSMutableArray array];
    for (NSString *name in classNames) {
        // objc_lookUpClass, unlike objc_getClass, never calls a class handler that could load code.
        const char *cName = ISCSafeCPath(name);
        if (cName != NULL && objc_lookUpClass(cName) != Nil) {
            [registered addObject:name];
        }
    }
    return registered;
}

/// The members of `paths` that exist. Blank or malformed entries are skipped.
static NSArray<NSString *> *ISCExistingPaths(NSArray<NSString *> *paths) {
    NSMutableArray<NSString *> *existing = [NSMutableArray array];
    for (NSString *path in paths) {
        // Configuration comes from the host app, so a blank or malformed entry must be skipped, never fatal.
        if (ISCPathExists(ISCSafeCPath(path))) {
            [existing addObject:path];
        }
    }
    return existing;
}

// MARK: - ISCJailbreakDetector

@implementation ISCJailbreakDetector

NSArray<ISCFinding *> *ISCJailbreakScan(ISCScanOptions *options) {
    if (!ISCChecksInclude(options, ISCChecksJailbreak)) {
        return @[];
    }
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];

    // 1. Known files and directories.
    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    if (options.includesBuiltInIndicators) {
        [candidates addObjectsFromArray:ISCBuiltInArtifactPaths()];
    }
    [candidates addObjectsFromArray:options.additionalSuspiciousPaths];
    NSArray<NSString *> *present = ISCExistingPaths(candidates);
    if (present.count > 0) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakArtifact, ISCSummarizeValues(present, ISCDetailLimit))];
    }

    // 2. System directories replaced by symbolic links.
    if (options.includesBuiltInIndicators) {
        NSMutableArray<NSString *> *links = [NSMutableArray array];
        for (NSString *path in ISCBuiltInSymlinkPaths()) {
            if (ISCPathIsSymbolicLink(ISCSafeCPath(path))) {
                [links addObject:path];
            }
        }
        if (links.count > 0) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakSymlink, ISCSummarizeValues(links, ISCDetailLimit))];
        }
    }

    // 3. Library injection through the environment.
    if (options.includesBuiltInIndicators) {
        NSString *injected = ISCFirstSuspiciousInjectedLibrary();
        if (injected != nil) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakInjectionEnvironment, injected)];
        }
    }

    // 4. Tweak-injection libraries that are already loaded.
    if (options.includesBuiltInIndicators) {
        NSArray<NSString *> *loaded = ISCStringsContainingAny(ISCCopyLoadedImagePaths(), ISCBuiltInInjectionLibraries());
        if (loaded.count > 0) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakInjectedLibrary, ISCSummarizeValues(loaded, ISCDetailLimit))];
        }
    }

    // 5. Sandbox escape.
    if (options.performsSandboxWriteProbe && ISCSandboxWriteSucceeds()) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakSandboxEscape, nil)];
    }

    // 6. Weakened sandbox.
    if (options.performsForkProbe && ISCForkSucceeds()) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakForkAllowed, nil)];
    }

    // 7. A remote shell listening on loopback.
    if (options.includesBuiltInIndicators && options.probesRemoteShellPorts) {
        NSMutableArray<NSString *> *open = [NSMutableArray array];
        for (size_t index = 0; index < sizeof(ISCRemoteShellPorts) / sizeof(ISCRemoteShellPorts[0]); index++) {
            if (ISCLoopbackPortIsOpen(ISCRemoteShellPorts[index], ISCPortProbeTimeoutMilliseconds)) {
                [open addObject:[NSString stringWithFormat:@"%u", (unsigned)ISCRemoteShellPorts[index]]];
            }
        }
        if (open.count > 0) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakRemoteShellPort, [open componentsJoinedByString:@", "])];
        }
    }

    // 8. A jailbreak-detection bypass tool, by its classes and its files.
    NSMutableArray<NSString *> *classNames = [NSMutableArray array];
    NSMutableArray<NSString *> *bypassPaths = [NSMutableArray array];
    if (options.includesBuiltInIndicators) {
        [classNames addObjectsFromArray:ISCBuiltInBypassToolClasses()];
        [bypassPaths addObjectsFromArray:ISCBuiltInBypassToolPaths()];
    }
    [classNames addObjectsFromArray:options.additionalSuspiciousClasses];
    NSMutableArray<NSString *> *bypass = [NSMutableArray arrayWithArray:ISCRegisteredClasses(classNames)];
    [bypass addObjectsFromArray:ISCExistingPaths(bypassPaths)];
    if (bypass.count > 0) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeJailbreakBypassTool, ISCSummarizeValues(bypass, ISCDetailLimit))];
    }

    return findings;
}

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    return ISCJailbreakScan(options);
}

+ (NSArray<NSString *> *)registeredClassesAmong:(NSArray<NSString *> *)classNames {
    return ISCRegisteredClasses(classNames);
}

+ (NSArray<NSString *> *)existingPathsAmong:(NSArray<NSString *> *)paths {
    return ISCExistingPaths(paths);
}

@end
