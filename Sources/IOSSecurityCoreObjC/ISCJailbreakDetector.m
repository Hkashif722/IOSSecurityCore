//
//  ISCJailbreakDetector.m
//  IOSSecurityCoreObjC
//

#import "ISCJailbreakDetector.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

/// How many matches a finding's `detail` spells out before summarizing.
static const NSUInteger ISCDetailLimit = 5;

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
            ISC_OBF_NSSTRING("/usr/lib/libsubstrate.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libsubstitute.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/substitute-inserter.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libhooker.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libellekit.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/TweakInject"),
            ISC_OBF_NSSTRING("/usr/lib/TweakInject.dylib"),
            ISC_OBF_NSSTRING("/usr/lib/libcycript.dylib"),

            // Remote shells and package tooling
            ISC_OBF_NSSTRING("/bin/bash"),
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
            ISC_OBF_NSSTRING("rocketbootstrap"),
            ISC_OBF_NSSTRING("pspawn_payload"),
            ISC_OBF_NSSTRING("ABypass"),
            ISC_OBF_NSSTRING("FlyJB"),
        ];
    });
    return names;
}

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

// MARK: - ISCJailbreakDetector

@implementation ISCJailbreakDetector

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];

    // 1. Known files and directories.
    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    if (options.includesBuiltInIndicators) {
        [candidates addObjectsFromArray:ISCBuiltInArtifactPaths()];
    }
    [candidates addObjectsFromArray:options.additionalSuspiciousPaths];
    NSArray<NSString *> *present = [self existingPathsAmong:candidates];
    if (present.count > 0) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakArtifact
                                                      detail:ISCSummarizeValues(present, ISCDetailLimit)]];
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
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakSymlink
                                                          detail:ISCSummarizeValues(links, ISCDetailLimit)]];
        }
    }

    // 3. Library injection through the environment.
    if (options.includesBuiltInIndicators) {
        NSString *injected = ISCFirstSuspiciousInjectedLibrary();
        if (injected != nil) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakInjectionEnvironment
                                                          detail:injected]];
        }
    }

    // 4. Tweak-injection libraries that are already loaded.
    if (options.includesBuiltInIndicators) {
        NSArray<NSString *> *loaded = ISCStringsContainingAny(ISCCopyLoadedImagePaths(), ISCBuiltInInjectionLibraries());
        if (loaded.count > 0) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakInjectedLibrary
                                                          detail:ISCSummarizeValues(loaded, ISCDetailLimit)]];
        }
    }

    // 5. Sandbox escape.
    if (options.performsSandboxWriteProbe && ISCSandboxWriteSucceeds()) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakSandboxEscape detail:nil]];
    }

    // 6. Weakened sandbox.
    if (options.performsForkProbe && ISCForkSucceeds()) {
        [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeJailbreakForkAllowed detail:nil]];
    }

    return findings;
}

+ (NSArray<NSString *> *)existingPathsAmong:(NSArray<NSString *> *)paths {
    NSMutableArray<NSString *> *existing = [NSMutableArray array];
    for (NSString *path in paths) {
        // Configuration comes from the host app, so a blank or malformed entry must be skipped, never fatal.
        if (ISCPathExists(ISCSafeCPath(path))) {
            [existing addObject:path];
        }
    }
    return existing;
}

@end
