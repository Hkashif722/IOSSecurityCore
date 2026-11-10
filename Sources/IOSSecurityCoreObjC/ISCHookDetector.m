//
//  ISCHookDetector.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Orchestrates the hooking probes (see Internal/) and owns the two that are about images in this
//  process: libraries from unexpected places, and methods the host asked to be watched.
//

#import "ISCHookDetector.h"
#import "ISCCodeTrust.h"
#import "ISCDetector.h"
#import "ISCInstrumentationProbe.h"
#import "ISCRuntimeSupport.h"
#import "ISCSelfIntegrityProbe.h"
#import "ISCSystemFunctionProbe.h"

#import <objc/runtime.h>

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

// MARK: - ISCHookDetector

@interface ISCHookDetector () <ISCDetector>
@end

@implementation ISCHookDetector

+ (ISCChecks)check {
    return ISCChecksHooking;
}

+ (NSArray<NSString *> *)loadedImagePaths {
    return ISCCopyLoadedImagePaths();
}

+ (BOOL)isFunctionInlineHooked:(const void *)function {
    NSString *destination = nil;
    return ISCFunctionIsInlineHooked(function, @[], &destination);
}

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    if (!ISCDetectorIsEnabled(self, options)) {
        return @[];
    }
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];
    NSArray<NSString *> *images = ISCCopyLoadedImagePaths();

    // 1. Has someone hooked the detectors themselves, or the system functions their answers come from?
    [findings addObjectsFromArray:ISCSelfIntegrityFindings()];
    if (options.includesBuiltInIndicators) {
        [findings addObjectsFromArray:ISCSystemFunctionFindings(options.allowedImagePathPrefixes)];
    }

    // 2. Instrumentation frameworks: loaded libraries, server on disk or on loopback, agent threads.
    [findings addObjectsFromArray:ISCInstrumentationFindings(images, options)];

    // 3. Images from places no legitimate image comes from.
    if (options.includesBuiltInIndicators && options.reportsUnknownLibraries) {
        NSArray<NSString *> *unknown = ISCUnknownImages(images, options.allowedImagePathPrefixes);
        if (unknown.count > 0) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookUnknownLibrary
                                                          detail:ISCSummarizeValues(unknown, ISCDetailLimit)]];
        }
    }

    // 4. A dylib injected into the app bundle itself.
    if (options.allowedBundleLibraries.count > 0) {
        NSArray<NSString *> *unexpected = ISCUnexpectedBundleImages(images, options.allowedBundleLibraries);
        if (unexpected.count > 0) {
            [findings addObject:[[ISCFinding alloc] initWithCode:ISCFindingCodeHookUnexpectedBundleLibrary
                                                          detail:ISCSummarizeValues(unexpected, ISCDetailLimit)]];
        }
    }

    // 5. Methods the host asked us to watch.
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
        BOOL hasImage = ISCImageForAddress(ISCMethodImplementationAddress(method), &imagePath, NULL);
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
