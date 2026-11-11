//
//  ISCEnvironment.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCEnvironment.h"
#import "ISCPlatform.h"

#import <TargetConditionals.h>

BOOL ISCPlatformIsSimulator(void) {
#if TARGET_OS_SIMULATOR
    return YES;
#else
    return NO;
#endif
}

BOOL ISCPlatformIsMacCatalyst(void) {
#if TARGET_OS_MACCATALYST
    return YES;
#else
    return NO;
#endif
}

BOOL ISCPlatformIsiOSAppOnMac(void) {
#if TARGET_OS_IOS && !TARGET_OS_MACCATALYST
    return NSProcessInfo.processInfo.isiOSAppOnMac;
#else
    return NO;
#endif
}

BOOL ISCPlatformIsSupportedDevice(void) {
#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR && !TARGET_OS_MACCATALYST
    return !ISCPlatformIsiOSAppOnMac();
#else
    return NO;
#endif
}

@implementation ISCEnvironment

+ (BOOL)isSimulator {
    return ISCPlatformIsSimulator();
}

+ (BOOL)isMacCatalystApp {
    return ISCPlatformIsMacCatalyst();
}

+ (BOOL)isiOSAppOnMac {
    return ISCPlatformIsiOSAppOnMac();
}

+ (BOOL)isSupportedDevicePlatform {
    return ISCPlatformIsSupportedDevice();
}

@end
