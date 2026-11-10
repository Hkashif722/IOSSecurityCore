//
//  ISCEnvironment.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCEnvironment.h"

#import <TargetConditionals.h>

@implementation ISCEnvironment

+ (BOOL)isSimulator {
#if TARGET_OS_SIMULATOR
    return YES;
#else
    return NO;
#endif
}

+ (BOOL)isMacCatalystApp {
#if TARGET_OS_MACCATALYST
    return YES;
#else
    return NO;
#endif
}

+ (BOOL)isiOSAppOnMac {
#if TARGET_OS_IOS && !TARGET_OS_MACCATALYST
    return NSProcessInfo.processInfo.isiOSAppOnMac;
#else
    return NO;
#endif
}

+ (BOOL)isSupportedDevicePlatform {
#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR && !TARGET_OS_MACCATALYST
    return !self.isiOSAppOnMac;
#else
    return NO;
#endif
}

@end
