//
//  ISCNetworkDetector.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCNetworkDetector.h"
#import "ISCDetector.h"
#import "ISCObfuscation.h"

#import <CFNetwork/CFNetwork.h>

typedef NS_OPTIONS(NSUInteger, ISCProxyKind) {
    ISCProxyKindHTTP = 1 << 0,
    ISCProxyKindHTTPS = 1 << 1,
    ISCProxyKindSOCKS = 1 << 2,
    ISCProxyKindAutoConfiguration = 1 << 3,
};

/// A settings flag. CFNetwork stores them as numbers; profiles have been seen to use strings.
static BOOL ISCSettingIsEnabled(id value) {
    if ([value isKindOfClass:NSNumber.class]) {
        return [value boolValue];
    }
    if ([value isKindOfClass:NSString.class]) {
        return [value integerValue] != 0;
    }
    return NO;
}

static BOOL ISCSettingHasText(id value) {
    return [value isKindOfClass:NSString.class] &&
           [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length > 0;
}

/// The kinds one settings dictionary (primary or per-interface) turns on. The key names are the
/// documented `kCFNetworkProxies…` values; literals are used because the HTTPS and SOCKS constants
/// are not declared for iOS although iOS reports them.
static ISCProxyKind ISCProxyKindsInDictionary(id settings) {
    if (![settings isKindOfClass:NSDictionary.class]) {
        return 0;
    }
    NSDictionary *dictionary = settings;
    ISCProxyKind kinds = 0;
    if (ISCSettingIsEnabled(dictionary[ISC_OBF_NSSTRING("HTTPEnable")]) &&
        ISCSettingHasText(dictionary[ISC_OBF_NSSTRING("HTTPProxy")])) {
        kinds |= ISCProxyKindHTTP;
    }
    if (ISCSettingIsEnabled(dictionary[ISC_OBF_NSSTRING("HTTPSEnable")]) &&
        ISCSettingHasText(dictionary[ISC_OBF_NSSTRING("HTTPSProxy")])) {
        kinds |= ISCProxyKindHTTPS;
    }
    if (ISCSettingIsEnabled(dictionary[ISC_OBF_NSSTRING("SOCKSEnable")]) &&
        ISCSettingHasText(dictionary[ISC_OBF_NSSTRING("SOCKSProxy")])) {
        kinds |= ISCProxyKindSOCKS;
    }
    BOOL autoConfiguration =
        ISCSettingIsEnabled(dictionary[ISC_OBF_NSSTRING("ProxyAutoConfigEnable")]) &&
        (ISCSettingHasText(dictionary[ISC_OBF_NSSTRING("ProxyAutoConfigURLString")]) ||
         ISCSettingHasText(dictionary[ISC_OBF_NSSTRING("ProxyAutoConfigJavaScript")]));
    if (autoConfiguration || ISCSettingIsEnabled(dictionary[ISC_OBF_NSSTRING("ProxyAutoDiscoveryEnable")])) {
        kinds |= ISCProxyKindAutoConfiguration;
    }
    return kinds;
}

static NSArray<NSString *> *ISCProxyKindsInSettings(NSDictionary *settings) {
    ISCProxyKind kinds = ISCProxyKindsInDictionary(settings);
    id scoped = [settings isKindOfClass:NSDictionary.class] ? settings[ISC_OBF_NSSTRING("__SCOPED__")] : nil;
    if ([scoped isKindOfClass:NSDictionary.class]) {
        for (id interface in (NSDictionary *)scoped) {
            kinds |= ISCProxyKindsInDictionary(((NSDictionary *)scoped)[interface]);
        }
    }

    NSMutableArray<NSString *> *names = [NSMutableArray array];
    if (kinds & ISCProxyKindHTTP) {
        [names addObject:@"http"];
    }
    if (kinds & ISCProxyKindHTTPS) {
        [names addObject:@"https"];
    }
    if (kinds & ISCProxyKindSOCKS) {
        [names addObject:@"socks"];
    }
    if (kinds & ISCProxyKindAutoConfiguration) {
        [names addObject:@"pac"];
    }
    return names;
}

static NSArray<NSString *> *ISCConfiguredProxyKinds(void) {
    CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
    if (settings == NULL) {
        return @[];
    }
    return ISCProxyKindsInSettings(CFBridgingRelease(settings));
}

// MARK: - ISCNetworkDetector

@interface ISCNetworkDetector () <ISCDetector>
@end

@implementation ISCNetworkDetector

+ (ISCChecks)check {
    return ISCChecksNetwork;
}

+ (NSArray<NSString *> *)configuredProxyKinds {
    return ISCConfiguredProxyKinds();
}

+ (NSArray<NSString *> *)proxyKindsInSettings:(NSDictionary *)settings {
    return ISCProxyKindsInSettings(settings);
}

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    if (!ISCDetectorIsEnabled(self, options)) {
        return @[];
    }
    NSArray<NSString *> *kinds = ISCConfiguredProxyKinds();
    if (kinds.count == 0) {
        return @[];
    }
    return @[[[ISCFinding alloc] initWithCode:ISCFindingCodeNetworkProxy
                                       detail:[kinds componentsJoinedByString:@", "]]];
}

@end
