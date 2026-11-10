//
//  ISCNetworkDetector.h
//  IOSSecurityCoreObjC
//
//  Detects traffic interception.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// Detects a configured proxy, the usual way traffic is routed through an interception tool (Charles,
/// Burp Suite, mitmproxy) to be read or modified.
///
/// Reads the system configuration with `CFNetworkCopySystemProxySettings`: HTTP, HTTPS and SOCKS proxies
/// and automatic configuration (a PAC URL or script, or WPAD discovery), for the primary network and for
/// every interface-scoped configuration such as a VPN's. Corporate, school and some carrier networks set
/// proxies legitimately, so the finding is `ISCSeverityMedium`: pin your certificates, and use this as
/// context for a server-side decision.
///
/// The finding names the kind of proxy, never its address.
///
/// All methods are thread-safe and synchronous. Do not call them on the main thread.
ISC_RN_NETWORK_DETECTOR
@interface ISCNetworkDetector : NSObject

/// Runs the network checks enabled in `options` and returns what they found.
+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options;

/// The kinds of proxy configured on this device right now: any of `http`, `https`, `socks` and `pac`,
/// in that order. Empty when traffic goes direct.
@property (class, nonatomic, readonly) NSArray<NSString *> *configuredProxyKinds;

/// The kinds of proxy a dictionary in the format `CFNetworkCopySystemProxySettings` returns turns on,
/// including its `__SCOPED__` per-interface entries. A kind counts only when it is enabled and names a
/// server (for `pac`: a URL, a script, or discovery). Malformed values are ignored, never raised on.
+ (NSArray<NSString *> *)proxyKindsInSettings:(nullable NSDictionary *)settings;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
