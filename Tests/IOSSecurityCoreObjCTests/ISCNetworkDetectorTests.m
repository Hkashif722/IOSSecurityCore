//
//  ISCNetworkDetectorTests.m
//  IOSSecurityCoreObjCTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

@interface ISCNetworkDetectorTests : XCTestCase
@end

@implementation ISCNetworkDetectorTests

// MARK: - Parsing

- (void)testNoSettingsMeansDirect {
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:nil], @[]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:@{}], @[]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"HTTPEnable": @0, @"ExceptionsList": @[]})], @[]);
}

- (void)testAnEnabledHTTPProxyWithAServerIsReported {
    NSDictionary *settings = @{@"HTTPEnable": @1, @"HTTPProxy": @"192.168.1.20", @"HTTPPort": @8888};
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:settings], @[@"http"]);
}

- (void)testAProxyNeedsBothTheFlagAndAServer {
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"HTTPEnable": @0, @"HTTPProxy": @"proxy"})], @[]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"HTTPEnable": @1, @"HTTPProxy": @""})], @[]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"HTTPEnable": @1, @"HTTPProxy": @"  \n"})], @[]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"HTTPEnable": @1})], @[]);
}

- (void)testEveryKindIsReportedInAStableOrder {
    NSDictionary *settings = @{
        @"ProxyAutoConfigEnable": @1, @"ProxyAutoConfigURLString": @"http://wpad/proxy.pac",
        @"SOCKSEnable": @1, @"SOCKSProxy": @"socks",
        @"HTTPSEnable": @1, @"HTTPSProxy": @"secure",
        @"HTTPEnable": @1, @"HTTPProxy": @"plain",
    };
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:settings], (@[@"http", @"https", @"socks", @"pac"]));
}

- (void)testAutoConfigurationCountsWithAURLAScriptOrDiscovery {
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"ProxyAutoConfigEnable": @1,
                                                                      @"ProxyAutoConfigURLString": @"http://x/p.pac"})],
                          @[@"pac"]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"ProxyAutoConfigEnable": @1,
                                                                      @"ProxyAutoConfigJavaScript": @"function FindProxyForURL(){}"})],
                          @[@"pac"]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"ProxyAutoDiscoveryEnable": @1})], @[@"pac"]);
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"ProxyAutoConfigEnable": @1})], @[],
                          @"auto-config switched on with nothing to load configures nothing");
}

- (void)testInterfaceScopedProxiesCount {
    // A VPN can carry its own proxy, reported only under its interface.
    NSDictionary *settings = @{@"__SCOPED__": @{
        @"en0": @{@"HTTPEnable": @0},
        @"utun3": @{@"HTTPSEnable": @1, @"HTTPSProxy": @"10.8.0.1"},
    }};
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:settings], @[@"https"]);
}

- (void)testMalformedValuesAreIgnoredNotRaisedOn {
    XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:(@{@"HTTPEnable": @"1", @"HTTPProxy": @"proxy"})],
                          @[@"http"], @"a flag stored as a string still counts");
    NSArray<NSDictionary *> *hostile = @[
        @{@"HTTPEnable": NSNull.null, @"HTTPProxy": @42},
        @{@"HTTPEnable": @[@1], @"HTTPProxy": @{}},
        @{@"__SCOPED__": @[@1, @2]},
        @{@"__SCOPED__": @{@1: @"not a dictionary", NSNull.null: @{@"HTTPEnable": @"yes?"}}},
        @{@42: @42},
    ];
    for (NSDictionary *settings in hostile) {
        XCTAssertNoThrow([ISCNetworkDetector proxyKindsInSettings:settings]);
        XCTAssertEqualObjects([ISCNetworkDetector proxyKindsInSettings:settings], @[], @"%@", settings);
    }
    id notADictionary = @[@"HTTPEnable", @1];
    XCTAssertNoThrow([ISCNetworkDetector proxyKindsInSettings:notADictionary]);
}

// MARK: - Scan

- (void)testTheScanReportsWhatTheSystemIsConfiguredWith {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksNetwork;
    NSArray<NSString *> *kinds = ISCNetworkDetector.configuredProxyKinds;
    NSArray<ISCFinding *> *findings = [ISCNetworkDetector scanWithOptions:options];

    ISCFinding *finding = ISCFindingWithCode(findings, ISCFindingCodeNetworkProxy);
    if (kinds.count == 0) {
        XCTAssertEqual(findings.count, 0u);
    } else {
        XCTAssertNotNil(finding);
        XCTAssertEqual(finding.severity, ISCSeverityMedium, @"proxies are legitimate on managed networks");
        XCTAssertEqual(finding.category, ISCCategoryNetwork);
        XCTAssertEqualObjects(finding.detail, [kinds componentsJoinedByString:@", "],
                              @"the detail names the kind of proxy, never its address");
    }
}

- (void)testTheScanHonoursTheCheckSelection {
    ISCScanOptions *options = ISCTestOptions();
    options.checks = ISCChecksAll & ~ISCChecksNetwork;
    XCTAssertEqual([ISCNetworkDetector scanWithOptions:options].count, 0u);
}

@end
