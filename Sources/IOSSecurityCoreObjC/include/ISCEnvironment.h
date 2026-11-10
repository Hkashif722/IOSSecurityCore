//
//  ISCEnvironment.h
//  IOSSecurityCoreObjC
//
//  Where the process is running.
//

#import <Foundation/Foundation.h>
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// Describes the platform the process runs on. The detectors only produce meaningful results on a
/// real iOS device, so the scanner consults this first.
ISC_RN_ENVIRONMENT
@interface ISCEnvironment : NSObject

/// `YES` when compiled for the iOS Simulator.
@property (class, nonatomic, readonly) BOOL isSimulator;

/// `YES` when running as a Mac Catalyst app.
@property (class, nonatomic, readonly) BOOL isMacCatalystApp;

/// `YES` when an iOS app runs on an Apple silicon Mac ("Designed for iPad/iPhone").
@property (class, nonatomic, readonly) BOOL isiOSAppOnMac;

/// `YES` on a physical iPhone or iPad: not the Simulator, not a Mac, not Catalyst.
@property (class, nonatomic, readonly) BOOL isSupportedDevicePlatform;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
