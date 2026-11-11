//
//  ISCPlatform.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Where the process runs, as plain C. The scanner gates on this before anything else, so it must not
//  go through a method a swizzle could replace. `ISCEnvironment` exposes the same answers publicly.
//

#import <Foundation/Foundation.h>
#import "ISCVisibility.h"

NS_ASSUME_NONNULL_BEGIN


ISC_HIDDEN BOOL ISCPlatformIsSimulator(void);
ISC_HIDDEN BOOL ISCPlatformIsMacCatalyst(void);
ISC_HIDDEN BOOL ISCPlatformIsiOSAppOnMac(void);

/// A physical iPhone or iPad: not the Simulator, not a Mac, not Catalyst.
ISC_HIDDEN BOOL ISCPlatformIsSupportedDevice(void);

NS_ASSUME_NONNULL_END
