//
//  IOSSecurityCoreObjC.h
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Umbrella header for the Objective-C runtime layer of IOSSecurityCore.
//
//  Everything here is built on documented Apple APIs (Foundation, <objc/runtime.h>, <dlfcn.h>, dyld,
//  Mach, CommonCrypto). There is no private API, so apps that ship it stay App Store safe.
//

#import <Foundation/Foundation.h>

#import "ISCObfuscationConfig.h"
#import "ISCObfuscation.h"
#import "ISCTypes.h"
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCEnvironment.h"
#import "ISCJailbreakDetector.h"
#import "ISCDebuggerDetector.h"
#import "ISCHookDetector.h"
#import "ISCIntegrityChecker.h"
#import "ISCNetworkDetector.h"
#import "ISCSecurityScanner.h"
