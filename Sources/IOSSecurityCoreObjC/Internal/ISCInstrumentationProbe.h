//
//  ISCInstrumentationProbe.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Looks for dynamic-instrumentation frameworks (Frida, Cycript, SSL Kill Switch) in the process.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"

NS_ASSUME_NONNULL_BEGIN

/// Findings for instrumentation frameworks, given the paths of every loaded image:
/// - a loaded library matching the built-in names or `options.additionalSuspiciousLibraries`;
/// - with built-in indicators on: `frida-server` on disk, a listener on its loopback port (when
///   `options.probesInstrumentationPorts`), and the threads its agent starts.
NSArray<ISCFinding *> *ISCInstrumentationFindings(NSArray<NSString *> *loadedImages, ISCScanOptions *options);

NS_ASSUME_NONNULL_END
