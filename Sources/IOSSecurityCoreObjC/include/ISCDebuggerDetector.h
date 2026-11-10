//
//  ISCDebuggerDetector.h
//  IOSSecurityCoreObjC
//
//  Detects an attached debugger.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// Debugger detection based on the technique Apple documents in Technical Q&A QA1361: ask the kernel
/// whether the process carries the `P_TRACED` flag.
///
/// Debuggers attach at any time, so call this periodically rather than once at launch. During
/// development an attached debugger is normal; gate enforcement on release builds.
ISC_RN_DEBUGGER_DETECTOR
@interface ISCDebuggerDetector : NSObject

/// `YES` while a debugger (LLDB, Frida in debugger mode, ...) is attached to this process.
@property (class, nonatomic, readonly) BOOL isDebuggerAttached;

/// Runs the debugger check enabled in `options`.
+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options;

/// Asks the kernel to refuse any future debugger attachment (`PT_DENY_ATTACH`).
///
/// **This is not detection, it is a countermeasure with consequences:**
/// - If a debugger is *already attached*, the kernel terminates the process immediately.
/// - Xcode, Instruments and LLDB can no longer attach, so never call it in debug or QA builds.
/// - A jailbroken attacker can still hook the call, so do not rely on it alone.
///
/// The symbol is resolved with `dlsym` at runtime, so the binary has no static reference to `ptrace`.
///
/// - Returns: `YES` if the request was accepted.
+ (BOOL)denyDebuggerAttachment;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
