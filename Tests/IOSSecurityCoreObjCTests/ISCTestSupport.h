//
//  ISCTestSupport.h
//  IOSSecurityCoreObjCTests
//
//  Helpers shared by the Objective-C tests.
//

#import <Foundation/Foundation.h>

@import IOSSecurityCoreObjC;

NS_ASSUME_NONNULL_BEGIN

/// Options that examine only what a test supplies: no built-in lists, no probes with side effects, and
/// no platform gating. Every test starts from these so results do not depend on the machine running them.
ISCScanOptions *ISCTestOptions(void);

/// Whether `findings` contains a finding with `code`.
BOOL ISCContainsCode(NSArray<ISCFinding *> *findings, ISCFindingCode code);

/// The first finding with `code`, or nil.
ISCFinding *_Nullable ISCFindingWithCode(NSArray<ISCFinding *> *findings, ISCFindingCode code);

/// A well-formed code-signature SuperBlob carrying `entitlements` in the XML-entitlements slot (plus an
/// unrelated slot before it, as real signatures have).
NSData *ISCMakeSignatureBlob(NSDictionary<NSString *, id> *entitlements);

NS_ASSUME_NONNULL_END
