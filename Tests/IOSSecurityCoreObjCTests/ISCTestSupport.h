//
//  ISCTestSupport.h
//  IOSSecurityCoreObjCTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Helpers shared by the Objective-C tests.
//

#import <Foundation/Foundation.h>

@import IOSSecurityCoreObjC;

NS_ASSUME_NONNULL_BEGIN

/// Options that examine only what a test supplies: no built-in lists, no probes with side effects, and
/// no platform gating. Every test starts from these so results do not depend on the machine running them.
ISCScanOptions *ISCTestOptions(void);

/// Opens a TCP listener on loopback `port`. Returns the descriptor, or -1 when the port cannot be
/// bound (in use, or privileged on this machine). Close it with `close(2)`.
int ISCOpenLoopbackListener(uint16_t port);

/// Whether `findings` contains a finding with `code`.
BOOL ISCContainsCode(NSArray<ISCFinding *> *findings, ISCFindingCode code);

/// The first finding with `code`, or nil.
ISCFinding *_Nullable ISCFindingWithCode(NSArray<ISCFinding *> *findings, ISCFindingCode code);

/// A well-formed code-signature SuperBlob carrying `entitlements` in the XML-entitlements slot (plus an
/// unrelated slot before it, as real signatures have).
NSData *ISCMakeSignatureBlob(NSDictionary<NSString *, id> *entitlements);

/// A SuperBlob with an XML entitlements slot (5) for `xmlEntitlements` and a DER slot (7) for
/// `derEntitlements`. Pass nil to leave either slot out. Slot order: code directory, XML, DER.
NSData *ISCMakeSignatureBlobWithSlots(NSDictionary<NSString *, id> *_Nullable xmlEntitlements,
                                      NSDictionary<NSString *, id> *_Nullable derEntitlements);

/// The same, from raw payloads, for feeding the parser deliberately damaged bytes.
NSData *ISCMakeSignatureBlobWithPayloads(NSData *_Nullable xmlPayload, NSData *_Nullable derPayload);

/// `entitlements` in Apple's DER form: `[APPLICATION 16] { INTEGER 1, SET { SEQUENCE { key, value } } }`.
/// Supports strings, booleans, integers, data, arrays and dictionaries.
NSData *ISCMakeDEREntitlementsPayload(NSDictionary<NSString *, id> *entitlements);

NS_ASSUME_NONNULL_END
