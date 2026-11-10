//
//  ISCFinding.h
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  The value types a scan produces.
//

#import <Foundation/Foundation.h>
#import "ISCTypes.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// One thing a detector noticed about the runtime environment.
///
/// Findings are immutable. `category`, `severity` and `identifier` are derived from `code`, so they
/// can never disagree with it.
ISC_RN_FINDING
@interface ISCFinding : NSObject <NSCopying>

/// What was found. Stable across releases.
@property (nonatomic, readonly) ISCFindingCode code;

/// The detector family that produced the finding.
@property (nonatomic, readonly) ISCCategory category;

/// How seriously to take it.
@property (nonatomic, readonly) ISCSeverity severity;

/// Dotted, stable, machine-readable name, for example `jailbreak.artifact`. Suitable for analytics.
@property (nonatomic, copy, readonly) NSString *identifier;

/// Human-readable specifics (the matching path, library or selector). For logs and diagnostics only:
/// do not show it to end users and do not parse it.
@property (nonatomic, copy, readonly, nullable) NSString *detail;

- (instancetype)initWithCode:(ISCFindingCode)code
                      detail:(nullable NSString *)detail NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

/// The outcome of one `ISCSecurityScanner` run.
ISC_RN_SCAN_RESULT
@interface ISCScanResult : NSObject

/// Everything that was found, most severe first.
@property (nonatomic, copy, readonly) NSArray<ISCFinding *> *findings;

/// The detector families that actually ran. Empty when the environment is unsupported (Simulator,
/// macOS, ...) and the scan was skipped.
@property (nonatomic, readonly) ISCChecks performedChecks;

/// When the scan started.
@property (nonatomic, copy, readonly) NSDate *startedAt;

/// How long the scan took, in seconds.
@property (nonatomic, readonly) NSTimeInterval duration;

/// `YES` when at least one finding is `ISCSeverityHigh` or `ISCSeverityCritical`.
@property (nonatomic, readonly) BOOL isCompromised;

- (instancetype)initWithFindings:(NSArray<ISCFinding *> *)findings
                  performedChecks:(ISCChecks)performedChecks
                        startedAt:(NSDate *)startedAt
                         duration:(NSTimeInterval)duration NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
