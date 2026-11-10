//
//  ISCScanOptions.m
//  IOSSecurityCoreObjC
//

#import "ISCScanOptions.h"

// MARK: - ISCProtectedMethod

@implementation ISCProtectedMethod

- (instancetype)initWithTargetClassName:(NSString *)targetClassName
                           selectorName:(NSString *)selectorName
                          isClassMethod:(BOOL)isClassMethod
               allowedImagePathPrefixes:(NSArray<NSString *> *)allowedImagePathPrefixes {
    self = [super init];
    if (self != nil) {
        _targetClassName = [targetClassName copy];
        _selectorName = [selectorName copy];
        _isClassMethod = isClassMethod;
        _allowedImagePathPrefixes = [allowedImagePathPrefixes copy];
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    return self; // immutable
}

@end

// MARK: - ISCScanOptions

@implementation ISCScanOptions

+ (instancetype)defaultOptions {
    return [[self alloc] init];
}

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _checks = ISCChecksAll;
        _includesBuiltInIndicators = YES;
        _scansUnsupportedEnvironments = NO;

        _additionalSuspiciousPaths = @[];
        _performsSandboxWriteProbe = YES;
        _performsForkProbe = YES;
        _additionalSuspiciousClasses = @[];
        _probesRemoteShellPorts = YES;

        _additionalSuspiciousLibraries = @[];
        _allowedImagePathPrefixes = @[];
        _reportsUnknownLibraries = YES;
        _allowedBundleLibraries = @[];
        _probesInstrumentationPorts = YES;
        _protectedMethods = @[];

        _expectedBundleIdentifier = nil;
        _expectedTeamIdentifier = nil;
        _expectedTextSegmentDigests = @[];
        _expectedImageTextDigests = @{};
        _expectedDistribution = ISCDistributionAny;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    ISCScanOptions *copy = [[[self class] allocWithZone:zone] init];
    copy.checks = self.checks;
    copy.includesBuiltInIndicators = self.includesBuiltInIndicators;
    copy.scansUnsupportedEnvironments = self.scansUnsupportedEnvironments;

    copy.additionalSuspiciousPaths = self.additionalSuspiciousPaths;
    copy.performsSandboxWriteProbe = self.performsSandboxWriteProbe;
    copy.performsForkProbe = self.performsForkProbe;
    copy.additionalSuspiciousClasses = self.additionalSuspiciousClasses;
    copy.probesRemoteShellPorts = self.probesRemoteShellPorts;

    copy.additionalSuspiciousLibraries = self.additionalSuspiciousLibraries;
    copy.allowedImagePathPrefixes = self.allowedImagePathPrefixes;
    copy.reportsUnknownLibraries = self.reportsUnknownLibraries;
    copy.allowedBundleLibraries = self.allowedBundleLibraries;
    copy.probesInstrumentationPorts = self.probesInstrumentationPorts;
    copy.protectedMethods = self.protectedMethods;

    copy.expectedBundleIdentifier = self.expectedBundleIdentifier;
    copy.expectedTeamIdentifier = self.expectedTeamIdentifier;
    copy.expectedTextSegmentDigests = self.expectedTextSegmentDigests;
    copy.expectedImageTextDigests = self.expectedImageTextDigests;
    copy.expectedDistribution = self.expectedDistribution;
    return copy;
}

@end
