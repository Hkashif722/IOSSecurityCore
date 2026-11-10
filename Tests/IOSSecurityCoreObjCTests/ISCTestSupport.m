//
//  ISCTestSupport.m
//  IOSSecurityCoreObjCTests
//

#import "ISCTestSupport.h"

ISCScanOptions *ISCTestOptions(void) {
    ISCScanOptions *options = [ISCScanOptions defaultOptions];
    options.includesBuiltInIndicators = NO;
    options.scansUnsupportedEnvironments = YES;
    options.performsSandboxWriteProbe = NO;
    options.performsForkProbe = NO;
    options.probesInstrumentationPorts = NO;
    options.reportsUnknownLibraries = NO;
    return options;
}

BOOL ISCContainsCode(NSArray<ISCFinding *> *findings, ISCFindingCode code) {
    return ISCFindingWithCode(findings, code) != nil;
}

ISCFinding *ISCFindingWithCode(NSArray<ISCFinding *> *findings, ISCFindingCode code) {
    for (ISCFinding *finding in findings) {
        if (finding.code == code) {
            return finding;
        }
    }
    return nil;
}

static void ISCAppendBigEndian32(NSMutableData *data, uint32_t value) {
    uint32_t big = CFSwapInt32HostToBig(value);
    [data appendBytes:&big length:sizeof(big)];
}

NSData *ISCMakeSignatureBlob(NSDictionary<NSString *, id> *entitlements) {
    NSData *plist = [NSPropertyListSerialization dataWithPropertyList:entitlements
                                                               format:NSPropertyListXMLFormat_v1_0
                                                              options:0
                                                                error:NULL];

    // Slot 0 stands in for the code directory; the parser must skip it.
    NSMutableData *codeDirectory = [NSMutableData data];
    ISCAppendBigEndian32(codeDirectory, 0xfade0c02);
    ISCAppendBigEndian32(codeDirectory, 16);
    ISCAppendBigEndian32(codeDirectory, 0);
    ISCAppendBigEndian32(codeDirectory, 0);

    NSMutableData *entitlementsBlob = [NSMutableData data];
    ISCAppendBigEndian32(entitlementsBlob, 0xfade7171);
    ISCAppendBigEndian32(entitlementsBlob, (uint32_t)(8 + plist.length));
    [entitlementsBlob appendData:plist];

    uint32_t indexSize = 12 + 2 * 8;
    uint32_t codeDirectoryOffset = indexSize;
    uint32_t entitlementsOffset = codeDirectoryOffset + (uint32_t)codeDirectory.length;
    uint32_t totalLength = entitlementsOffset + (uint32_t)entitlementsBlob.length;

    NSMutableData *blob = [NSMutableData data];
    ISCAppendBigEndian32(blob, 0xfade0cc0);
    ISCAppendBigEndian32(blob, totalLength);
    ISCAppendBigEndian32(blob, 2);
    ISCAppendBigEndian32(blob, 0); // CSSLOT_CODEDIRECTORY
    ISCAppendBigEndian32(blob, codeDirectoryOffset);
    ISCAppendBigEndian32(blob, 5); // CSSLOT_ENTITLEMENTS
    ISCAppendBigEndian32(blob, entitlementsOffset);
    [blob appendData:codeDirectory];
    [blob appendData:entitlementsBlob];
    return blob;
}
