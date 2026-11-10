//
//  ISCTestSupport.m
//  IOSSecurityCoreObjCTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCTestSupport.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int ISCOpenLoopbackListener(uint16_t port) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return -1;
    }
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 4) != 0) {
        close(listener);
        return -1;
    }
    return listener;
}

ISCScanOptions *ISCTestOptions(void) {
    ISCScanOptions *options = [ISCScanOptions defaultOptions];
    options.includesBuiltInIndicators = NO;
    options.scansUnsupportedEnvironments = YES;
    options.performsSandboxWriteProbe = NO;
    options.performsForkProbe = NO;
    options.probesInstrumentationPorts = NO;
    options.probesRemoteShellPorts = NO;
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
