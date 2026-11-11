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
#include <time.h>
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

// MARK: - DER encoding (CoreFoundation's property-list mapping)

static void ISCDERAppendLength(NSMutableData *data, NSUInteger length) {
    if (length < 0x80) {
        uint8_t byte = (uint8_t)length;
        [data appendBytes:&byte length:1];
        return;
    }
    int octets = 0;
    for (NSUInteger value = length; value > 0; value >>= 8) {
        octets++;
    }
    uint8_t header = (uint8_t)(0x80 | octets);
    [data appendBytes:&header length:1];
    for (int index = octets - 1; index >= 0; index--) {
        uint8_t byte = (uint8_t)(length >> (8 * index));
        [data appendBytes:&byte length:1];
    }
}

static void ISCDERAppendElement(NSMutableData *data, uint8_t tag, NSData *content) {
    [data appendBytes:&tag length:1];
    ISCDERAppendLength(data, content.length);
    [data appendData:content];
}

static NSData *ISCDEREncode(id object) {
    NSMutableData *out = [NSMutableData data];
    if ([object isKindOfClass:NSString.class]) {
        ISCDERAppendElement(out, 0x0C, [object dataUsingEncoding:NSUTF8StringEncoding]);
    } else if ([object isKindOfClass:NSNumber.class]) {
        if (CFGetTypeID((__bridge CFTypeRef)object) == CFBooleanGetTypeID()) {
            uint8_t value = [object boolValue] ? 0xFF : 0x00;
            ISCDERAppendElement(out, 0x01, [NSData dataWithBytes:&value length:1]);
        } else {
            // Minimal two's-complement big-endian encoding.
            int64_t value = [object longLongValue];
            uint8_t bytes[8];
            for (int index = 0; index < 8; index++) {
                bytes[index] = (uint8_t)((uint64_t)value >> (8 * (7 - index)));
            }
            int start = 0;
            while (start < 7 && ((bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0) ||
                                 (bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0))) {
                start++;
            }
            ISCDERAppendElement(out, 0x02, [NSData dataWithBytes:bytes + start length:(NSUInteger)(8 - start)]);
        }
    } else if ([object isKindOfClass:NSData.class]) {
        ISCDERAppendElement(out, 0x04, object);
    } else if ([object isKindOfClass:NSDate.class]) {
        // GeneralizedTime, UTC, whole seconds: "YYYYMMDDHHMMSSZ".
        time_t seconds = (time_t)[object timeIntervalSince1970];
        struct tm utc;
        gmtime_r(&seconds, &utc);
        char text[16];
        strftime(text, sizeof(text), "%Y%m%d%H%M%SZ", &utc);
        ISCDERAppendElement(out, 0x18, [NSData dataWithBytes:text length:15]);
    } else if ([object isKindOfClass:NSArray.class]) {
        NSMutableData *content = [NSMutableData data];
        for (id item in object) {
            [content appendData:ISCDEREncode(item)];
        }
        ISCDERAppendElement(out, 0x30, content);
    } else if ([object isKindOfClass:NSDictionary.class]) {
        NSMutableData *content = [NSMutableData data];
        for (NSString *key in [[object allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
            NSMutableData *entry = [NSMutableData data];
            [entry appendData:ISCDEREncode(key)];
            [entry appendData:ISCDEREncode(object[key])];
            ISCDERAppendElement(content, 0x30, entry);
        }
        ISCDERAppendElement(out, 0xB0, content); // [16]: what Apple's signing emits for a dictionary
    }
    return out;
}

NSData *ISCMakeDEREntitlementsPayload(NSDictionary<NSString *, id> *entitlements) {
    NSMutableData *content = [NSMutableData data];
    [content appendData:ISCDEREncode(@1)]; // format version
    [content appendData:ISCDEREncode(entitlements)];
    NSMutableData *payload = [NSMutableData data];
    ISCDERAppendElement(payload, 0x70, content); // [APPLICATION 16], constructed
    return payload;
}

// MARK: - Signature SuperBlobs

NSData *ISCMakeSignatureBlobWithPayloads(NSData *xmlPayload, NSData *derPayload) {
    // Slot 0 stands in for the code directory; the parser must skip it.
    NSMutableData *codeDirectory = [NSMutableData data];
    ISCAppendBigEndian32(codeDirectory, 0xfade0c02);
    ISCAppendBigEndian32(codeDirectory, 16);
    ISCAppendBigEndian32(codeDirectory, 0);
    ISCAppendBigEndian32(codeDirectory, 0);

    NSMutableArray<NSNumber *> *slots = [NSMutableArray arrayWithObject:@0]; // CSSLOT_CODEDIRECTORY
    NSMutableArray<NSData *> *blobs = [NSMutableArray arrayWithObject:codeDirectory];
    if (xmlPayload != nil) {
        NSMutableData *blob = [NSMutableData data];
        ISCAppendBigEndian32(blob, 0xfade7171);
        ISCAppendBigEndian32(blob, (uint32_t)(8 + xmlPayload.length));
        [blob appendData:xmlPayload];
        [slots addObject:@5]; // CSSLOT_ENTITLEMENTS
        [blobs addObject:blob];
    }
    if (derPayload != nil) {
        NSMutableData *blob = [NSMutableData data];
        ISCAppendBigEndian32(blob, 0xfade7172);
        ISCAppendBigEndian32(blob, (uint32_t)(8 + derPayload.length));
        [blob appendData:derPayload];
        [slots addObject:@7]; // CSSLOT_DER_ENTITLEMENTS
        [blobs addObject:blob];
    }

    uint32_t offset = (uint32_t)(12 + slots.count * 8);
    NSMutableArray<NSNumber *> *offsets = [NSMutableArray array];
    for (NSData *blob in blobs) {
        [offsets addObject:@(offset)];
        offset += (uint32_t)blob.length;
    }

    NSMutableData *superBlob = [NSMutableData data];
    ISCAppendBigEndian32(superBlob, 0xfade0cc0);
    ISCAppendBigEndian32(superBlob, offset);
    ISCAppendBigEndian32(superBlob, (uint32_t)slots.count);
    for (NSUInteger index = 0; index < slots.count; index++) {
        ISCAppendBigEndian32(superBlob, slots[index].unsignedIntValue);
        ISCAppendBigEndian32(superBlob, offsets[index].unsignedIntValue);
    }
    for (NSData *blob in blobs) {
        [superBlob appendData:blob];
    }
    return superBlob;
}

NSData *ISCMakeSignatureBlobWithSlots(NSDictionary<NSString *, id> *xmlEntitlements,
                                      NSDictionary<NSString *, id> *derEntitlements) {
    NSData *xmlPayload = xmlEntitlements != nil
        ? [NSPropertyListSerialization dataWithPropertyList:xmlEntitlements
                                                     format:NSPropertyListXMLFormat_v1_0
                                                    options:0
                                                      error:NULL]
        : nil;
    NSData *derPayload = derEntitlements != nil ? ISCMakeDEREntitlementsPayload(derEntitlements) : nil;
    return ISCMakeSignatureBlobWithPayloads(xmlPayload, derPayload);
}

NSData *ISCMakeSignatureBlob(NSDictionary<NSString *, id> *entitlements) {
    return ISCMakeSignatureBlobWithSlots(entitlements, nil);
}
