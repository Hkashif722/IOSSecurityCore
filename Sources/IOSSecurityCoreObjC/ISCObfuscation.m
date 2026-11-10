//
//  ISCObfuscation.m
//  IOSSecurityCoreObjC
//

#import "ISCObfuscation.h"

#include <string.h>

void ISCDeobfuscateBytes(const uint8_t *encoded, size_t length, uint8_t key, char *output) {
    for (size_t index = 0; index < length; index++) {
        output[index] = (char)(encoded[index] ^ ISC_OBF_STEP(index, key));
    }
    output[length] = '\0';
}

NSString *ISCStringFromObfuscatedBytes(const uint8_t *encoded, size_t length, uint8_t key) {
    char buffer[ISC_OBF_MAX_LENGTH + 1];
    size_t count = length > ISC_OBF_MAX_LENGTH ? ISC_OBF_MAX_LENGTH : length;
    ISCDeobfuscateBytes(encoded, count, key, buffer);
    NSString *string = [[NSString alloc] initWithBytes:buffer length:count encoding:NSUTF8StringEncoding];
    ISCSecureZero(buffer, sizeof(buffer));
    return string != nil ? string : @"";
}

void ISCSecureZero(void *buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return;
    }
    // memset_s is specified not to be optimized away, unlike a plain memset of a dead buffer.
    memset_s(buffer, length, 0, length);
}
