//
//  ISCDEREntitlements.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Tags are from ITU-T X.690 (DER). The property-list mapping is CoreFoundation's.
//

#import "ISCDEREntitlements.h"

// MARK: - Tags

static const uint8_t ISCDERTagBoolean = 0x01;
static const uint8_t ISCDERTagInteger = 0x02;
static const uint8_t ISCDERTagOctetString = 0x04;
static const uint8_t ISCDERTagNull = 0x05;
static const uint8_t ISCDERTagUTF8String = 0x0C;
static const uint8_t ISCDERTagGeneralizedTime = 0x18;
static const uint8_t ISCDERTagSequence = 0x30;
static const uint8_t ISCDERTagSet = 0x31;
/// `[APPLICATION 16]`, constructed: the wrapper Apple puts around the entitlements dictionary.
static const uint8_t ISCDERTagEntitlementsWrapper = 0x70;

/// Nesting deeper than this is not a property list anyone signs; it bounds the recursion.
static const size_t ISCDERMaximumDepth = 32;

// MARK: - Reading

typedef struct {
    uint8_t tag;
    const uint8_t *content;
    size_t length;
    const uint8_t *next;
} ISCDERElement;

/// Reads the tag, length and content bounds of the element at `cursor`. Only single-byte tags and
/// lengths of up to four bytes are accepted; property lists use nothing else.
static bool ISCDERRead(const uint8_t *cursor, const uint8_t *end, ISCDERElement *out) {
    if (cursor == NULL || end - cursor < 2) {
        return false;
    }
    uint8_t tag = cursor[0];
    if ((tag & 0x1F) == 0x1F) {
        return false; // multi-byte tag number
    }
    uint8_t first = cursor[1];
    const uint8_t *lengthEnd = cursor + 2;
    size_t length = 0;
    if (first < 0x80) {
        length = first;
    } else {
        size_t octets = first & 0x7F;
        if (octets == 0 || octets > 4 || (size_t)(end - lengthEnd) < octets) {
            return false; // indefinite length, or more than DER's practical maximum
        }
        for (size_t index = 0; index < octets; index++) {
            length = (length << 8) | lengthEnd[index];
        }
        lengthEnd += octets;
    }
    if ((size_t)(end - lengthEnd) < length) {
        return false;
    }
    out->tag = tag;
    out->content = lengthEnd;
    out->length = length;
    out->next = lengthEnd + length;
    return true;
}

// MARK: - Values

static id ISCDERObject(const ISCDERElement *element, size_t depth);

static NSString *ISCDERString(const ISCDERElement *element) {
    return [[NSString alloc] initWithBytes:element->content length:element->length encoding:NSUTF8StringEncoding];
}

/// Two's-complement big-endian integer of up to eight bytes.
static NSNumber *ISCDERInteger(const ISCDERElement *element) {
    if (element->length == 0 || element->length > sizeof(int64_t)) {
        return nil;
    }
    uint64_t raw = 0;
    for (size_t index = 0; index < element->length; index++) {
        raw = (raw << 8) | element->content[index];
    }
    if (element->length < sizeof(int64_t) && (element->content[0] & 0x80) != 0) {
        raw |= ~(uint64_t)0 << (8 * element->length); // sign-extend
    }
    return @((int64_t)raw);
}

static NSArray *ISCDERArray(const ISCDERElement *element, size_t depth) {
    NSMutableArray *array = [NSMutableArray array];
    const uint8_t *cursor = element->content;
    const uint8_t *end = element->content + element->length;
    while (cursor < end) {
        ISCDERElement item;
        if (!ISCDERRead(cursor, end, &item)) {
            return nil;
        }
        id object = ISCDERObject(&item, depth);
        if (object == nil) {
            return nil;
        }
        [array addObject:object];
        cursor = item.next;
    }
    return array;
}

/// A `SET` of `SEQUENCE { UTF8String key, value }`.
static NSDictionary<NSString *, id> *ISCDERDictionary(const ISCDERElement *element, size_t depth) {
    NSMutableDictionary<NSString *, id> *dictionary = [NSMutableDictionary dictionary];
    const uint8_t *cursor = element->content;
    const uint8_t *end = element->content + element->length;
    while (cursor < end) {
        ISCDERElement entry;
        if (!ISCDERRead(cursor, end, &entry) || entry.tag != ISCDERTagSequence) {
            return nil;
        }
        const uint8_t *entryEnd = entry.content + entry.length;
        ISCDERElement key;
        ISCDERElement value;
        if (!ISCDERRead(entry.content, entryEnd, &key) || key.tag != ISCDERTagUTF8String ||
            !ISCDERRead(key.next, entryEnd, &value)) {
            return nil;
        }
        NSString *name = ISCDERString(&key);
        id object = ISCDERObject(&value, depth);
        if (name == nil || object == nil) {
            return nil;
        }
        dictionary[name] = object;
        cursor = entry.next;
    }
    return dictionary;
}

static id ISCDERObject(const ISCDERElement *element, size_t depth) {
    if (depth > ISCDERMaximumDepth) {
        return nil;
    }
    switch (element->tag) {
        case ISCDERTagBoolean:
            return element->length == 1 ? @(element->content[0] != 0) : nil;
        case ISCDERTagInteger:
            return ISCDERInteger(element);
        case ISCDERTagOctetString:
            return [NSData dataWithBytes:element->content length:element->length];
        case ISCDERTagNull:
            return NSNull.null;
        case ISCDERTagUTF8String:
        case ISCDERTagGeneralizedTime:
            return ISCDERString(element);
        case ISCDERTagSequence:
            return ISCDERArray(element, depth + 1);
        case ISCDERTagSet:
            return ISCDERDictionary(element, depth + 1);
        default:
            // Well-formed but not a type this reader knows. Keep the entry rather than fail the whole
            // dictionary; a Team ID lookup checks the value's class anyway.
            return NSNull.null;
    }
}

// MARK: - Entry point

NSDictionary<NSString *, id> *ISCDictionaryFromDEREntitlements(const uint8_t *bytes, size_t length) {
    if (bytes == NULL || length == 0) {
        return nil;
    }
    const uint8_t *end = bytes + length;
    ISCDERElement top;
    if (!ISCDERRead(bytes, end, &top)) {
        return nil;
    }

    // Apple's form is [APPLICATION 16] { INTEGER version, SET }. A bare SET is accepted too.
    if (top.tag == ISCDERTagEntitlementsWrapper) {
        const uint8_t *wrapperEnd = top.content + top.length;
        ISCDERElement item;
        if (!ISCDERRead(top.content, wrapperEnd, &item)) {
            return nil;
        }
        if (item.tag == ISCDERTagInteger && !ISCDERRead(item.next, wrapperEnd, &item)) {
            return nil;
        }
        top = item;
    }
    if (top.tag != ISCDERTagSet) {
        return nil;
    }
    id object = ISCDERObject(&top, 0);
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}
