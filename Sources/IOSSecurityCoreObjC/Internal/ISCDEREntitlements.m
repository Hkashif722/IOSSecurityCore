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
/// `[16]`, context-specific and constructed: how Apple's signing tools encode a dictionary. Seen in real
/// signatures; `SET` is accepted as well, for any encoder that follows the universal tag.
static const uint8_t ISCDERTagDictionary = 0xB0;
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

/// A two's-complement big-endian integer. Up to eight bytes is an `int64_t`; nine bytes with a leading zero
/// (DER's form of an unsigned 64-bit value of 2^63 or more) is a `uint64_t`. Anything wider is a well-formed
/// value this reader cannot represent, so it becomes `NSNull` and the other entitlements are kept. An empty
/// INTEGER is not valid DER and fails the parse.
static id ISCDERInteger(const ISCDERElement *element) {
    if (element->length == 0) {
        return nil;
    }
    if (element->length == sizeof(uint64_t) + 1 && element->content[0] == 0x00) {
        uint64_t value = 0;
        for (size_t index = 1; index < element->length; index++) {
            value = (value << 8) | element->content[index];
        }
        return @(value);
    }
    if (element->length > sizeof(int64_t)) {
        return NSNull.null;
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

/// Reads `count` ASCII digits at `digits` into `outValue`. `NO` if any of them is not a digit.
static BOOL ISCDERReadDigits(const uint8_t *digits, size_t count, NSInteger *outValue) {
    NSInteger value = 0;
    for (size_t index = 0; index < count; index++) {
        if (digits[index] < '0' || digits[index] > '9') {
            return NO;
        }
        value = value * 10 + (digits[index] - '0');
    }
    *outValue = value;
    return YES;
}

/// A GeneralizedTime in the only form DER allows, `YYYYMMDDHHMMSS[.f...]Z` in UTC, as an `NSDate`: the type
/// the XML entitlements slot yields for the same value. A value that does not parse becomes `NSNull`.
static id ISCDERDate(const ISCDERElement *element) {
    const uint8_t *text = element->content;
    size_t length = element->length;
    if (length < 15 || text[length - 1] != 'Z') {
        return NSNull.null;
    }
    NSInteger year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!ISCDERReadDigits(text, 4, &year) || !ISCDERReadDigits(text + 4, 2, &month) ||
        !ISCDERReadDigits(text + 6, 2, &day) || !ISCDERReadDigits(text + 8, 2, &hour) ||
        !ISCDERReadDigits(text + 10, 2, &minute) || !ISCDERReadDigits(text + 12, 2, &second)) {
        return NSNull.null;
    }
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
        return NSNull.null;
    }

    double fraction = 0;
    if (length > 15) {
        // ".f...Z": at least one digit between the point and the Z.
        if (text[14] != '.' || length < 17) {
            return NSNull.null;
        }
        double scale = 0.1;
        for (size_t index = 15; index < length - 1; index++) {
            if (text[index] < '0' || text[index] > '9') {
                return NSNull.null;
            }
            fraction += (text[index] - '0') * scale;
            scale /= 10;
        }
    }

    NSDateComponents *components = [[NSDateComponents alloc] init];
    components.year = year;
    components.month = month;
    components.day = day;
    components.hour = hour;
    components.minute = minute;
    components.second = second;
    NSCalendar *calendar = [[NSCalendar alloc] initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
    calendar.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    NSDate *date = [calendar dateFromComponents:components];
    return date != nil ? [date dateByAddingTimeInterval:fraction] : NSNull.null;
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

/// A dictionary (`[16]` or `SET`) of `SEQUENCE { UTF8String key, value }`.
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
            return ISCDERString(element);
        case ISCDERTagGeneralizedTime:
            return ISCDERDate(element);
        case ISCDERTagSequence:
            return ISCDERArray(element, depth + 1);
        case ISCDERTagSet:
        case ISCDERTagDictionary:
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

    // Apple's form is [APPLICATION 16] { INTEGER version, [16] dictionary }. A bare dictionary is accepted too.
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
    if (top.tag != ISCDERTagDictionary && top.tag != ISCDERTagSet) {
        return nil;
    }
    id object = ISCDERObject(&top, 0);
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}
