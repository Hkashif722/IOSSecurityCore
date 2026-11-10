//
//  ISCRuntimeSupport.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCRuntimeSupport.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// MARK: - File system

const char *ISCSafeCPath(NSString *path) {
    if (path.length == 0 || [path rangeOfString:@"\0"].location != NSNotFound) {
        return NULL;
    }
    return path.UTF8String; // NULL, not an exception, when the string cannot be encoded
}

bool ISCPathExists(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }
    if (access(path, F_OK) == 0) {
        return true;
    }
    // A second, independent system call: a bypass that only hooks access(2) is not enough.
    int descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return true;
    }
    return false;
}

bool ISCPathIsSymbolicLink(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }
    char target[PATH_MAX];
    // readlink(2) succeeds only for symbolic links (EINVAL otherwise), and unlike lstat(2) it is not a
    // "required reason" API.
    return readlink(path, target, sizeof(target)) >= 0;
}

// MARK: - Images and paths

NSArray<NSString *> *ISCCopyLoadedImagePaths(void) {
    uint32_t count = _dyld_image_count();
    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithCapacity:count];
    for (uint32_t index = 0; index < count; index++) {
        // The list can change while another thread loads or unloads a library, so tolerate gaps.
        const char *name = _dyld_get_image_name(index);
        if (name == NULL) {
            continue;
        }
        NSString *path = [NSString stringWithUTF8String:name];
        if (path != nil) {
            [paths addObject:path];
        }
    }
    return paths;
}

/// `/private/var/x` and `/var/x` name the same file; compare them in one canonical form.
NSString *ISCCanonicalizePath(NSString *path) {
    if ([path hasPrefix:@"/private/"]) {
        return [path substringFromIndex:[@"/private" length]];
    }
    return path;
}

/// Prefix test that treats `/private/var/...` and `/var/...` as the same location.
static BOOL ISCPathHasPrefix(NSString *path, NSString *prefix) {
    if (prefix.length == 0) {
        return NO;
    }
    if ([path hasPrefix:prefix]) {
        return YES;
    }
    return [ISCCanonicalizePath(path) hasPrefix:ISCCanonicalizePath(prefix)];
}

BOOL ISCPathMatchesAnyPrefix(NSString *path, NSArray<NSString *> *prefixes) {
    for (NSString *prefix in prefixes) {
        if (ISCPathHasPrefix(path, prefix)) {
            return YES;
        }
    }
    return NO;
}

NSArray<NSString *> *ISCAppBundleRoots(void) {
    NSString *bundlePath = NSBundle.mainBundle.bundlePath;
    if (bundlePath.length == 0) {
        return @[];
    }

    NSString *resolved = bundlePath;
    char buffer[PATH_MAX];
    const char *bundleCPath = ISCSafeCPath(bundlePath);
    if (bundleCPath != NULL && realpath(bundleCPath, buffer) != NULL) {
        NSString *real = [NSString stringWithUTF8String:buffer];
        if (real.length > 0) {
            resolved = real;
        }
    }

    NSString *root = [resolved hasSuffix:@"/"] ? resolved : [resolved stringByAppendingString:@"/"];
    NSMutableArray<NSString *> *roots = [NSMutableArray arrayWithObject:root];

    // Inside an app extension the main bundle is Foo.app/PlugIns/Bar.appex, but the frameworks it
    // loads live in Foo.app/Frameworks.
    NSRange appRange = [root rangeOfString:@".app/"];
    if (appRange.location != NSNotFound) {
        NSString *containingApp = [root substringToIndex:NSMaxRange(appRange)];
        if (![roots containsObject:containingApp]) {
            [roots addObject:containingApp];
        }
    }
    return roots;
}

BOOL ISCImageForAddress(const void *address, NSString **outPath, const void **outBase) {
    if (address == NULL) {
        return NO;
    }
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(address, &info) == 0 || info.dli_fname == NULL) {
        return NO;
    }
    if (outPath != NULL) {
        NSString *path = [NSString stringWithUTF8String:info.dli_fname];
        *outPath = path != nil ? path : @"";
    }
    if (outBase != NULL) {
        *outBase = info.dli_fbase;
    }
    return YES;
}

BOOL ISCImageIsInSharedCache(const void *base) {
    if (base == NULL) {
        return NO;
    }
    // `base` comes from dladdr, so it is the mapped header of a loaded image and safe to read.
    const struct mach_header *header = base;
    if (header->magic != MH_MAGIC_64 && header->magic != MH_MAGIC) {
        return NO;
    }
    return (header->flags & MH_DYLIB_IN_CACHE) != 0;
}

BOOL ISCPathHasComponentSuffix(NSString *path, NSString *suffix) {
    if (suffix.length == 0 || path.length < suffix.length) {
        return NO;
    }
    if ([path isEqualToString:suffix]) {
        return YES;
    }
    return [path hasSuffix:suffix] && [path characterAtIndex:path.length - suffix.length - 1] == '/';
}

// MARK: - Network

BOOL ISCLoopbackPortIsOpen(uint16_t port, int timeoutMilliseconds) {
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return NO;
    }

    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(descriptor);
        return NO;
    }
    int noSigPipe = 1;
    setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    BOOL isOpen = NO;
    if (connect(descriptor, (const struct sockaddr *)&address, sizeof(address)) == 0) {
        isOpen = YES;
    } else if (errno == EINPROGRESS) {
        struct pollfd waiting = {.fd = descriptor, .events = POLLOUT, .revents = 0};
        int ready;
        do {
            ready = poll(&waiting, 1, timeoutMilliseconds);
        } while (ready < 0 && errno == EINTR);

        if (ready > 0) {
            int socketError = 0;
            socklen_t length = sizeof(socketError);
            if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0 && socketError == 0) {
                isOpen = YES;
            }
        }
    }
    close(descriptor);
    return isOpen;
}

// MARK: - Strings

/// `YES` when `haystack` contains any of `needles`, ignoring case. Empty needles never match.
static BOOL ISCStringContainsAny(NSString *haystack, NSArray<NSString *> *needles) {
    for (NSString *needle in needles) {
        if (needle.length > 0 &&
            [haystack rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

NSArray<NSString *> *ISCStringsContainingAny(NSArray<NSString *> *strings, NSArray<NSString *> *needles) {
    NSMutableArray<NSString *> *matches = [NSMutableArray array];
    for (NSString *string in strings) {
        if (ISCStringContainsAny(string, needles)) {
            [matches addObject:string];
        }
    }
    return matches;
}

NSString *ISCSummarizeValues(NSArray<NSString *> *values, NSUInteger limit) {
    if (values.count <= limit) {
        return [values componentsJoinedByString:@", "];
    }
    NSString *shown = [[values subarrayWithRange:NSMakeRange(0, limit)] componentsJoinedByString:@", "];
    return [NSString stringWithFormat:@"%@ (+%lu more)", shown, (unsigned long)(values.count - limit)];
}
