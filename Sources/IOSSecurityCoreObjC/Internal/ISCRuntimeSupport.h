//
//  ISCRuntimeSupport.h
//  IOSSecurityCoreObjC (private)
//
//  Small helpers shared by the detectors. Not part of the public API.
//

#import <Foundation/Foundation.h>
#include <stdbool.h>

NS_ASSUME_NONNULL_BEGIN

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
/// Removes the pointer-authentication signature from a code pointer (arm64e).
#define ISC_STRIP_CODE_POINTER(pointer) ptrauth_strip((pointer), ptrauth_key_function_pointer)
#else
#define ISC_STRIP_CODE_POINTER(pointer) (pointer)
#endif

// MARK: - File system

/// A C string for `path` that is safe to pass to system calls, or `NULL` when there is none.
///
/// Use this instead of `-[NSString fileSystemRepresentation]`, which **raises** an exception for an empty
/// string (one blank entry in a host's configuration would crash the app at launch). This returns `NULL`
/// for an empty string, a string containing a NUL, and a string that cannot be encoded as UTF-8. The
/// pointer is valid for as long as `path` is.
const char *_Nullable ISCSafeCPath(NSString *path);

/// `true` if `path` can be reached with `access(2)` or `open(2)`.
///
/// The `stat` family is deliberately not used: Apple lists it as a "required reason" API (file
/// timestamps) that would force a privacy-manifest declaration this package cannot honestly make.
bool ISCPathExists(const char *path);

/// `true` if `path` is itself a symbolic link (`readlink(2)` succeeds).
bool ISCPathIsSymbolicLink(const char *path);

// MARK: - Images and paths

/// Paths of all images dyld has loaded, in load order.
NSArray<NSString *> *ISCCopyLoadedImagePaths(void);

/// Drops a leading `/private`, so `/private/var/x` and `/var/x` compare equal.
NSString *ISCCanonicalizePath(NSString *path);

/// Prefix test that treats `/private/var/...` and `/var/...` as the same location.
BOOL ISCPathHasPrefix(NSString *path, NSString *prefix);

/// `YES` if `path` has any of `prefixes` as a prefix (see `ISCPathHasPrefix`).
BOOL ISCPathMatchesAnyPrefix(NSString *path, NSArray<NSString *> *prefixes);

/// The app bundle directory (with trailing slash) and, inside an app extension, the containing `.app`.
NSArray<NSString *> *ISCAppBundleRoots(void);

/// The image that contains `address`. `outPath` receives its path and `outBase` its load address.
BOOL ISCImageForAddress(const void *address,
                        NSString *_Nullable *_Nullable outPath,
                        const void *_Nullable *_Nullable outBase);

// MARK: - Strings

/// `YES` when `haystack` contains any of `needles`, ignoring case. `matched` receives the first hit.
BOOL ISCStringContainsAny(NSString *haystack,
                          NSArray<NSString *> *needles,
                          NSString *_Nullable *_Nullable matched);

/// The members of `strings` that contain any of `needles`, ignoring case.
NSArray<NSString *> *ISCStringsContainingAny(NSArray<NSString *> *strings, NSArray<NSString *> *needles);

/// Joins up to `limit` values with ", " and appends "(+N more)" when some were left out.
NSString *ISCSummarizeValues(NSArray<NSString *> *values, NSUInteger limit);

NS_ASSUME_NONNULL_END
