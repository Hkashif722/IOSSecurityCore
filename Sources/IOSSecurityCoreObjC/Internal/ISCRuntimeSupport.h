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

/// How many matches a finding's `detail` spells out before `ISCSummarizeValues` cuts it short.
static const NSUInteger ISCDetailLimit = 5;

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

/// `YES` if `path` has any of `prefixes` as a prefix. `/private/var/...` and `/var/...` count as the same
/// location.
BOOL ISCPathMatchesAnyPrefix(NSString *path, NSArray<NSString *> *prefixes);

/// The app bundle directory (with trailing slash) and, inside an app extension, the containing `.app`.
NSArray<NSString *> *ISCAppBundleRoots(void);

/// The image that contains `address`. `outPath` receives its path and `outBase` its load address.
BOOL ISCImageForAddress(const void *address,
                        NSString *_Nullable *_Nullable outPath,
                        const void *_Nullable *_Nullable outBase);

/// `YES` when the Mach-O image whose header is at `base` lives in the dyld shared cache, which holds
/// every library the OS ships. Tweaks, instrumentation agents and the app's own code never do.
BOOL ISCImageIsInSharedCache(const void *_Nullable base);

/// `YES` when `path` equals `suffix` or ends in `/` followed by `suffix`: whole path components only,
/// so `Auth.framework/Auth` does not match `EvilAuth.framework/Auth`. An empty suffix never matches.
BOOL ISCPathHasComponentSuffix(NSString *path, NSString *suffix);

// MARK: - Network

/// Longest wait for a loopback probe to answer. A closed port refuses instantly; this bounds the
/// pathological case of a firewall that silently drops loopback traffic.
static const int ISCPortProbeTimeoutMilliseconds = 150;

/// Whether something is listening on the loopback interface at `port`. Never leaves the device.
BOOL ISCLoopbackPortIsOpen(uint16_t port, int timeoutMilliseconds);

// MARK: - Strings

/// The members of `strings` that contain any of `needles`, ignoring case.
NSArray<NSString *> *ISCStringsContainingAny(NSArray<NSString *> *strings, NSArray<NSString *> *needles);

/// Joins up to `limit` values with ", " and appends "(+N more)" when some were left out.
NSString *ISCSummarizeValues(NSArray<NSString *> *values, NSUInteger limit);

NS_ASSUME_NONNULL_END
