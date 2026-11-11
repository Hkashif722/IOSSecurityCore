//
//  ISCVisibility.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#ifndef ISCVisibility_h
#define ISCVisibility_h

/// Marks a declaration private to this package. The symbol is never exported, so its name leaves the
/// binary when the app is stripped. It must be on the declaration in the header: Clang's visibility
/// pragma would only cover definitions inside the pragma, not the ones in the .m files.
#define ISC_HIDDEN __attribute__((visibility("hidden")))

#endif /* ISCVisibility_h */
