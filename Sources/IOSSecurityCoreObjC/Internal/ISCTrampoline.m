//
//  ISCTrampoline.m
//  IOSSecurityCoreObjC (private)
//
//  Encodings are from the Arm Architecture Reference Manual (A64 base instructions).
//

#import "ISCTrampoline.h"
#import "ISCRuntimeSupport.h"

#include <mach/mach.h>

#if defined(__arm64__)

// MARK: - Safe memory access

/// Reads `length` bytes at `address` without faulting on unmapped memory.
static bool ISCReadMemory(uintptr_t address, void *buffer, size_t length) {
    if (address == 0) {
        return false;
    }
    vm_size_t copied = 0;
    kern_return_t result = vm_read_overwrite(mach_task_self(), (vm_address_t)address, (vm_size_t)length,
                                             (vm_address_t)buffer, &copied);
    return result == KERN_SUCCESS && copied == length;
}

static bool ISCReadInstruction(uintptr_t address, uint32_t *instruction) {
    return ISCReadMemory(address, instruction, sizeof(*instruction));
}

static bool ISCReadPointer(uintptr_t address, uint64_t *pointer) {
    return ISCReadMemory(address, pointer, sizeof(*pointer));
}

// MARK: - Decoding helpers

static int64_t ISCSignExtend(uint64_t value, unsigned bits) {
    unsigned shift = 64 - bits;
    return (int64_t)(value << shift) >> shift;
}

/// `bti`, `paciasp` or `pacibsp`: harmless prologue hints a hook may sit behind.
static bool ISCIsPrologueHint(uint32_t instruction) {
    return (instruction & 0xFFFFFF3Fu) == 0xD503241Fu   // bti {c, j, jc}
        || instruction == 0xD503233Fu                    // paciasp
        || instruction == 0xD503237Fu;                   // pacibsp
}

/// `br`, `braaz`, `brabz`, `braa` or `brab` through register `reg`.
static bool ISCIsBranchToRegister(uint32_t instruction, uint32_t reg) {
    if (((instruction >> 5) & 31u) != reg) {
        return false;
    }
    return (instruction & 0xFFFFFC1Fu) == 0xD61F0000u     // br
        || (instruction & 0xFFFFFC1Fu) == 0xD61F081Fu     // braaz
        || (instruction & 0xFFFFFC1Fu) == 0xD61F0C1Fu     // brabz
        || (instruction & 0xFFFFFC00u) == 0xD71F0800u     // braa
        || (instruction & 0xFFFFFC00u) == 0xD71F0C00u;    // brab
}

static const void *ISCStrippedTarget(uint64_t value) {
    const void *pointer = (const void *)(uintptr_t)value;
    return (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(pointer);
}

// MARK: - Decoder

bool ISCDecodeTrampoline(const void *function, const void **outTarget) {
    *outTarget = NULL;
    uintptr_t pc = (uintptr_t)ISC_STRIP_CODE_POINTER(function);
    if (pc == 0 || (pc & 3u) != 0) {
        return false;
    }

    uint32_t first = 0;
    if (!ISCReadInstruction(pc, &first)) {
        return false;
    }
    if (ISCIsPrologueHint(first)) {
        pc += 4;
        if (!ISCReadInstruction(pc, &first)) {
            return false;
        }
    }

    // b <label>
    if ((first & 0xFC000000u) == 0x14000000u) {
        int64_t offset = ISCSignExtend(first & 0x03FFFFFFu, 26) * 4;
        *outTarget = (const void *)(uintptr_t)(pc + (uintptr_t)offset);
        return true;
    }

    uint32_t second = 0;
    if (!ISCReadInstruction(pc + 4, &second)) {
        return false;
    }

    // ldr xN, <literal> ; br xN
    if ((first & 0xFF000000u) == 0x58000000u) {
        uint32_t reg = first & 31u;
        if (!ISCIsBranchToRegister(second, reg)) {
            return false;
        }
        int64_t offset = ISCSignExtend((first >> 5) & 0x7FFFFu, 19) * 4;
        uint64_t value = 0;
        if (!ISCReadPointer(pc + (uintptr_t)offset, &value)) {
            return false;
        }
        *outTarget = ISCStrippedTarget(value);
        return true;
    }

    // adrp xN, <page> ; add xN, xN, #off | ldr xN, [xN, #off] ; br xN
    if ((first & 0x9F000000u) == 0x90000000u) {
        uint32_t reg = first & 31u;
        uint64_t immediate = (((first >> 5) & 0x7FFFFu) << 2) | ((first >> 29) & 3u);
        uintptr_t page = (pc & ~(uintptr_t)0xFFF) + (uintptr_t)(ISCSignExtend(immediate, 21) * 4096);

        uint32_t third = 0;
        if (!ISCReadInstruction(pc + 8, &third) || !ISCIsBranchToRegister(third, reg)) {
            return false;
        }
        bool sameRegisters = (second & 31u) == reg && ((second >> 5) & 31u) == reg;
        if (!sameRegisters) {
            return false;
        }
        if ((second & 0xFF800000u) == 0x91000000u) {           // add xN, xN, #imm{, lsl #12}
            uint64_t offset = (second >> 10) & 0xFFFu;
            if ((second >> 22) & 1u) {
                offset <<= 12;
            }
            *outTarget = (const void *)(page + (uintptr_t)offset);
            return true;
        }
        if ((second & 0xFFC00000u) == 0xF9400000u) {           // ldr xN, [xN, #imm]
            uint64_t value = 0;
            if (!ISCReadPointer(page + (uintptr_t)(((second >> 10) & 0xFFFu) * 8), &value)) {
                return false;
            }
            *outTarget = ISCStrippedTarget(value);
            return true;
        }
        return false;
    }

    // movz xN, #imm{, lsl #s} ; movk xN, ... (up to three) ; br xN
    if ((first & 0xFF800000u) == 0xD2800000u) {
        uint32_t reg = first & 31u;
        uint64_t value = (uint64_t)((first >> 5) & 0xFFFFu) << (((first >> 21) & 3u) * 16);
        uint32_t instruction = second;
        for (unsigned index = 2; index <= 5; index++) {
            if (ISCIsBranchToRegister(instruction, reg)) {
                *outTarget = ISCStrippedTarget(value);
                return true;
            }
            bool isMovk = (instruction & 0xFF800000u) == 0xF2800000u && (instruction & 31u) == reg;
            if (!isMovk || index == 5) {
                return false;
            }
            unsigned shift = ((instruction >> 21) & 3u) * 16;
            value = (value & ~((uint64_t)0xFFFFu << shift)) | ((uint64_t)((instruction >> 5) & 0xFFFFu) << shift);
            if (!ISCReadInstruction(pc + 4 * index, &instruction)) {
                return false;
            }
        }
        return false;
    }

    return false;
}

#else

bool ISCDecodeTrampoline(const void *function, const void **outTarget) {
    (void)function;
    *outTarget = NULL;
    return false;
}

#endif
