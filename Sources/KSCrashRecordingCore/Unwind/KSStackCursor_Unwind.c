//
// KSStackCursor_Unwind.c
//
// Created by Alexander Cohen on 2025-01-16.
//
// Copyright (c) 2012 Karl Stenerud. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall remain in place
// in this source code.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#include "Unwind/KSStackCursor_Unwind.h"

#include <mach/vm_param.h>

#include "KSBinaryImageCache.h"
#include "KSCPU.h"
#include "KSMemory.h"
#include "KSSystemCapabilities.h"
#include "Unwind/KSCompactUnwind.h"
#include "Unwind/KSDwarfUnwind.h"

// #define KSLogger_LocalLevel TRACE
#include "KSLogger.h"

// MARK: - Address Validation

/**
 * Check if an address is valid for use as a code address.
 *
 * Addresses in or near the NULL page are invalid. We use > PAGE_SIZE (rather than >=)
 * to be conservative and reject the page boundary itself, since the minimum valid
 * text address on iOS/macOS is far above PAGE_SIZE.
 * This catches:
 * - NULL pointers
 * - Uninitialized LR values
 * - Corrupted return addresses at thread boundaries (thread_start, _pthread_start)
 *
 * This approach is used by PLCrashReporter and prevents spurious frames
 * at the bottom of the stack.
 */
static inline bool isValidCodeAddress(uintptr_t address) { return address > PAGE_SIZE; }

// MARK: - Types

/** Represents a frame entry for frame pointer walking (fallback). */
typedef struct FrameEntry {
    struct FrameEntry *previous;
    uintptr_t return_address;
} FrameEntry;

// Note: KSUnwindMethod enum is defined in the header file

/** Maximum number of unwind methods (CompactUnwind, Dwarf, FramePointer). */
#define KSUNWIND_MAX_METHODS 3

/** Internal context for the unwind cursor. */
typedef struct {
    const struct KSMachineContext *machineContext;
    int maxStackDepth;

    // Current register state (updated as we unwind)
    uintptr_t pc;      // Program counter / instruction pointer
    uintptr_t sp;      // Stack pointer
    uintptr_t fp;      // Frame pointer
    uintptr_t lr;      // Link register (ARM only)
    uintptr_t prevSP;  // Previous stack pointer (for progress detection)

    // State tracking
    bool isFirstFrame;
    bool usedLinkRegister;
    bool reachedEndOfStack;     // Set when FP becomes 0 (thread entry point reached)
    bool framePointerRestored;  // True if last unwind restored FP from stack
    KSUnwindMethod lastMethod;

    // Method selection - try methods in order until one succeeds (0 = end)
    KSUnwindMethod methods[KSUNWIND_MAX_METHODS];

    // Frame pointer fallback state
    FrameEntry currentFrame;

#if defined(__arm64__) || defined(__x86_64__)
    // Swift Concurrency AsyncContext chain walk state, used once the physical
    // stack is exhausted. 0 = not started yet, or chain exhausted.
    uintptr_t asyncContext;
    bool asyncChainStarted;
#endif
} UnwindCursorContext;

// MARK: - Architecture-Specific Helpers

#if defined(__arm64__)

static bool tryCompactUnwindForPC(uintptr_t pc, uintptr_t sp, uintptr_t fp, uintptr_t lr, KSCompactUnwindResult *result)
{
    // Find unwind info for this PC
    KSBinaryImageUnwindInfo imageInfo;
    if (!ksbic_getUnwindInfoForAddress(pc, &imageInfo) || !imageInfo.hasCompactUnwind) {
        KSLOG_TRACE("No compact unwind info for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    // Find the compact unwind entry for this function
    KSCompactUnwindEntry entry;
    uintptr_t imageBase = (uintptr_t)imageInfo.header;
    if (!kscu_findEntry(imageInfo.unwindInfo, imageInfo.unwindInfoSize, pc, imageBase, imageInfo.slide, &entry)) {
        KSLOG_TRACE("No compact unwind entry for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    // Check if this encoding requires DWARF
    if (kscu_encodingRequiresDwarf(entry.encoding)) {
        KSLOG_TRACE("Encoding 0x%x requires DWARF for PC 0x%lx", entry.encoding, (unsigned long)pc);
        return false;
    }

    // Decode the compact unwind encoding
    return kscu_arm64_decode(entry.encoding, pc, sp, fp, lr, result);
}

#elif defined(__x86_64__)

static bool tryCompactUnwindForPC(uintptr_t pc, uintptr_t sp, uintptr_t fp, uintptr_t lr __attribute__((unused)),
                                  KSCompactUnwindResult *result)
{
    KSBinaryImageUnwindInfo imageInfo;
    if (!ksbic_getUnwindInfoForAddress(pc, &imageInfo) || !imageInfo.hasCompactUnwind) {
        KSLOG_TRACE("No compact unwind info for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    KSCompactUnwindEntry entry;
    uintptr_t imageBase = (uintptr_t)imageInfo.header;
    if (!kscu_findEntry(imageInfo.unwindInfo, imageInfo.unwindInfoSize, pc, imageBase, imageInfo.slide, &entry)) {
        KSLOG_TRACE("No compact unwind entry for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    if (kscu_encodingRequiresDwarf(entry.encoding)) {
        KSLOG_TRACE("Encoding 0x%x requires DWARF for PC 0x%lx", entry.encoding, (unsigned long)pc);
        return false;
    }

    return kscu_x86_64_decode(entry.encoding, pc, sp, fp, result);
}

#elif defined(__arm__)

static bool tryCompactUnwindForPC(uintptr_t pc, uintptr_t sp, uintptr_t fp, uintptr_t lr, KSCompactUnwindResult *result)
{
    KSBinaryImageUnwindInfo imageInfo;
    if (!ksbic_getUnwindInfoForAddress(pc, &imageInfo) || !imageInfo.hasCompactUnwind) {
        KSLOG_TRACE("No compact unwind info for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    KSCompactUnwindEntry entry;
    uintptr_t imageBase = (uintptr_t)imageInfo.header;
    if (!kscu_findEntry(imageInfo.unwindInfo, imageInfo.unwindInfoSize, pc, imageBase, imageInfo.slide, &entry)) {
        KSLOG_TRACE("No compact unwind entry for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    if (kscu_encodingRequiresDwarf(entry.encoding)) {
        KSLOG_TRACE("Encoding 0x%x requires DWARF for PC 0x%lx", entry.encoding, (unsigned long)pc);
        return false;
    }

    return kscu_arm_decode(entry.encoding, pc, sp, fp, lr, result);
}

#elif defined(__i386__)

static bool tryCompactUnwindForPC(uintptr_t pc, uintptr_t sp, uintptr_t fp, uintptr_t lr __attribute__((unused)),
                                  KSCompactUnwindResult *result)
{
    KSBinaryImageUnwindInfo imageInfo;
    if (!ksbic_getUnwindInfoForAddress(pc, &imageInfo) || !imageInfo.hasCompactUnwind) {
        KSLOG_TRACE("No compact unwind info for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    KSCompactUnwindEntry entry;
    uintptr_t imageBase = (uintptr_t)imageInfo.header;
    if (!kscu_findEntry(imageInfo.unwindInfo, imageInfo.unwindInfoSize, pc, imageBase, imageInfo.slide, &entry)) {
        KSLOG_TRACE("No compact unwind entry for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    if (kscu_encodingRequiresDwarf(entry.encoding)) {
        KSLOG_TRACE("Encoding 0x%x requires DWARF for PC 0x%lx", entry.encoding, (unsigned long)pc);
        return false;
    }

    return kscu_x86_decode(entry.encoding, pc, sp, fp, result);
}

#else
// Unsupported architecture - compact unwind always fails
static bool tryCompactUnwindForPC(uintptr_t pc __attribute__((unused)), uintptr_t sp __attribute__((unused)),
                                  uintptr_t fp __attribute__((unused)), uintptr_t lr __attribute__((unused)),
                                  KSCompactUnwindResult *result __attribute__((unused)))
{
    return false;
}
#endif

// MARK: - DWARF Unwinding

static bool tryDwarfUnwindForPC(uintptr_t pc, uintptr_t sp, uintptr_t fp, uintptr_t lr, KSCompactUnwindResult *result)
{
    // Find unwind info for this PC
    KSBinaryImageUnwindInfo imageInfo;
    if (!ksbic_getUnwindInfoForAddress(pc, &imageInfo) || !imageInfo.hasEhFrame) {
        KSLOG_TRACE("No DWARF eh_frame info for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    // Try DWARF unwinding
    KSDwarfUnwindResult dwarfResult;
    uintptr_t imageBase = (uintptr_t)imageInfo.header;
    if (!ksdwarf_unwind(imageInfo.ehFrame, imageInfo.ehFrameSize, pc, sp, fp, lr, imageBase, &dwarfResult)) {
        KSLOG_TRACE("DWARF unwind failed for PC 0x%lx", (unsigned long)pc);
        return false;
    }

    if (!dwarfResult.valid) {
        return false;
    }

    // Copy results to compact unwind result format
    result->valid = true;
    result->framePointerRestored = dwarfResult.framePointerRestored;
    result->returnAddress = dwarfResult.returnAddress;
    result->stackPointer = dwarfResult.stackPointer;
    result->framePointer = dwarfResult.framePointer;
    result->savedRegisterMask = 0;

    KSLOG_TRACE("DWARF unwind succeeded: returnAddr=0x%lx", (unsigned long)result->returnAddress);
    return true;
}

// MARK: - Frame Pointer Fallback

static bool tryFramePointerUnwind(UnwindCursorContext *ctx, uintptr_t *outReturnAddress)
{
    if (ctx->fp == 0) {
        return false;
    }

    // Read the frame entry at FP
    FrameEntry frame;
    if (!ksmem_copySafely((const void *)ctx->fp, &frame, sizeof(frame))) {
        KSLOG_TRACE("Failed to read frame at FP 0x%lx", (unsigned long)ctx->fp);
        return false;
    }

    // Only check return_address - a NULL previous just means end of chain.
    // A NULL return_address means we can't continue (invalid frame).
    if (frame.return_address == 0) {
        KSLOG_TRACE("Frame at FP 0x%lx has NULL return address", (unsigned long)ctx->fp);
        return false;
    }

    // Validate stack direction: On all Apple platforms, the stack grows downward,
    // so older frames (callers) are at higher addresses. When unwinding, the new FP
    // should be greater than the current FP. If it's less than or equal, we've hit
    // corruption or an invalid frame chain.
    uintptr_t newFP = (uintptr_t)frame.previous;
    if (newFP != 0 && newFP <= ctx->fp) {
        KSLOG_TRACE("Stack direction violation: new FP 0x%lx <= current FP 0x%lx", (unsigned long)newFP,
                    (unsigned long)ctx->fp);
        return false;
    }

    *outReturnAddress = frame.return_address;
    ctx->currentFrame = frame;

    // Calculate SP from current FP BEFORE updating it
    // On x86/x86_64, SP = FP + 16 (after the saved FP and return address)
    // On ARM64, similar layout
#if defined(__x86_64__) || defined(__arm64__)
    ctx->sp = ctx->fp + 16;
#elif defined(__i386__) || defined(__arm__)
    ctx->sp = ctx->fp + 8;
#endif

    // Update FP for next iteration (AFTER calculating SP)
    ctx->fp = newFP;

    return true;
}

// MARK: - Cursor Implementation

/**
 * Compute the PC to use for unwind info lookup.
 *
 * Return addresses point to the instruction AFTER the call instruction.
 * To look up unwind info for the function containing the call, we need
 * to subtract 1 from the return address. This prevents spurious frames
 * at function boundaries (e.g., _pthread_start -> thread_start).
 *
 * This technique is used by Firebase/Crashlytics (FIRCLSUnwind.c:156-180).
 *
 * @param pc The program counter value
 * @param isReturnAddress Whether this PC is a return address (vs. current instruction pointer)
 * @return The PC value to use for unwind info lookup
 */
static inline uintptr_t lookupPCForUnwind(uintptr_t pc, bool isReturnAddress)
{
    if (isReturnAddress && pc > 0) {
        return pc - 1;
    }
    return pc;
}

/** Try to unwind one frame using a specific method. Updates ctx state on success.
 *  @param isReturnAddress If true, ctx->pc is a return address and should be adjusted for lookup.
 */
static bool tryUnwindWithMethod(UnwindCursorContext *ctx, KSUnwindMethod method, uintptr_t *outAddress,
                                bool isReturnAddress)
{
    KSCompactUnwindResult result;
    // Normalize the PC to strip PAC bits (arm64e) before looking up unwind info.
    // Return addresses read from stack memory contain PAC signatures, but unwind
    // tables store canonical (unsigned) addresses.
    uintptr_t lookupPC = kscpu_normaliseInstructionPointer(lookupPCForUnwind(ctx->pc, isReturnAddress));

    switch (method) {
        case KSUnwindMethod_CompactUnwind:
            if (tryCompactUnwindForPC(lookupPC, ctx->sp, ctx->fp, ctx->lr, &result) && result.valid) {
                *outAddress = result.returnAddress;
                ctx->sp = result.stackPointer;
                ctx->fp = result.framePointer;
                ctx->framePointerRestored = result.framePointerRestored;
                ctx->pc = result.returnAddress;
                ctx->lastMethod = KSUnwindMethod_CompactUnwind;
                KSLOG_TRACE("Compact unwind succeeded: returnAddr=0x%lx", (unsigned long)*outAddress);
                return true;
            }
            break;

        case KSUnwindMethod_Dwarf:
            if (tryDwarfUnwindForPC(lookupPC, ctx->sp, ctx->fp, ctx->lr, &result) && result.valid) {
                *outAddress = result.returnAddress;
                ctx->sp = result.stackPointer;
                ctx->fp = result.framePointer;
                ctx->framePointerRestored = result.framePointerRestored;
                ctx->pc = result.returnAddress;
                ctx->lastMethod = KSUnwindMethod_Dwarf;
                KSLOG_TRACE("DWARF unwind succeeded: returnAddr=0x%lx", (unsigned long)*outAddress);
                return true;
            }
            break;

        case KSUnwindMethod_FramePointer:
            if (tryFramePointerUnwind(ctx, outAddress)) {
                ctx->pc = *outAddress;
                ctx->framePointerRestored = true;  // Frame pointer walking always restores FP
                ctx->lastMethod = KSUnwindMethod_FramePointer;
                KSLOG_TRACE("Frame pointer unwind succeeded: returnAddr=0x%lx", (unsigned long)*outAddress);
                return true;
            }
            break;

        default:
            break;
    }
    return false;
}

#if defined(__arm64__) || defined(__arm__)
/**
 * Try to update register state after using LR, using methods in order.
 *
 * Note: We use the exact PC (not PC-1) here because ctx->pc is still the
 * instruction pointer where the crash/sample occurred, not a return address.
 * The LR value (which IS a return address) will be stored to ctx->pc after
 * this function returns.
 *
 * @param consumedLR The LR value the caller already emitted as a frame. ctx->lr has been
 *        cleared by then (so a frameless-leaf encoding cannot hand it back as a duplicate
 *        return address), but the frame-pointer fallback still has to restore PC to it, so
 *        it is passed explicitly rather than read back off the context.
 */
static bool tryUpdateStateAfterLR(UnwindCursorContext *ctx, uintptr_t consumedLR)
{
    KSCompactUnwindResult result;

    // Use exact PC - this is the instruction pointer, not a return address.
    // Normalize to strip PAC bits (arm64e) for unwind table lookup.
    uintptr_t lookupPC = kscpu_normaliseInstructionPointer(ctx->pc);

    for (int i = 0; i < KSUNWIND_MAX_METHODS && ctx->methods[i] != KSUnwindMethod_None; i++) {
        switch (ctx->methods[i]) {
            case KSUnwindMethod_CompactUnwind:
                if (tryCompactUnwindForPC(lookupPC, ctx->sp, ctx->fp, ctx->lr, &result) && result.valid) {
                    ctx->sp = result.stackPointer;
                    ctx->fp = result.framePointer;
                    ctx->framePointerRestored = result.framePointerRestored;
                    ctx->pc = result.returnAddress;
                    ctx->lastMethod = KSUnwindMethod_CompactUnwind;
                    return true;
                }
                break;

            case KSUnwindMethod_Dwarf:
                if (tryDwarfUnwindForPC(lookupPC, ctx->sp, ctx->fp, ctx->lr, &result) && result.valid) {
                    ctx->sp = result.stackPointer;
                    ctx->fp = result.framePointer;
                    ctx->framePointerRestored = result.framePointerRestored;
                    ctx->pc = result.returnAddress;
                    ctx->lastMethod = KSUnwindMethod_Dwarf;
                    return true;
                }
                break;

            case KSUnwindMethod_FramePointer: {
                FrameEntry frame;
                if (ctx->fp != 0 && ksmem_copySafely((const void *)ctx->fp, &frame, sizeof(frame))) {
                    // Validate stack direction: new FP must be greater than current FP
                    // (stack grows downward, so older frames are at higher addresses)
                    uintptr_t newFP = (uintptr_t)frame.previous;
                    if (newFP != 0 && newFP <= ctx->fp) {
                        KSLOG_TRACE("LR path: stack direction violation, new FP 0x%lx <= current FP 0x%lx",
                                    (unsigned long)newFP, (unsigned long)ctx->fp);
                        break;  // Try next method
                    }
                    ctx->fp = newFP;
                    ctx->framePointerRestored = true;  // Frame pointer walking always restores FP
                    ctx->pc = consumedLR;
                    return true;
                }
                break;
            }

            default:
                break;
        }
    }
    return false;
}
#endif  // __arm64__ || __arm__

#if defined(__arm64__) || defined(__x86_64__)
/**
 * Marker OR'd directly into the frame-pointer (x29 on arm64, rbp on x86_64) value of any
 * function using the `swiftasync` calling convention, exported by the Concurrency runtime as
 * `swift_async_extendedFramePointerFlags` (bit 60 on 64-bit Apple platforms - both
 * architectures share the same bit and the same `__POINTER_WIDTH__ == 64` definition in
 * stdlib/public/Concurrency/Task.cpp). A function with this convention carries the tag in
 * its own live frame-pointer register for as long as it's running, so any unwind step that
 * restores a caller's FP from such a frame's record hands back the tagged value verbatim.
 * This is the same mechanism Swift's own crash-time backtracer
 * (FramePointerUnwinder.swift's `isAsyncFrame`) and LLVM's X86/AArch64 codegen
 * (X86FrameLowering.cpp's BTS64ri8/AArch64's ORR on the frame pointer) use to identify async
 * frames - note the tag lives in the FP *value* itself, not in memory it points to, so it
 * must be masked off before the address is dereferenced for anything else.
 */
#define KS_SWIFT_ASYNC_EXTENDED_FRAME_FLAG ((uintptr_t)0x1000000000000000ULL)

/**
 * The async-context register (x22 on arm64, r14 on x86_64 - confirmed in LLVM's
 * X86FrameLowering.cpp/AArch64 codegen) is callee-saved: it keeps whatever AsyncContext the
 * most recent async frame on this physical call chain last put there, even after control has
 * returned deep into synchronous code - or, on a reused thread-pool worker thread, even after
 * that async frame has long since finished and the thread has gone on to do something
 * unrelated. So the register alone cannot tell us whether the thread is actually inside an
 * async call chain right now; only the frame-pointer's extended-frame marker can. Check that
 * the last physical frame reached (ctx->fp) is itself async before trusting the register
 * value as its AsyncContext.
 */
static bool currentFrameHasAsyncContext(UnwindCursorContext *ctx)
{
    return (ctx->fp & KS_SWIFT_ASYNC_EXTENDED_FRAME_FLAG) != 0;
}

/**
 * Walk the Swift Concurrency AsyncContext chain (Parent at offset 0, ResumeParent at
 * offset 8) to recover the logical async caller chain once the physical stack has been
 * exhausted. This is the crash-time analogue of Darwin's `backtrace_async()`, which only
 * works on the calling/live thread and so cannot be used from a signal/exception handler
 * inspecting a different, frozen thread.
 *
 * Reads go through ksmem_copySafely() (a Mach vm_read_overwrite trap), so a corrupted or
 * garbage AsyncContext chain can only make this function fail safely - it cannot fault the
 * crash handler thread. Pointers are stripped of PAC signature bits via
 * kscpu_normaliseInstructionPointer(), which is a "strip not authenticate" trade-off: a
 * corrupted chain may silently produce a wrong-but-plausible address rather than trapping,
 * consistent with how the rest of this unwinder already trusts addresses read out of a
 * possibly-corrupted crashed process.
 */
static bool tryAdvanceSwiftAsyncChain(UnwindCursorContext *ctx, uintptr_t *outAddress)
{
    if (!kssc_swiftAsyncStackTracesEnabled()) {
        return false;
    }

#if KSCRASH_HAS_BACKTRACE_ASYNC
    if (!__builtin_available(macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0, *)) {
        return false;
    }
#else
    return false;
#endif

    if (!ctx->asyncChainStarted) {
        ctx->asyncChainStarted = true;
        uintptr_t asyncContextRegister =
            currentFrameHasAsyncContext(ctx) ? kscpu_asyncContextRegister(ctx->machineContext) : 0;
        ctx->asyncContext = asyncContextRegister == 0 ? 0 : kscpu_normaliseInstructionPointer(asyncContextRegister);
    }

    while (ctx->asyncContext != 0) {
        struct {
            uintptr_t parent;
            uintptr_t resumeParent;
        } link;

        if (!ksmem_copySafely((const void *)ctx->asyncContext, &link, sizeof(link))) {
            KSLOG_TRACE("Failed to read AsyncContext at 0x%lx", (unsigned long)ctx->asyncContext);
            ctx->asyncContext = 0;
            return false;
        }

        uintptr_t parent = link.parent == 0 ? 0 : kscpu_normaliseInstructionPointer(link.parent);
        // Bias by +1 to match the convention backtrace_async() uses for async continuation
        // addresses, which kssymbolicator_callInstructionAddress()'s uniform -1 expects.
        uintptr_t resumeAddr = link.resumeParent == 0 ? 0 : kscpu_normaliseInstructionPointer(link.resumeParent) + 1;

        // Advance toward the parent regardless of whether this link's resumeParent is
        // usable, so a single bad/root link doesn't stop the walk short.
        ctx->asyncContext = parent;

        if (resumeAddr != 0 && isValidCodeAddress(resumeAddr)) {
            *outAddress = resumeAddr;
            return true;
        }
    }
    return false;
}
#endif  // __arm64__ || __x86_64__

static bool advanceCursor(KSStackCursor *cursor)
{
    UnwindCursorContext *ctx = (UnwindCursorContext *)cursor->context;
    uintptr_t nextAddress = 0;

    if (cursor->state.currentDepth >= ctx->maxStackDepth) {
        cursor->state.hasGivenUp = true;
        return false;
    }

#if defined(__arm64__) || defined(__x86_64__)
    // A tagged FP isn't a real address - it's the Swift async ABI's marker that the
    // previous frame was a synthetic/async one with no physical caller. Trying to unwind
    // further from it feeds compact-unwind/DWARF/frame-pointer garbage input, which can
    // spuriously "succeed" (e.g. a TSan-interposed thunk decoding it into a bogus-but
    // valid-looking address) and clobber the tag before the async chain walk gets to see
    // it. Stop the physical walk here instead, same as a genuine end-of-stack.
    if (currentFrameHasAsyncContext(ctx)) {
        ctx->reachedEndOfStack = true;
    }
#endif

    // If we've already reached the end of the stack (FP became 0), stop.
    // This prevents spurious frames after thread entry points (thread_start, _pthread_start).
    if (ctx->reachedEndOfStack) {
        KSLOG_TRACE("Stopping unwind - already reached end of stack (FP was 0)");
#if defined(__arm64__) || defined(__x86_64__)
        if (tryAdvanceSwiftAsyncChain(ctx, &nextAddress)) {
            ctx->lastMethod = KSUnwindMethod_SwiftAsync;
            goto successfulExit;
        }
#endif
        return false;
    }

    // First frame: return the current instruction pointer
    if (ctx->isFirstFrame) {
        ctx->isFirstFrame = false;
        ctx->pc = kscpu_instructionAddress(ctx->machineContext);
        ctx->sp = kscpu_stackPointer(ctx->machineContext);
        ctx->fp = kscpu_framePointer(ctx->machineContext);
        ctx->lr = kscpu_linkRegister(ctx->machineContext);
        ctx->prevSP = ctx->sp;  // Initialize for progress tracking

        if (ctx->pc == 0) {
            return false;
        }

        nextAddress = ctx->pc;
        goto successfulExit;
    }

    // For ARM architectures, the link register contains the return address for the first call
    // Use it before trying to unwind
#if defined(__arm64__) || defined(__arm__)
    if (!ctx->usedLinkRegister && ctx->lr != 0) {
        ctx->usedLinkRegister = true;
        nextAddress = ctx->lr;

        // Validate the LR value before using it. Invalid LR values (in the NULL page)
        // indicate we've reached the bottom of the stack (thread_start, _pthread_start).
        if (!isValidCodeAddress(nextAddress)) {
            KSLOG_TRACE("LR 0x%lx is in NULL page - terminating unwind", (unsigned long)nextAddress);
            return false;
        }

        // Clear LR after consuming it. Compact unwind passes ctx->lr to the
        // decoder, and frameless-leaf encodings (stackSize==0) or mode-0
        // entries return it as the return address. If LR still holds the
        // original register value, any such encoding deep in the stack would
        // produce a spurious duplicate of frame [1].
        // The value itself is still needed: the frame-pointer fallbacks below set PC to it,
        // so keep it in a local rather than reading the (now zero) register back.
        const uintptr_t consumedLR = ctx->lr;
        ctx->lr = 0;

        // After using LR, we need to unwind to get the next return address
        // Try methods in order to update our register state
        if (!tryUpdateStateAfterLR(ctx, consumedLR)) {
            // Fallback: advance FP if possible and set PC to LR
            FrameEntry frame;
            if (ctx->fp != 0 && ksmem_copySafely((const void *)ctx->fp, &frame, sizeof(frame))) {
                // Validate stack direction before updating FP
                uintptr_t newFP = (uintptr_t)frame.previous;
                if (newFP == 0 || newFP > ctx->fp) {
                    // Calculate SP from current FP BEFORE updating FP.
                    // This ensures the next unwind step (which may be a frameless
                    // function) has the correct SP for stack address calculations.
#if defined(__x86_64__) || defined(__arm64__)
                    ctx->sp = ctx->fp + 16;
#elif defined(__i386__) || defined(__arm__)
                    ctx->sp = ctx->fp + 8;
#endif
                    ctx->fp = newFP;
                    // We successfully restored FP from the frame chain
                    ctx->framePointerRestored = true;
                } else {
                    KSLOG_TRACE("LR fallback: stack direction violation, new FP 0x%lx <= current FP 0x%lx",
                                (unsigned long)newFP, (unsigned long)ctx->fp);
                    // Don't update FP on invalid frame chain - FP was not restored
                    ctx->framePointerRestored = false;
                }
            } else {
                // Couldn't read frame from stack - FP was not restored
                ctx->framePointerRestored = false;
            }
            // Always update PC to the LR we consumed, even if FP read failed. This ensures the
            // next unwind step starts from the correct address rather than a stale PC.
            ctx->pc = consumedLR;
        }

        // The LR frame itself wasn't unwound - we just read the register.
        // Set method to None regardless of what tryUpdateStateAfterLR did.
        ctx->lastMethod = KSUnwindMethod_None;

        // Check if FP became 0 after LR handling - mark end of stack
        // Only treat FP==0 as end-of-stack if FP was actually restored from unwind info.
        // Frameless functions pass FP through unchanged, so FP==0 doesn't indicate end of stack.
        if (ctx->fp == 0 && ctx->framePointerRestored) {
            KSLOG_TRACE("FP is 0 after LR handling (restored from stack) - marking end of stack");
            ctx->reachedEndOfStack = true;
        }

        // Note: We don't check SP progress on the LR path. The LR is a register read,
        // not a stack frame pop, so SP may not have increased yet. SP progress checking
        // only makes sense for subsequent stack frame unwinds.
        ctx->prevSP = ctx->sp;

        goto successfulExit;
    }
#endif

    // Try each method in order until one succeeds.
    // ctx->pc is a return address at this point, so use PC-1 for unwind info lookup.
    for (int i = 0; i < KSUNWIND_MAX_METHODS && ctx->methods[i] != KSUnwindMethod_None; i++) {
        if (tryUnwindWithMethod(ctx, ctx->methods[i], &nextAddress, true /* isReturnAddress */)) {
            // Check if we've reached end of frame chain.
            // At thread entry points (thread_start, _pthread_start), FP is typically 0.
            // If FP is 0 after unwinding, we've reached the bottom of the stack.
            // Accept this frame but mark that we should stop on the next iteration.
            // IMPORTANT: Only treat FP==0 as end-of-stack if FP was actually restored
            // from unwind info. Frameless functions (compact unwind frameless mode,
            // or DWARF CFI without FP rule) pass FP through unchanged.
            if (ctx->fp == 0 && ctx->framePointerRestored) {
                KSLOG_TRACE("FP is 0 after unwind (restored from stack) - marking end of stack");
                ctx->reachedEndOfStack = true;
            }

            // Secondary stop condition: SP must progress (increase) when unwinding.
            // On stack-grows-down architectures, older frames are at higher addresses.
            // If SP doesn't increase, we're stuck or walking into garbage.
            //
            // IMPORTANT: Only apply this check for frame pointer walking, where SP non-progress
            // is genuinely suspicious. For compact unwind and DWARF, the unwind info explicitly
            // tells us the new SP, and SP == prevSP can be legitimate in scenarios like:
            // - Stack switching (signal handlers on alternate stacks)
            // - Trampoline frames that don't modify the stack
            // - DWARF CFI where CFA equals the current SP
            // Trusting the unwind info avoids truncating valid stack traces.
            if (ctx->lastMethod == KSUnwindMethod_FramePointer && ctx->sp != 0 && ctx->sp <= ctx->prevSP) {
                KSLOG_TRACE("SP not progressing during FP walk (0x%lx <= 0x%lx) - marking end of stack",
                            (unsigned long)ctx->sp, (unsigned long)ctx->prevSP);
                ctx->reachedEndOfStack = true;
            }
            ctx->prevSP = ctx->sp;

            goto successfulExit;
        }
    }

    // All methods exhausted - the physical stack is done. Try recovering the logical
    // Swift async caller chain before giving up entirely.
#if defined(__arm64__) || defined(__x86_64__)
    if (tryAdvanceSwiftAsyncChain(ctx, &nextAddress)) {
        ctx->lastMethod = KSUnwindMethod_SwiftAsync;
        goto successfulExit;
    }
#endif
    return false;

successfulExit:
    // Final validation: reject addresses in the NULL page.
    // This catches corrupted return addresses and prevents spurious frames
    // at thread boundaries (thread_start, _pthread_start, etc.).
    if (!isValidCodeAddress(nextAddress)) {
        KSLOG_TRACE("Address 0x%lx is in NULL page - terminating unwind", (unsigned long)nextAddress);
        return false;
    }

    // Swift async chain addresses are already normalised + biased by
    // tryAdvanceSwiftAsyncChain(); re-normalising is harmless but must not re-bias.
    cursor->stackEntry.address =
        ctx->lastMethod == KSUnwindMethod_SwiftAsync ? nextAddress : kscpu_normaliseInstructionPointer(nextAddress);
    cursor->state.currentDepth++;
    if (cursor->state.currentDepth >= KSSC_STACK_OVERFLOW_THRESHOLD) {
        cursor->state.stackOverflow = true;
    }
    return true;
}

static void resetCursor(KSStackCursor *cursor)
{
    kssc_resetCursor(cursor);
    UnwindCursorContext *ctx = (UnwindCursorContext *)cursor->context;

    ctx->pc = 0;
    ctx->sp = 0;
    ctx->fp = 0;
    ctx->lr = 0;
    ctx->prevSP = 0;
    ctx->isFirstFrame = true;
    ctx->usedLinkRegister = false;
    ctx->reachedEndOfStack = false;
    ctx->framePointerRestored = false;
    ctx->lastMethod = KSUnwindMethod_None;
    // Note: methods[] is preserved across reset
    ctx->currentFrame.previous = NULL;
    ctx->currentFrame.return_address = 0;
#if defined(__arm64__) || defined(__x86_64__)
    ctx->asyncContext = 0;
    ctx->asyncChainStarted = false;
#endif
}

// MARK: - Public API

void kssc_initWithUnwindMethods(KSStackCursor *cursor, int maxStackDepth, const struct KSMachineContext *machineContext,
                                const KSUnwindMethod *methods, size_t methodCount)
{
    kssc_initCursor(cursor, resetCursor, advanceCursor);

    UnwindCursorContext *ctx = (UnwindCursorContext *)cursor->context;
    ctx->machineContext = machineContext;
    ctx->maxStackDepth = maxStackDepth;
    ctx->pc = 0;
    ctx->sp = 0;
    ctx->fp = 0;
    ctx->lr = 0;
    ctx->prevSP = 0;
    ctx->isFirstFrame = true;
    ctx->usedLinkRegister = false;
    ctx->reachedEndOfStack = false;
    ctx->framePointerRestored = false;
    ctx->lastMethod = KSUnwindMethod_None;
    ctx->currentFrame.previous = NULL;
    ctx->currentFrame.return_address = 0;
#if defined(__arm64__) || defined(__x86_64__)
    ctx->asyncContext = 0;
    ctx->asyncChainStarted = false;
#endif

    memset(ctx->methods, 0, sizeof(ctx->methods));
    if (methods != NULL && methodCount > 0) {
        size_t count = methodCount > KSUNWIND_MAX_METHODS ? KSUNWIND_MAX_METHODS : methodCount;
        memcpy(ctx->methods, methods, count * sizeof(KSUnwindMethod));
    }
}

void kssc_initWithUnwind(KSStackCursor *cursor, int maxStackDepth, const struct KSMachineContext *machineContext)
{
    kssc_initWithUnwindMethods(
        cursor, maxStackDepth, machineContext,
        (KSUnwindMethod[]) { KSUnwindMethod_CompactUnwind, KSUnwindMethod_Dwarf, KSUnwindMethod_FramePointer }, 3);
}

const char *kssc_unwindMethodName(KSUnwindMethod method)
{
    switch (method) {
        case KSUnwindMethod_None:
            return "none";
        case KSUnwindMethod_CompactUnwind:
            return "compact_unwind";
        case KSUnwindMethod_Dwarf:
            return "dwarf";
        case KSUnwindMethod_FramePointer:
            return "frame_pointer";
        case KSUnwindMethod_SwiftAsync:
            return "swift_async";
        default:
            return "unknown";
    }
}

KSUnwindMethod kssc_getUnwindMethod(const KSStackCursor *cursor)
{
    if (cursor == NULL) {
        return KSUnwindMethod_None;
    }

    // The context must be an UnwindCursorContext.
    // Verify this by checking if the advanceCursor function matches ours.
    // Cursors from kssc_initWithBacktrace or kssc_initSelfThread have different
    // context layouts and would read garbage if we cast blindly.
    if (cursor->advanceCursor != advanceCursor) {
        return KSUnwindMethod_None;
    }

    const UnwindCursorContext *ctx = (const UnwindCursorContext *)cursor->context;
    return ctx->lastMethod;
}
