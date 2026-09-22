//
//  KSSwiftAsyncCrashUnwindTests.swift
//
//  Created by Maxime Epain on 2026-09-22.
//
//  Copyright (c) 2012 Karl Stenerud. All rights reserved.
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

import Darwin
import KSCrashRecordingCore
import XCTest

// Crash-time AsyncContext chain walking is only implemented for arm64/arm64e.
#if arch(arm64)
    @available(macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0, *)
    final class KSSwiftAsyncCrashUnwindTests: XCTestCase {

        private final class MachThreadBox: @unchecked Sendable {
            var value: mach_port_t = 0
        }

        // True when the process is running under a sanitizer (ASan/TSan/UBSan). A sanitizer
        // interposes libc/libdispatch primitives with its own thunks, which use x22 (the Swift
        // async-context register) as scratch space while executing - if `thread_suspend` catches
        // the thread mid-thunk, x22 no longer holds the live AsyncContext. That's an inherent
        // limitation of reading a register at an arbitrary suspend point, not a KSCrash bug, so
        // the async-recovery assertions below are skipped rather than chasing sanitizer-specific
        // register corruption. See KSBenchmarkTestCase.swift for why a dlsym probe is used here
        // instead of `#if KSCRASH_HAS_SANITIZER` (a C macro Swift's `#if` cannot see) or a shared
        // helper (this target must not gain a dependency for a one-off check).
        private func isRunningUnderSanitizer() -> Bool {
            let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
            return ["__asan_init", "__tsan_init", "__ubsan_handle_add_overflow"].contains { symbol in
                symbol.withCString { dlsym(rtldDefault, $0) != nil }
            }
        }

        @inline(never)
        private func asyncInner(ready: DispatchSemaphore, release: DispatchSemaphore, box: MachThreadBox) async {
            box.value = pthread_mach_thread_np(pthread_self())
            ready.signal()
            release.wait()
        }

        @inline(never)
        private func asyncMiddle(ready: DispatchSemaphore, release: DispatchSemaphore, box: MachThreadBox) async {
            await asyncInner(ready: ready, release: release, box: box)
        }

        @inline(never)
        private func asyncOuter(ready: DispatchSemaphore, release: DispatchSemaphore, box: MachThreadBox) async {
            await asyncMiddle(ready: ready, release: release, box: box)
        }

        /// Launches a Task that parks a real thread mid-`await` three async frames deep,
        /// suspends that thread's mach port, and hands it to `body` for inspection.
        private func withSuspendedAsyncChain(_ body: (mach_port_t) -> Void) {
            let ready = DispatchSemaphore(value: 0)
            let release = DispatchSemaphore(value: 0)
            let box = MachThreadBox()

            Task {
                await asyncOuter(ready: ready, release: release, box: box)
            }

            ready.wait()

            let machThread = box.value
            let kr = thread_suspend(machThread)
            guard kr == KERN_SUCCESS else {
                XCTFail("thread_suspend failed: \(kr)")
                release.signal()
                return
            }

            body(machThread)

            thread_resume(machThread)
            release.signal()
        }

        /// Suspends a plain synchronous thread (no Swift async anywhere in its chain) and
        /// hands it to `body` for inspection.
        private func withSuspendedSyncThread(_ body: (mach_port_t) -> Void) {
            let ready = DispatchSemaphore(value: 0)
            let release = DispatchSemaphore(value: 0)
            let box = MachThreadBox()

            func deepBlock(_ depth: Int) {
                if depth > 0 {
                    deepBlock(depth - 1)
                } else {
                    box.value = pthread_mach_thread_np(pthread_self())
                    ready.signal()
                    release.wait()
                }
            }

            DispatchQueue.global().async {
                deepBlock(20)
            }

            ready.wait()

            let machThread = box.value
            let kr = thread_suspend(machThread)
            guard kr == KERN_SUCCESS else {
                XCTFail("thread_suspend failed: \(kr)")
                release.signal()
                return
            }

            body(machThread)

            thread_resume(machThread)
            release.signal()
        }

        private struct WalkedFrame {
            let symbolName: String?
            let method: KSUnwindMethod
        }

        private func walkUnwindCursor(machThread: mach_port_t) -> [WalkedFrame] {
            ksdl_init()

            let context = UnsafeMutablePointer<KSMachineContext>.allocate(capacity: 1)
            defer { context.deallocate() }
            guard ksmc_getContextForThread(KSThread(machThread), context, false) else {
                XCTFail("ksmc_getContextForThread failed")
                return []
            }

            let cursor = UnsafeMutablePointer<KSStackCursor>.allocate(capacity: 1)
            defer { cursor.deallocate() }
            kssc_initWithUnwind(cursor, Int32(KSSC_MAX_STACK_DEPTH), context)

            var frames: [WalkedFrame] = []
            while cursor.pointee.advanceCursor(cursor) {
                _ = cursor.pointee.symbolicate(cursor)
                let symbolName = cursor.pointee.stackEntry.symbolName.map { String(cString: $0) }
                frames.append(WalkedFrame(symbolName: symbolName, method: kssc_getUnwindMethod(cursor)))
            }
            return frames
        }

        private static func asyncCallerFrameCount(in frames: [WalkedFrame]) -> Int {
            let expectedCallers = ["asyncOuter", "asyncMiddle"]
            return frames.filter { frame in
                guard let symbolName = frame.symbolName else { return false }
                return expectedCallers.contains { symbolName.contains($0) }
            }.count
        }

        func testCrashTimeUnwindRecoversAsyncCallerChain() throws {
            try XCTSkipIf(
                isRunningUnderSanitizer(),
                "Sanitizer interposer thunks can clobber x22 while this thread is suspended inside them; see isRunningUnderSanitizer()."
            )
            withSuspendedAsyncChain { machThread in
                kssc_setSwiftAsyncStackTracesEnabled(true)
                defer { kssc_setSwiftAsyncStackTracesEnabled(false) }

                let frames = walkUnwindCursor(machThread: machThread)
                let callerCount = Self.asyncCallerFrameCount(in: frames)

                XCTAssertGreaterThanOrEqual(
                    callerCount, 2,
                    "Crash-time unwind should recover the suspended Swift async caller chain. Frames: \(frames.map { $0.symbolName ?? "?" })"
                )
            }
        }

        func testCrashTimeUnwindWithFlagDisabledMatchesOldBehavior() {
            withSuspendedAsyncChain { machThread in
                kssc_setSwiftAsyncStackTracesEnabled(false)

                let frames = walkUnwindCursor(machThread: machThread)
                let callerCount = Self.asyncCallerFrameCount(in: frames)

                XCTAssertEqual(
                    callerCount, 0,
                    "Async caller frames must not appear when enableSwiftAsyncStackTraces is off. Frames: \(frames.map { $0.symbolName ?? "?" })"
                )
                XCTAssertFalse(
                    frames.contains { $0.method == KSUnwindMethod_SwiftAsync },
                    "No frame should be attributed to the Swift async walker when the flag is off."
                )
            }
        }

        func testCrashTimeUnwindOnNonAsyncThreadUnaffected() {
            withSuspendedSyncThread { machThread in
                kssc_setSwiftAsyncStackTracesEnabled(true)
                defer { kssc_setSwiftAsyncStackTracesEnabled(false) }

                let frames = walkUnwindCursor(machThread: machThread)

                XCTAssertFalse(
                    frames.contains { $0.method == KSUnwindMethod_SwiftAsync },
                    "A thread with no Swift async frames must not produce spurious async-walker frames. Frames: \(frames.map { $0.symbolName ?? "?" })"
                )
            }
        }

        func testSwiftAsyncFrameReportsCorrectUnwindMethod() throws {
            try XCTSkipIf(
                isRunningUnderSanitizer(),
                "Sanitizer interposer thunks can clobber x22 while this thread is suspended inside them; see isRunningUnderSanitizer()."
            )
            withSuspendedAsyncChain { machThread in
                kssc_setSwiftAsyncStackTracesEnabled(true)
                defer { kssc_setSwiftAsyncStackTracesEnabled(false) }

                let frames = walkUnwindCursor(machThread: machThread)

                XCTAssertTrue(
                    frames.contains { $0.method == KSUnwindMethod_SwiftAsync },
                    "At least one frame should be attributed to KSUnwindMethod_SwiftAsync. Frames: \(frames.map { $0.symbolName ?? "?" })"
                )
                XCTAssertTrue(
                    frames.contains { $0.method != KSUnwindMethod_SwiftAsync && $0.method != KSUnwindMethod_None },
                    "Physical frames before the async splice should still report their own unwind method."
                )
            }
        }
    }
#endif
