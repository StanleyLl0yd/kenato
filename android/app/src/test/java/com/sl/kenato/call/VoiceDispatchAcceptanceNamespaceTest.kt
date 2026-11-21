package com.sl.kenato.call

import org.junit.Assert.assertThrows
import org.junit.Test

/** Pure scope tests. No Android Keystore, device, or live dispatch was executed. */
class VoiceDispatchAcceptanceNamespaceTest {
    @Test
    fun onlyFresh128BitAcceptanceAliasShapeIsAllowed() {
        VoiceDispatchAcceptanceNamespace.requireAliasPrefix(
            "com.sl.kenato.dispatch.epoch-acceptance.v1." + "a".repeat(32) + "."
        )
        for (candidate in listOf(
            "com.sl.kenato.dispatch.epoch-continuity.v1." + "a".repeat(32) + ".",
            "com.sl.kenato.session.epoch-acceptance.v1." + "a".repeat(32) + ".",
            "com.sl.kenato.dispatch.epoch-acceptance.v1.",
            "com.sl.kenato.dispatch.epoch-acceptance.v1." + "a".repeat(31) + ".",
            "com.sl.kenato.dispatch.epoch-acceptance.v1." + "A".repeat(32) + ".",
            "../com.sl.kenato.dispatch.epoch-acceptance.v1." + "a".repeat(32) + ".",
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                VoiceDispatchAcceptanceNamespace.requireAliasPrefix(candidate)
            }
        }
    }

    @Test
    fun onlyDisposableDispatchProbeFilesAreAllowed() {
        VoiceDispatchAcceptanceNamespace.requireFileName(
            "kenato_m5_dispatch_probe_" + "f".repeat(32) + ".bin"
        )
        for (candidate in listOf(
            "kenato_voice_replay_v1.state",
            "kenato_m5_voice_capabilities_v1.enc",
            "kenato_m5_dispatch_probe_" + "f".repeat(31) + ".bin",
            "kenato_m5_dispatch_probe_" + "F".repeat(32) + ".bin",
            "../kenato_m5_dispatch_probe_" + "f".repeat(32) + ".bin",
            "kenato_m5_dispatch_probe_" + "f".repeat(32) + ".bin.tmp",
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                VoiceDispatchAcceptanceNamespace.requireFileName(candidate)
            }
        }
    }
}
