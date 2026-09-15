package com.apiaxess.client.capture

import com.apiaxess.client.core.ClientDiagnostic
import com.apiaxess.client.core.WorkbenchConfig
import com.apiaxess.client.root.RootShell

/**
 * Installs and removes the per-app capture redirect (Phase C3, requirements 1 & 4).
 *
 * Two rule families, both scoped by `-m owner --uid-owner <uid>` so ONLY the
 * chosen app is affected — per-app by construction, never the whole device:
 *
 *  1. nat OUTPUT: `REDIRECT --to-ports <relay>` sends the app's TCP to the local
 *     relay, preserving the original destination for `SO_ORIGINAL_DST`. No proxy
 *     setting, so proxy-ignoring apps are still captured.
 *  2. filter OUTPUT: REJECT UDP/443 so the app abandons QUIC/HTTP-3 and falls back
 *     to interceptable TLS-over-TCP. Non-negotiable — without it HTTP/3 vanishes.
 *
 * Rules are applied and removed by exact spec (no dependency on the xt_comment
 * module), and any pre-existing identical rule is deleted first for idempotency.
 */
class IptablesRedirector(private val relayPort: Int = WorkbenchConfig.RELAY_PORT) {

    /** Installs the redirect + QUIC block for [uid]. Returns null on success. */
    fun apply(uid: Int): ClientDiagnostic? {
        // Idempotency: clear any stale rules for this uid first.
        clear(uid)
        for (spec in redirectSpecs(uid)) {
            val result = RootShell.run("${spec.binary} ${spec.add()}")
            if (!result.ok) {
                clear(uid)
                return ClientDiagnostic.iptablesFailed(
                    "${spec.binary} ${spec.add()} -> ${result.stderr.ifBlank { "exit ${result.exitCode}" }}",
                )
            }
        }
        // IPv6 is best-effort: on devices without IPv6 the v6 rules simply no-op.
        for (spec in redirectSpecsV6(uid)) {
            RootShell.run("${spec.binary} ${spec.add()}")
        }
        return null
    }

    /** Removes every rule this class may have installed for [uid]. Best-effort. */
    fun clear(uid: Int) {
        for (spec in redirectSpecs(uid) + redirectSpecsV6(uid)) {
            // Delete repeatedly in case the same rule was added more than once.
            repeat(2) { RootShell.run("${spec.binary} ${spec.delete()}") }
        }
    }

    private fun redirectSpecs(uid: Int): List<RuleSpec> = listOf(
        RuleSpec(
            binary = "iptables",
            table = "nat",
            body = "OUTPUT -p tcp -m owner --uid-owner $uid ! -d 127.0.0.1/8 " +
                "-j REDIRECT --to-ports $relayPort",
        ),
        RuleSpec(
            binary = "iptables",
            table = "filter",
            body = "OUTPUT -p udp --dport 443 -m owner --uid-owner $uid " +
                "-j REJECT --reject-with icmp-port-unreachable",
        ),
    )

    private fun redirectSpecsV6(uid: Int): List<RuleSpec> = listOf(
        RuleSpec(
            binary = "ip6tables",
            table = "nat",
            body = "OUTPUT -p tcp -m owner --uid-owner $uid ! -d ::1/128 " +
                "-j REDIRECT --to-ports $relayPort",
        ),
        RuleSpec(
            binary = "ip6tables",
            table = "filter",
            body = "OUTPUT -p udp --dport 443 -m owner --uid-owner $uid " +
                "-j REJECT --reject-with icmp6-port-unreachable",
        ),
    )

    private data class RuleSpec(val binary: String, val table: String, val body: String) {
        fun add(): String = "-t $table -A $body"
        fun delete(): String = "-t $table -D $body"
    }
}
