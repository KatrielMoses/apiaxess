package com.apiaxess.client.root

import java.io.BufferedReader
import java.io.DataOutputStream
import java.util.concurrent.TimeUnit

/** Result of a root command: exit code plus captured stdout/stderr. */
data class ShellResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
) {
    val ok: Boolean get() = exitCode == 0
}

/**
 * Runs commands as root through `su`. A single persistent `su` shell would be
 * faster, but per-invocation `su -c` keeps the surface minimal and is plenty for
 * the handful of iptables/getprop calls this client makes.
 */
object RootShell {

    /** Whether a working `su` is present and grants uid=0. */
    fun isRootAvailable(): Boolean {
        return try {
            val result = run(listOf("id"), timeoutSeconds = 10)
            result.ok && result.stdout.contains("uid=0")
        } catch (error: Exception) {
            false
        }
    }

    /**
     * Runs one shell command line as root. Commands are passed to `su -c` as a
     * single program string executed by the guest shell.
     */
    fun run(commands: List<String>, timeoutSeconds: Long = 30): ShellResult {
        val script = commands.joinToString("\n")
        val process = ProcessBuilder("su").redirectErrorStream(false).start()
        DataOutputStream(process.outputStream).use { stdin ->
            stdin.writeBytes(script)
            stdin.writeBytes("\n")
            stdin.writeBytes("exit\n")
            stdin.flush()
        }
        val stdout = readFully(process.inputStream.bufferedReader())
        val stderr = readFully(process.errorStream.bufferedReader())
        val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            return ShellResult(exitCode = -1, stdout = stdout, stderr = "timed out after ${timeoutSeconds}s")
        }
        return ShellResult(process.exitValue(), stdout.trim(), stderr.trim())
    }

    /** Convenience for a single command string. */
    fun run(command: String, timeoutSeconds: Long = 30): ShellResult =
        run(listOf(command), timeoutSeconds)

    private fun readFully(reader: BufferedReader): String =
        reader.use { it.readText() }
}
