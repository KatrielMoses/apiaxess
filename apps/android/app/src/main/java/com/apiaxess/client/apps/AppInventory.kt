package com.apiaxess.client.apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

/** One installed app the user can choose to inspect. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val uid: Int,
    val isSystem: Boolean,
    val icon: Drawable?,
)

/**
 * Lists installed apps and resolves an app's Linux UID — the value the per-app
 * iptables `--uid-owner` rule is scoped by.
 */
class AppInventory(private val context: Context) {

    private val pm: PackageManager get() = context.packageManager

    /**
     * Returns launchable apps, third-party first, each with its resolved UID.
     * System apps are included but flagged so the UI can de-emphasise them.
     */
    fun installedApps(includeSystem: Boolean = true): List<InstalledApp> {
        val flags = PackageManager.GET_META_DATA
        val packages = pm.getInstalledApplications(flags)
        return packages.asSequence()
            .filter { info -> pm.getLaunchIntentForPackage(info.packageName) != null }
            .map { info -> info.toInstalledApp() }
            .filter { app -> includeSystem || !app.isSystem }
            .sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
            .toList()
    }

    /** Resolves an app's UID directly, e.g. to re-scope the redirect after reboot. */
    fun resolveUid(packageName: String): Int? =
        try {
            pm.getApplicationInfo(packageName, 0).uid
        } catch (error: PackageManager.NameNotFoundException) {
            null
        }

    private fun ApplicationInfo.toInstalledApp(): InstalledApp {
        val label = pm.getApplicationLabel(this).toString()
        val icon = runCatching { pm.getApplicationIcon(this) }.getOrNull()
        val isSystem = flags and ApplicationInfo.FLAG_SYSTEM != 0
        return InstalledApp(
            packageName = packageName,
            label = label,
            uid = uid,
            isSystem = isSystem,
            icon = icon,
        )
    }
}
