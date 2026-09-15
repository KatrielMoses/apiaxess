package com.apiaxess.client

import android.app.Application
import com.apiaxess.client.service.CaptureManager

/** Application entry point; initialises the process-wide capture manager. */
class ApiaxessApp : Application() {
    override fun onCreate() {
        super.onCreate()
        CaptureManager.ensureInitialised(this)
    }
}
