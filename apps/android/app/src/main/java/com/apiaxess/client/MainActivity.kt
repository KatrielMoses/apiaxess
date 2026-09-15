package com.apiaxess.client

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.apiaxess.client.ui.ClientApp
import com.apiaxess.client.ui.theme.ApiaxessTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ApiaxessTheme {
                ClientApp()
            }
        }
    }
}
