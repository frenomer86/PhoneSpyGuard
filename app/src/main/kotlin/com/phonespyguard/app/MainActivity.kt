package com.phonespyguard.app

import android.Manifest
import android.app.ActivityManager
import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.phonespyguard.app.security.AppLock
import com.phonespyguard.app.ui.SafetyScreen
import com.phonespyguard.app.ui.ScanScreen
import com.phonespyguard.app.ui.ScanViewModel

/**
 * The single screen host. It is locked behind the device credential before any
 * result is shown (review C4), marks its window [WindowManager.LayoutParams.FLAG_SECURE]
 * so results never appear in screenshots or the recents preview, and offers a
 * quick exit that drops the app from recents.
 */
public class MainActivity : FragmentActivity() {

    private val viewModel: ScanViewModel by viewModels()

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* best effort */ }

    // The unlock state lives on the activity, not inside a composable, so it can
    // be cleared when the app goes to the background (review N4): whoever resumes
    // the app next must unlock again.
    private var unlocked by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep results out of screenshots and the recents thumbnail (NFR-SEC-08).
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        markAccessibilityDataSensitive()
        setNeutralTaskDescription()
        maybeAskForNotifications()

        setContent {
            MaterialTheme {
                Surface {
                    if (!unlocked) {
                        LockGate(onUnlock = { unlocked = true }, onExit = ::quickExit)
                    } else {
                        MainTabs()
                    }
                }
            }
        }
    }

    /** Relock whenever the app leaves the foreground (review N4). */
    override fun onStop() {
        super.onStop()
        unlocked = false
    }

    /**
     * On Android 14+ mark the whole UI as accessibility-data-sensitive, so an
     * accessibility service (the main stalkerware channel) cannot read the
     * results or evidence off the screen (NFR-SEC-08, review N4).
     */
    private fun markAccessibilityDataSensitive() {
        if (Build.VERSION.SDK_INT >= 34) {
            runCatching {
                window.decorView.setAccessibilityDataSensitive(
                    android.view.View.ACCESSIBILITY_DATA_SENSITIVE_YES,
                )
            }
        }
    }

    @androidx.compose.runtime.Composable
    private fun LockGate(onUnlock: () -> Unit, onExit: () -> Unit) {
        val appPin = remember { com.phonespyguard.app.security.AppPin(this@MainActivity) }
        val usePin = remember { appPin.isSet() }
        Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
            Text("This app is locked", style = MaterialTheme.typography.headlineSmall)
            if (usePin) {
                var entry by remember { mutableStateOf("") }
                var error by remember { mutableStateOf(false) }
                Text(
                    "Enter your app PIN to see your results. This PIN is separate from " +
                        "your phone's screen lock.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(vertical = 12.dp),
                )
                androidx.compose.material3.OutlinedTextField(
                    value = entry,
                    onValueChange = { entry = it; error = false },
                    label = { Text("App PIN") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword,
                    ),
                )
                if (error) {
                    Text(
                        "That PIN didn't match.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Button(
                    onClick = { if (appPin.verify(entry)) onUnlock() else error = true },
                    modifier = Modifier.padding(top = 8.dp),
                ) { Text("Unlock") }
            } else {
                Text(
                    "Unlock with your fingerprint or screen lock to see your results. " +
                        "This keeps them private if someone else picks up your phone.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(vertical = 12.dp),
                )
                Button(onClick = { AppLock.prompt(this@MainActivity) { ok -> if (ok) onUnlock() } }) {
                    Text("Unlock")
                }
            }
            Button(onClick = onExit, modifier = Modifier.padding(top = 8.dp)) { Text("Quick exit") }
        }
    }

    @androidx.compose.runtime.Composable
    private fun MainTabs() {
        var tab by remember { mutableIntStateOf(0) }
        // The app does one job: check this device for spyware/stalkerware and
        // keep a tamper-evident record. Device check runs the scan and folds the
        // safety guidance into its results; Safety holds the evidence export, the
        // app PIN and the privacy toggles.
        val titles = listOf("Device check", "Safety")
        Column(modifier = Modifier.fillMaxSize()) {
            ScrollableTabRow(selectedTabIndex = tab) {
                titles.forEachIndexed { i, title ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(title) })
                }
            }
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                when (tab) {
                    0 -> ScanScreen(viewModel, onQuickExit = ::quickExit)
                    else -> SafetyScreen(onQuickExit = ::quickExit)
                }
            }
        }
    }

    /** Leave at once and drop the app from the recents list (FR-SAF-02). */
    private fun quickExit() {
        finishAndRemoveTask()
        startActivity(
            Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            },
        )
    }

    private fun setNeutralTaskDescription() {
        runCatching {
            val icon = BitmapFactory.decodeResource(resources, android.R.drawable.ic_popup_sync)
            @Suppress("DEPRECATION")
            setTaskDescription(ActivityManager.TaskDescription("Sync", icon))
        }
    }

    private fun maybeAskForNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
