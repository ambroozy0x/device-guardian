package com.example.deviceguardian.receiver

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.os.UserHandle
import android.util.Log
import android.widget.Toast
import com.example.deviceguardian.data.PreferencesManager
import com.example.deviceguardian.service.IntruderCaptureManager

class DeviceGuardianAdminReceiver : DeviceAdminReceiver() {

    override fun onPasswordFailed(context: Context, intent: Intent, user: UserHandle) {
        super.onPasswordFailed(context, intent, user)
        val prefs = PreferencesManager(context)
        val currentCount = prefs.failedAttemptsCount + 1
        prefs.failedAttemptsCount = currentCount
        Log.w(TAG, "Screen unlock failed! Count: $currentCount (Threshold: ${prefs.failedAttemptsThreshold})")

        if (currentCount >= prefs.failedAttemptsThreshold) {
            Log.i(TAG, "Threshold reached! Triggering intruder alert pipeline...")
            try {
                val captureIntent = Intent(context, com.example.deviceguardian.service.CaptureActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
                }
                context.startActivity(captureIntent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to launch CaptureActivity, falling back to direct background alert: ${e.message}")
                IntruderCaptureManager.triggerIntruderAlert(context, isTest = false)
            }
        }
    }

    override fun onPasswordSucceeded(context: Context, intent: Intent, user: UserHandle) {
        super.onPasswordSucceeded(context, intent, user)
        val prefs = PreferencesManager(context)
        if (prefs.failedAttemptsCount > 0) {
            Log.i(TAG, "Device unlocked successfully. Resetting failed attempts count to 0.")
            prefs.failedAttemptsCount = 0
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Toast.makeText(context, "Device Guardian Lock Protection Enabled", Toast.LENGTH_SHORT).show()
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        Toast.makeText(context, "Device Guardian Lock Protection Disabled", Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val TAG = "DGAdminReceiver"
    }
}
