package com.example.deviceguardian.service

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.view.WindowManager

class CaptureActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Show transparently over lock screen and wake display
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
            )
        }

        // Trigger intruder alert pipeline and close activity when complete
        IntruderCaptureManager.triggerIntruderAlert(this, isTest = false) {
            finish()
        }
    }
}
