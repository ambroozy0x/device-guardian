package com.example.deviceguardian.data

import android.content.Context
import android.content.SharedPreferences

class PreferencesManager(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("device_guardian_prefs", Context.MODE_PRIVATE)

    var botToken: String
        get() = prefs.getString(KEY_BOT_TOKEN, "") ?: ""
        set(value) = prefs.edit().putString(KEY_BOT_TOKEN, value.trim()).apply()

    var chatId: String
        get() = prefs.getString(KEY_CHAT_ID, "") ?: ""
        set(value) = prefs.edit().putString(KEY_CHAT_ID, value.trim()).apply()

    var failedAttemptsThreshold: Int
        get() = prefs.getInt(KEY_FAILED_THRESHOLD, 2)
        set(value) = prefs.edit().putInt(KEY_FAILED_THRESHOLD, value).apply()

    var isVoiceWarningEnabled: Boolean
        get() = prefs.getBoolean(KEY_VOICE_WARNING, true)
        set(value) = prefs.edit().putBoolean(KEY_VOICE_WARNING, value).apply()

    var isGpsEnabled: Boolean
        get() = prefs.getBoolean(KEY_GPS_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_GPS_ENABLED, value).apply()

    var isProtectionActive: Boolean
        get() = prefs.getBoolean(KEY_PROTECTION_ACTIVE, true)
        set(value) = prefs.edit().putBoolean(KEY_PROTECTION_ACTIVE, value).apply()

    var failedAttemptsCount: Int
        get() = prefs.getInt(KEY_CURRENT_FAILED_COUNT, 0)
        set(value) = prefs.edit().putInt(KEY_CURRENT_FAILED_COUNT, value).apply()

    fun isTelegramConfigured(): Boolean {
        return botToken.isNotBlank() && chatId.isNotBlank()
    }

    companion object {
        private const val KEY_BOT_TOKEN = "telegram_bot_token"
        private const val KEY_CHAT_ID = "telegram_chat_id"
        private const val KEY_FAILED_THRESHOLD = "failed_attempts_threshold"
        private const val KEY_VOICE_WARNING = "voice_warning_enabled"
        private const val KEY_GPS_ENABLED = "gps_enabled"
        private const val KEY_PROTECTION_ACTIVE = "protection_active"
        private const val KEY_CURRENT_FAILED_COUNT = "current_failed_count"
    }
}
