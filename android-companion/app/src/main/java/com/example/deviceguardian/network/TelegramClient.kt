package com.example.deviceguardian.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

object TelegramClient {
    private const val TAG = "DeviceGuardian_TG"
    private const val BASE_URL = "https://api.telegram.org/bot"

    suspend fun sendMessage(botToken: String, chatId: String, text: String): Result<Boolean> =
        withContext(Dispatchers.IO) {
            try {
                val encodedText = URLEncoder.encode(text, "UTF-8")
                val urlString = "$BASE_URL$botToken/sendMessage?chat_id=$chatId&text=$encodedText&parse_mode=Markdown"
                val url = URL(urlString)
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 15000
                    readTimeout = 15000
                }

                val responseCode = conn.responseCode
                if (responseCode == 200) {
                    Result.success(true)
                } else {
                    val errorBody = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
                    Log.e(TAG, "sendMessage error ($responseCode): $errorBody")
                    Result.failure(Exception("Telegram API Error $responseCode: $errorBody"))
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendMessage failed: ${e.message}", e)
                Result.failure(e)
            }
        }

    suspend fun sendPhoto(
        botToken: String,
        chatId: String,
        photoBytes: ByteArray,
        caption: String = "",
        fileName: String = "intruder.jpg"
    ): Result<Boolean> = withContext(Dispatchers.IO) {
        val boundary = "====DG" + System.currentTimeMillis() + "===="
        val lineEnd = "\r\n"
        val twoHyphens = "--"

        try {
            val url = URL("$BASE_URL$botToken/sendPhoto")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doInput = true
                doOutput = true
                useCaches = false
                connectTimeout = 20000
                readTimeout = 20000
                setRequestProperty("Connection", "Keep-Alive")
                setRequestProperty("Content-Type", "multipart/form-data;boundary=$boundary")
            }

            DataOutputStream(conn.outputStream).use { dos ->
                // Chat ID part
                dos.writeBytes(twoHyphens + boundary + lineEnd)
                dos.writeBytes("Content-Disposition: form-data; name=\"chat_id\"$lineEnd$lineEnd")
                dos.writeBytes(chatId + lineEnd)

                // Caption part
                if (caption.isNotBlank()) {
                    dos.writeBytes(twoHyphens + boundary + lineEnd)
                    dos.writeBytes("Content-Disposition: form-data; name=\"caption\"$lineEnd$lineEnd")
                    dos.write(caption.toByteArray(Charsets.UTF_8))
                    dos.writeBytes(lineEnd)
                }

                // Photo part
                dos.writeBytes(twoHyphens + boundary + lineEnd)
                dos.writeBytes("Content-Disposition: form-data; name=\"photo\"; filename=\"$fileName\"$lineEnd")
                dos.writeBytes("Content-Type: image/jpeg$lineEnd$lineEnd")
                dos.write(photoBytes)
                dos.writeBytes(lineEnd)

                // End boundary
                dos.writeBytes(twoHyphens + boundary + twoHyphens + lineEnd)
                dos.flush()
            }

            val responseCode = conn.responseCode
            if (responseCode == 200) {
                Result.success(true)
            } else {
                val errorBody = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
                Log.e(TAG, "sendPhoto error ($responseCode): $errorBody")
                Result.failure(Exception("Telegram API Error $responseCode: $errorBody"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendPhoto failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    suspend fun sendLocation(
        botToken: String,
        chatId: String,
        latitude: Double,
        longitude: Double
    ): Result<Boolean> = withContext(Dispatchers.IO) {
        try {
            val urlString = "$BASE_URL$botToken/sendLocation?chat_id=$chatId&latitude=$latitude&longitude=$longitude"
            val url = URL(urlString)
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 15000
                readTimeout = 15000
            }

            val responseCode = conn.responseCode
            if (responseCode == 200) {
                Result.success(true)
            } else {
                val errorBody = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
                Log.e(TAG, "sendLocation error ($responseCode): $errorBody")
                Result.failure(Exception("Telegram API Error $responseCode: $errorBody"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendLocation failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    suspend fun verifyBotToken(botToken: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            val url = URL("$BASE_URL$botToken/getMe")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 10000
                readTimeout = 10000
            }
            if (conn.responseCode == 200) {
                val response = conn.inputStream.bufferedReader().use { it.readText() }
                val json = JSONObject(response)
                val ok = json.optBoolean("ok", false)
                if (ok) {
                    val result = json.getJSONObject("result")
                    val username = result.optString("username", "Bot")
                    Result.success(username)
                } else {
                    Result.failure(Exception("Invalid Bot Token response"))
                }
            } else {
                Result.failure(Exception("Bot verification failed with HTTP ${conn.responseCode}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
