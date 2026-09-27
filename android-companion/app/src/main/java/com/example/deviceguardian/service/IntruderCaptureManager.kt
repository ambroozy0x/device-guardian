package com.example.deviceguardian.service

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.*
import android.location.Location
import android.location.LocationManager
import android.media.ImageReader
import android.os.BatteryManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.speech.tts.TextToSpeech
import android.util.Log
import androidx.core.content.ContextCompat
import com.example.deviceguardian.data.PreferencesManager
import com.example.deviceguardian.network.TelegramClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.coroutines.resume

object IntruderCaptureManager {
    private const val TAG = "IntruderCaptureManager"
    private var textToSpeech: TextToSpeech? = null

    fun triggerIntruderAlert(context: Context, isTest: Boolean = false) {
        val prefs = PreferencesManager(context)
        if (!prefs.isProtectionActive && !isTest) {
            Log.d(TAG, "Protection is not active, ignoring trigger.")
            return
        }

        if (!prefs.isTelegramConfigured()) {
            Log.w(TAG, "Telegram is not configured, cannot send alert.")
            return
        }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                // 1. Voice Warning
                if (prefs.isVoiceWarningEnabled) {
                    speakVoiceWarning(context)
                }

                // 2. Fetch Battery
                val batteryLevel = getBatteryLevel(context)

                // 3. Fetch Location
                val location = if (prefs.isGpsEnabled) getLocation(context) else null

                // 4. Capture Front Camera Photos (Attempt burst of up to 3)
                val photos = mutableListOf<ByteArray>()
                if (hasCameraPermission(context)) {
                    val burstCount = if (isTest) 1 else 3
                    for (i in 1..burstCount) {
                        val photoBytes = captureFrontCameraPhoto(context)
                        if (photoBytes != null && photoBytes.isNotEmpty()) {
                            photos.add(photoBytes)
                        }
                        if (i < burstCount) {
                            delay(350)
                        }
                    }
                }

                // 5. Build Alert Message
                val timeStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
                val deviceName = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}"

                val locationText = if (location != null) {
                    val mapsUrl = "https://maps.google.com/?q=${location.latitude},${location.longitude}"
                    "📍 *Location*: [Google Maps Link]($mapsUrl)\n" +
                            "🌐 *Coordinates*: `${location.latitude}, ${location.longitude}` (±${location.accuracy.toInt()}m)"
                } else {
                    "📍 *Location*: Location unavailable or disabled"
                }

                val title = if (isTest) "🧪 *TEST SECURITY ALERT*" else "🚨 *INTRUSION ALERT - DEVICE GUARDIAN*"
                val caption = "$title\n\n" +
                        "📱 *Device*: $deviceName\n" +
                        "🔋 *Battery*: $batteryLevel%\n" +
                        "⏰ *Timestamp*: `$timeStr`\n" +
                        "$locationText\n\n" +
                        (if (isTest) "✅ This is a simulated test alert from your Android app." 
                         else "⚠️ Multiple failed lock screen attempts detected!")

                // 6. Send to Telegram
                if (photos.isNotEmpty()) {
                    for ((index, photo) in photos.withIndex()) {
                        val photoCaption = if (index == 0) caption else "Intruder frame ${index + 1}/3"
                        TelegramClient.sendPhoto(
                            botToken = prefs.botToken,
                            chatId = prefs.chatId,
                            photoBytes = photo,
                            caption = photoCaption,
                            fileName = "intruder_frame_${index + 1}.jpg"
                        )
                    }
                } else {
                    TelegramClient.sendMessage(
                        botToken = prefs.botToken,
                        chatId = prefs.chatId,
                        text = "$caption\n\n📷 _Camera capture was unavailable or permission not granted._"
                    )
                }

                // 7. Send Native Telegram Map Pin
                if (location != null) {
                    TelegramClient.sendLocation(
                        botToken = prefs.botToken,
                        chatId = prefs.chatId,
                        latitude = location.latitude,
                        longitude = location.longitude
                    )
                }

                Log.i(TAG, "Intruder alert dispatched successfully to Telegram.")
            } catch (e: Exception) {
                Log.e(TAG, "Error executing intruder alert: ${e.message}", e)
            }
        }
    }

    private fun speakVoiceWarning(context: Context) {
        Handler(Looper.getMainLooper()).post {
            try {
                if (textToSpeech == null) {
                    textToSpeech = TextToSpeech(context.applicationContext) { status ->
                        if (status == TextToSpeech.SUCCESS) {
                            textToSpeech?.language = Locale.US
                            textToSpeech?.speak(
                                "Warning! Unauthorized unlock attempts detected. Photos and GPS coordinates have been transmitted to the device owner.",
                                TextToSpeech.QUEUE_FLUSH,
                                null,
                                "DeviceGuardianWarning"
                            )
                        }
                    }
                } else {
                    textToSpeech?.speak(
                        "Warning! Unauthorized unlock attempts detected. Photos and GPS coordinates have been transmitted to the device owner.",
                        TextToSpeech.QUEUE_FLUSH,
                        null,
                        "DeviceGuardianWarning"
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Voice warning error: ${e.message}")
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun getLocation(context: Context): Location? {
        val fineGranted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        val coarseGranted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_COARSE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED

        if (!fineGranted && !coarseGranted) {
            return null
        }

        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return null

        var bestLocation: Location? = null
        try {
            val providers = locationManager.getProviders(true)
            for (provider in providers) {
                val l = locationManager.getLastKnownLocation(provider) ?: continue
                if (bestLocation == null || l.accuracy < bestLocation.accuracy) {
                    bestLocation = l
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get location: ${e.message}")
        }
        return bestLocation
    }

    private fun getBatteryLevel(context: Context): Int {
        val batteryIntent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) {
            (level * 100 / scale)
        } else {
            -1
        }
    }

    private fun hasCameraPermission(context: Context): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
    }

    @SuppressLint("MissingPermission")
    private suspend fun captureFrontCameraPhoto(context: Context): ByteArray? =
        suspendCancellableCoroutine { continuation ->
            val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager
            if (cameraManager == null) {
                continuation.resume(null)
                return@suspendCancellableCoroutine
            }

            try {
                // Find front-facing camera
                var frontCameraId: String? = null
                for (id in cameraManager.cameraIdList) {
                    val characteristics = cameraManager.getCameraCharacteristics(id)
                    val facing = characteristics.get(CameraCharacteristics.LENS_FACING)
                    if (facing == CameraCharacteristics.LENS_FACING_FRONT) {
                        frontCameraId = id
                        break
                    }
                }

                if (frontCameraId == null) {
                    // Fallback to first available camera if no front camera
                    frontCameraId = cameraManager.cameraIdList.firstOrNull()
                }

                if (frontCameraId == null) {
                    continuation.resume(null)
                    return@suspendCancellableCoroutine
                }

                val handlerThread = HandlerThread("DGCameraBackground").apply { start() }
                val backgroundHandler = Handler(handlerThread.looper)

                val imageReader = ImageReader.newInstance(640, 480, ImageFormat.JPEG, 2)
                var cameraDevice: CameraDevice? = null

                imageReader.setOnImageAvailableListener({ reader ->
                    try {
                        val image = reader.acquireLatestImage()
                        if (image != null) {
                            val buffer = image.planes[0].buffer
                            val bytes = ByteArray(buffer.remaining())
                            buffer.get(bytes)
                            image.close()

                            cameraDevice?.close()
                            imageReader.close()
                            handlerThread.quitSafely()

                            if (continuation.isActive) {
                                continuation.resume(bytes)
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error acquiring image: ${e.message}")
                        if (continuation.isActive) {
                            continuation.resume(null)
                        }
                    }
                }, backgroundHandler)

                cameraManager.openCamera(
                    frontCameraId,
                    object : CameraDevice.StateCallback() {
                        override fun onOpened(camera: CameraDevice) {
                            cameraDevice = camera
                            try {
                                val captureBuilder =
                                    camera.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE)
                                captureBuilder.addTarget(imageReader.surface)
                                captureBuilder.set(
                                    CaptureRequest.CONTROL_AF_MODE,
                                    CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE
                                )

                                camera.createCaptureSession(
                                    listOf(imageReader.surface),
                                    object : CameraCaptureSession.StateCallback() {
                                        override fun onConfigured(session: CameraCaptureSession) {
                                            try {
                                                session.capture(
                                                    captureBuilder.build(),
                                                    null,
                                                    backgroundHandler
                                                )
                                            } catch (e: Exception) {
                                                Log.e(TAG, "Session capture error: ${e.message}")
                                                camera.close()
                                                if (continuation.isActive) continuation.resume(null)
                                            }
                                        }

                                        override fun onConfigureFailed(session: CameraCaptureSession) {
                                            camera.close()
                                            if (continuation.isActive) continuation.resume(null)
                                        }
                                    },
                                    backgroundHandler
                                )
                            } catch (e: Exception) {
                                Log.e(TAG, "Camera configuration error: ${e.message}")
                                camera.close()
                                if (continuation.isActive) continuation.resume(null)
                            }
                        }

                        override fun onDisconnected(camera: CameraDevice) {
                            camera.close()
                            if (continuation.isActive) continuation.resume(null)
                        }

                        override fun onError(camera: CameraDevice, error: Int) {
                            camera.close()
                            if (continuation.isActive) continuation.resume(null)
                        }
                    },
                    backgroundHandler
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error opening front camera: ${e.message}")
                if (continuation.isActive) {
                    continuation.resume(null)
                }
            }
        }
}
