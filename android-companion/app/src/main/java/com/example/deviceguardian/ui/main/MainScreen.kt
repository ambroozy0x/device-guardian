package com.example.deviceguardian.ui.main

import android.Manifest
import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.example.deviceguardian.data.PreferencesManager
import com.example.deviceguardian.network.TelegramClient
import com.example.deviceguardian.receiver.DeviceGuardianAdminReceiver
import com.example.deviceguardian.service.IntruderCaptureManager
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val prefs = remember { PreferencesManager(context) }

    var botToken by remember { mutableStateOf(prefs.botToken) }
    var chatId by remember { mutableStateOf(prefs.chatId) }
    var showToken by remember { mutableStateOf(false) }
    var threshold by remember { mutableIntStateOf(prefs.failedAttemptsThreshold) }
    var isVoiceEnabled by remember { mutableStateOf(prefs.isVoiceWarningEnabled) }
    var isGpsEnabled by remember { mutableStateOf(prefs.isGpsEnabled) }
    var isProtectionActive by remember { mutableStateOf(prefs.isProtectionActive) }

    var testStatusText by remember { mutableStateOf("") }
    var isTestingConnection by remember { mutableStateOf(false) }
    var isSimulatingAlert by remember { mutableStateOf(false) }

    // Device Admin status
    val devicePolicyManager = remember {
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    }
    val adminComponent = remember {
        ComponentName(context, DeviceGuardianAdminReceiver::class.java)
    }
    var isAdminActive by remember {
        mutableStateOf(devicePolicyManager.isAdminActive(adminComponent))
    }

    // Permission statuses
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }
    var hasLocationPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        )
    }

    // Activity result launcher for Device Admin activation
    val adminLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { _ ->
        isAdminActive = devicePolicyManager.isAdminActive(adminComponent)
    }

    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        hasCameraPermission = permissions[Manifest.permission.CAMERA] ?: false
        hasLocationPermission = permissions[Manifest.permission.ACCESS_FINE_LOCATION] ?: false
    }

    val isFullyConfigured = prefs.isTelegramConfigured() && isAdminActive && hasCameraPermission && hasLocationPermission

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("🛡️ Device Guardian", fontWeight = FontWeight.Bold)
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = MaterialTheme.colorScheme.primaryContainer,
                            modifier = Modifier.padding(horizontal = 4.dp)
                        ) {
                            Text(
                                "v1.0.0",
                                fontSize = 11.sp,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(modifier = Modifier.height(4.dp))

            // 1. Protection Status Card
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (isFullyConfigured && isProtectionActive)
                        Color(0xFF1B5E20).copy(alpha = 0.15f)
                    else
                        Color(0xFFE65100).copy(alpha = 0.15f)
                ),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = if (isFullyConfigured && isProtectionActive) "🟢 ARMED & PROTECTING" else "🟡 SETUP INCOMPLETE",
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            color = if (isFullyConfigured && isProtectionActive) Color(0xFF2E7D32) else Color(0xFFE65100)
                        )
                        Switch(
                            checked = isProtectionActive,
                            onCheckedChange = {
                                isProtectionActive = it
                                prefs.isProtectionActive = it
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = if (isFullyConfigured && isProtectionActive)
                            "Your phone is armed. Any incorrect lock screen attempt will trigger voice warning, capture front camera photos, and send GPS coordinates to your Telegram."
                        else
                            "Complete the items below to arm protection for your phone:",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(modifier = Modifier.height(10.dp))
                    StatusRow("Telegram Configured", prefs.isTelegramConfigured())
                    StatusRow("Device Admin Active", isAdminActive)
                    StatusRow("Camera Permission", hasCameraPermission)
                    StatusRow("GPS Location Permission", hasLocationPermission)
                }
            }

            // 2. Device Admin & Permissions Action Card
            if (!isAdminActive || !hasCameraPermission || !hasLocationPermission) {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f)
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("🔑 Required Permissions", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            "Device Admin allows detecting incorrect screen unlock attempts. Camera and Location permissions capture intruder selfies and GPS.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            if (!hasCameraPermission || !hasLocationPermission) {
                                Button(
                                    onClick = {
                                        permissionLauncher.launch(
                                            arrayOf(
                                                Manifest.permission.CAMERA,
                                                Manifest.permission.ACCESS_FINE_LOCATION,
                                                Manifest.permission.ACCESS_COARSE_LOCATION
                                            )
                                        )
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Grant Permissions", fontSize = 12.sp)
                                }
                            }

                            if (!isAdminActive) {
                                Button(
                                    onClick = {
                                        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                                            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent)
                                            putExtra(
                                                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                                                "Device Guardian requires Device Admin to detect failed screen lock attempts and trigger intruder alerts."
                                            )
                                        }
                                        adminLauncher.launch(intent)
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.tertiary),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Enable Admin", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }

            // 3. Telegram Configuration Card
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("🤖 Telegram Alert Settings", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = botToken,
                        onValueChange = { botToken = it },
                        label = { Text("Bot Token") },
                        placeholder = { Text("e.g. 123456789:ABCdefGhIjk...") },
                        singleLine = true,
                        visualTransformation = if (showToken) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        trailingIcon = {
                            TextButton(onClick = { showToken = !showToken }) {
                                Text(if (showToken) "Hide" else "Show", fontSize = 12.sp)
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = chatId,
                        onValueChange = { chatId = it },
                        label = { Text("Your Chat ID") },
                        placeholder = { Text("e.g. 8393885977") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Button(
                            onClick = {
                                prefs.botToken = botToken
                                prefs.chatId = chatId
                                Toast.makeText(context, "Telegram settings saved!", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Save Settings")
                        }

                        OutlinedButton(
                            onClick = {
                                if (botToken.isBlank() || chatId.isBlank()) {
                                    testStatusText = "⚠️ Please enter both Bot Token and Chat ID"
                                    return@OutlinedButton
                                }
                                prefs.botToken = botToken
                                prefs.chatId = chatId
                                isTestingConnection = true
                                testStatusText = "Connecting to Telegram..."

                                coroutineScope.launch {
                                    val result = TelegramClient.sendMessage(
                                        botToken = botToken,
                                        chatId = chatId,
                                        text = "✅ *Device Guardian Mobile Connected!*\n\nYour Android device is successfully linked to this Telegram alert bot."
                                    )
                                    isTestingConnection = false
                                    testStatusText = if (result.isSuccess) {
                                        "✅ Telegram Verified! Test message received on phone."
                                    } else {
                                        "❌ Failed: ${result.exceptionOrNull()?.message}"
                                    }
                                }
                            },
                            enabled = !isTestingConnection,
                            modifier = Modifier.weight(1f)
                        ) {
                            if (isTestingConnection) {
                                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            } else {
                                Text("Test Connection")
                            }
                        }
                    }

                    if (testStatusText.isNotBlank()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = testStatusText,
                            fontSize = 12.sp,
                            color = if (testStatusText.startsWith("✅")) Color(0xFF2E7D32) else Color(0xFFC62828),
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }

            // 4. Security Rules Card
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("⚙️ Intrusion Rules", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(modifier = Modifier.height(10.dp))

                    Text("Trigger Alert After Wrong Lock Attempts:", fontSize = 13.sp)
                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        listOf(1, 2, 3).forEach { count ->
                            FilterChip(
                                selected = threshold == count,
                                onClick = {
                                    threshold = count
                                    prefs.failedAttemptsThreshold = count
                                },
                                label = { Text("$count Attempt${if (count > 1) "s" else ""}") },
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))
                    Divider()
                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("🔊 Voice Warning", fontWeight = FontWeight.Medium, fontSize = 14.sp)
                            Text("Speaks aloud 'Warning: Intruder detected' upon failed unlocks", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Switch(
                            checked = isVoiceEnabled,
                            onCheckedChange = {
                                isVoiceEnabled = it
                                prefs.isVoiceWarningEnabled = it
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("📍 GPS Geolocation", fontWeight = FontWeight.Medium, fontSize = 14.sp)
                            Text("Attaches exact coordinates and Google Maps pin to alert", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Switch(
                            checked = isGpsEnabled,
                            onCheckedChange = {
                                isGpsEnabled = it
                                prefs.isGpsEnabled = it
                            }
                        )
                    }
                }
            }

            // 5. Simulate Alert Live Test
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("🧪 Verify Alert Pipeline", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Test full alert execution right now: captures a selfie photo, gets GPS coordinates, speaks voice warning, and sends the real alert to Telegram.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = {
                            if (!prefs.isTelegramConfigured()) {
                                Toast.makeText(context, "Please configure Telegram Bot Token and Chat ID first!", Toast.LENGTH_LONG).show()
                                return@Button
                            }
                            isSimulatingAlert = true
                            Toast.makeText(context, "Executing test alert...", Toast.LENGTH_SHORT).show()
                            coroutineScope.launch {
                                IntruderCaptureManager.triggerIntruderAlert(context, isTest = true)
                                isSimulatingAlert = false
                            }
                        },
                        enabled = !isSimulatingAlert && prefs.isTelegramConfigured(),
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isSimulatingAlert) {
                            CircularProgressIndicator(color = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Capturing & Dispatching Alert...")
                        } else {
                            Text("🚨 Simulate Intrusion Alert Now")
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun StatusRow(label: String, isOk: Boolean) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
    ) {
        Text(
            text = if (isOk) "✅" else "⚠️",
            fontSize = 13.sp,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(
            text = label,
            fontSize = 13.sp,
            fontWeight = if (isOk) FontWeight.Normal else FontWeight.Medium,
            color = if (isOk) MaterialTheme.colorScheme.onSurface else Color(0xFFE65100)
        )
    }
}
