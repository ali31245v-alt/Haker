package com.at.shield

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import java.security.MessageDigest

class MainActivity : ComponentActivity() {
    private val prefs by lazy { getSharedPreferences("haker_settings", MODE_PRIVATE) }
    private val protectionOn = mutableStateOf(false)

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startProtection()
            protectionOn.value = true
        } else {
            Toast.makeText(this, "لم يتم منح إذن VPN", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        protectionOn.value = prefs.getBoolean("protection_on", false)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(
                primary = Color(0xFF00D9FF),
                secondary = Color(0xFF1677FF),
                background = Color(0xFF050816),
                surface = Color(0xFF0D1730)
            )) {
                Surface(Modifier.fillMaxSize(), color = Color(0xFF050816)) {
                    AppScreen()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        protectionOn.value = prefs.getBoolean("protection_on", false)
    }

    private fun startProtection() {
        prefs.edit().putBoolean("protection_on", true).apply()
        ContextCompat.startForegroundService(this, Intent(this, DnsFilterVpnService::class.java))
    }

    private fun stopProtection() {
        prefs.edit().putBoolean("protection_on", false).apply()
        startService(Intent(this, DnsFilterVpnService::class.java).setAction(DnsFilterVpnService.ACTION_STOP))
    }

    private fun requestProtection() {
        val request = VpnService.prepare(this)
        if (request != null) vpnPermissionLauncher.launch(request) else {
            startProtection()
            protectionOn.value = true
        }
    }

    @Composable
    private fun AppScreen() {
        val savedHash = prefs.getString("pin_hash", null)
        var hasPin by remember { mutableStateOf(savedHash != null) }
        var unlocked by remember { mutableStateOf(savedHash == null) }
        var pin by remember { mutableStateOf("") }
        var pinError by remember { mutableStateOf("") }

        Column(
            modifier = Modifier.fillMaxSize().background(Color(0xFF050816)).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("HAKER", color = Color(0xFF00D9FF), fontSize = 14.sp, letterSpacing = 5.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Text("SHIELD", color = Color.White, fontSize = 34.sp, fontWeight = FontWeight.ExtraBold)
            Spacer(Modifier.height(8.dp))
            Text("حماية DNS بواجهة واضحة وتحكم بإيدك", color = Color(0xFF9FB4D8), fontSize = 14.sp)
            Spacer(Modifier.height(28.dp))

            if (!unlocked) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1730))
                ) {
                    Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("أدخل الرمز السري", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(14.dp))
                        OutlinedTextField(
                            value = pin,
                            onValueChange = { pin = it.filter(Char::isDigit).take(12); pinError = "" },
                            label = { Text("الرمز السري") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
                        )
                        if (pinError.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text(pinError, color = Color(0xFFFF7272))
                        }
                        Spacer(Modifier.height(14.dp))
                        Button(onClick = {
                            val expected = prefs.getString("pin_hash", null)
                            if (expected == hashPin(pin)) {
                                unlocked = true
                                pin = ""
                            } else pinError = "الرمز غير صحيح"
                        }, modifier = Modifier.fillMaxWidth()) { Text("فتح التطبيق") }
                    }
                }
            } else if (!hasPin) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1730))
                ) {
                    Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("أنشئ رمزك السري", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Text("أدخل 4 أرقام على الأقل لحماية إعدادات التطبيق.", color = Color(0xFF9FB4D8))
                        Spacer(Modifier.height(14.dp))
                        OutlinedTextField(
                            value = pin,
                            onValueChange = { pin = it.filter(Char::isDigit).take(12); pinError = "" },
                            label = { Text("رمز من 4 أرقام أو أكثر") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
                        )
                        if (pinError.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text(pinError, color = Color(0xFFFF7272))
                        }
                        Spacer(Modifier.height(14.dp))
                        Button(onClick = {
                            if (pin.length >= 4) {
                                prefs.edit().putString("pin_hash", hashPin(pin)).apply()
                                hasPin = true
                                unlocked = true
                                pin = ""
                            } else pinError = "لازم الرمز يكون 4 أرقام على الأقل"
                        }, modifier = Modifier.fillMaxWidth()) { Text("حفظ الرمز") }
                    }
                }
            } else {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1730))
                ) {
                    Column(Modifier.padding(20.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(if (protectionOn.value) "●" else "●", color = if (protectionOn.value) Color(0xFF31E6A0) else Color(0xFFFF7272), fontSize = 22.sp)
                            Spacer(Modifier.padding(horizontal = 5.dp))
                            Column {
                                Text(if (protectionOn.value) "الحماية مفعّلة" else "الحماية متوقفة", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                                Text("فلترة طلبات DNS عبر VPN محلي", color = Color(0xFF9FB4D8), fontSize = 12.sp)
                            }
                        }
                        Spacer(Modifier.height(20.dp))
                        Button(
                            onClick = {
                                if (protectionOn.value) {
                                    stopProtection()
                                    protectionOn.value = false
                                } else requestProtection()
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = if (protectionOn.value) Color(0xFFB93A4A) else Color(0xFF087EAD))
                        ) {
                            Text(if (protectionOn.value) "إيقاف الحماية" else "تفعيل الحماية")
                        }
                        Spacer(Modifier.height(12.dp))
                        Text("يستخدم التطبيق قائمة حجب أولية قابلة للتعديل داخل ملفات المشروع.", color = Color(0xFF9FB4D8), fontSize = 12.sp)
                    }
                }
                Spacer(Modifier.height(16.dp))
                Text("التطبيق ظاهر ويمكن إيقافه أو حذفه من إعدادات Android بشكل طبيعي.", color = Color(0xFF6F85AA), fontSize = 11.sp)
            }
        }
    }

    private fun hashPin(pin: String): String =
        MessageDigest.getInstance("SHA-256").digest(pin.toByteArray()).joinToString("") { "%02x".format(it) }
}
