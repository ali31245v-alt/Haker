package com.at.shield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.Locale
import kotlin.concurrent.thread

class DnsFilterVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "com.at.shield.action.STOP"
        private const val CHANNEL_ID = "haker_dns_filter"
        private const val NOTIFICATION_ID = 42
        private const val DNS_IP = "10.111.0.2"
        private const val UPSTREAM_DNS = "1.1.1.1"
    }

    @Volatile private var running = false
    @Volatile private var tun: ParcelFileDescriptor? = null
    private val blockedDomains by lazy { loadBlocklist() }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            running = false
            stopSelf()
            return START_NOT_STICKY
        }

        createNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        if (tun == null) {
            val descriptor = Builder()
                .setSession("Haker Shield DNS")
                .setMtu(1500)
                .addAddress("10.111.0.1", 32)
                .addDnsServer(DNS_IP)
                .addRoute(DNS_IP, 32)
                .setBlocking(true)
                .establish()

            if (descriptor == null) {
                stopSelf()
                return START_NOT_STICKY
            }

            tun = descriptor
            running = true
            thread(name = "haker-dns-tunnel") { runTunnel(descriptor) }
        }
        return START_STICKY
    }

    private fun runTunnel(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (running) {
                val count = input.read(buffer)
                if (count <= 0) continue
                val packet = buffer.copyOf(count)
                val response = processPacket(packet) ?: continue
                output.write(response)
            }
        } catch (_: Exception) {
            // Closing the VPN descriptor when the service stops ends this loop.
        } finally {
            try { input.close() } catch (_: Exception) {}
            try { output.close() } catch (_: Exception) {}
        }
    }

    private fun processPacket(packet: ByteArray): ByteArray? {
        if (packet.size < 28) return null
        if ((packet[0].toInt() and 0xF0) != 0x40) return null
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (ipHeaderLength < 20 || packet.size < ipHeaderLength + 8) return null
        if ((packet[9].toInt() and 0xFF) != 17) return null // UDP only

        val udpOffset = ipHeaderLength
        val destinationPort = readU16(packet, udpOffset + 2)
        if (destinationPort != 53) return null

        val dnsOffset = udpOffset + 8
        val dnsLength = readU16(packet, udpOffset + 4) - 8
        if (dnsLength < 12 || dnsOffset + dnsLength > packet.size) return null
        val query = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val domain = readQuestionName(query) ?: return null

        val dnsResponse = if (isBlocked(domain)) {
            makeBlockedResponse(query)
        } else {
            queryUpstream(query) ?: return null
        }
        return makeIpv4UdpResponse(packet, ipHeaderLength, udpOffset, dnsResponse)
    }

    private fun readQuestionName(dns: ByteArray): String? {
        if (dns.size < 17) return null
        var offset = 12
        val labels = ArrayList<String>()
        while (offset < dns.size) {
            val length = dns[offset++].toInt() and 0xFF
            if (length == 0) break
            if ((length and 0xC0) != 0 || length > 63 || offset + length > dns.size) return null
            labels.add(String(dns, offset, length, Charsets.US_ASCII).lowercase(Locale.ROOT))
            offset += length
        }
        if (labels.isEmpty() || offset + 4 > dns.size) return null
        return labels.joinToString(".")
    }

    private fun isBlocked(domain: String): Boolean =
        blockedDomains.any { domain == it || domain.endsWith(".$it") }

    private fun makeBlockedResponse(query: ByteArray): ByteArray {
        val response = query.copyOf()
        response[2] = 0x81.toByte() // response + recursion desired
        response[3] = 0x83.toByte() // recursion available + NXDOMAIN
        for (i in 6..11) response[i] = 0
        return response
    }

    private fun queryUpstream(query: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                if (!protect(socket)) return null
                socket.soTimeout = 2500
                val address = InetAddress.getByName(UPSTREAM_DNS)
                socket.send(DatagramPacket(query, query.size, address, 53))
                val buffer = ByteArray(4096)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                buffer.copyOf(response.length)
            }
        } catch (_: SocketTimeoutException) {
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun makeIpv4UdpResponse(
        original: ByteArray,
        ipHeaderLength: Int,
        udpOffset: Int,
        dnsResponse: ByteArray
    ): ByteArray? {
        val totalLength = ipHeaderLength + 8 + dnsResponse.size
        if (totalLength > 65535) return null
        val result = ByteArray(totalLength)
        System.arraycopy(original, 0, result, 0, ipHeaderLength)

        // Swap IPv4 source and destination.
        for (i in 0 until 4) {
            result[12 + i] = original[16 + i]
            result[16 + i] = original[12 + i]
        }

        // Swap UDP ports and set the response length.
        result[udpOffset] = original[udpOffset + 2]
        result[udpOffset + 1] = original[udpOffset + 3]
        result[udpOffset + 2] = original[udpOffset]
        result[udpOffset + 3] = original[udpOffset + 1]
        writeU16(result, udpOffset + 4, 8 + dnsResponse.size)
        result[udpOffset + 6] = 0
        result[udpOffset + 7] = 0
        System.arraycopy(dnsResponse, 0, result, udpOffset + 8, dnsResponse.size)

        writeU16(result, 2, totalLength)
        result[10] = 0
        result[11] = 0
        writeU16(result, 10, ipv4Checksum(result, ipHeaderLength))
        return result
    }

    private fun ipv4Checksum(data: ByteArray, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i < length) {
            sum += (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun writeU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value shr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }

    private fun loadBlocklist(): Set<String> = try {
        assets.open("blocklist.txt").bufferedReader().useLines { lines ->
            lines.map { it.substringBefore('#').trim().lowercase(Locale.ROOT) }
                .filter { it.isNotEmpty() && !it.contains(' ') }
                .toSet()
        }
    } catch (_: Exception) {
        emptySet()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Haker Shield protection", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows when DNS filtering is active" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder
            .setContentTitle("Haker Shield")
            .setContentText("فلترة DNS مفعّلة — اضغط لفتح التطبيق")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        running = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        super.onDestroy()
    }
}
