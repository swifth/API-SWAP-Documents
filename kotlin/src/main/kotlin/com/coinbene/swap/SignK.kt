package com.coinbene.swap;

import org.apache.commons.codec.digest.HmacUtils
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*


private fun ByteArray.toHex() = this.joinToString(separator = "") { it.toInt().and(0xff).toString(16).padStart(2, '0') }
private fun String.sha256(secretKey: String): ByteArray = HmacUtils.hmacSha256(secretKey, this)

class SignK(val apiKey: String, val apiSecret: String) {

    companion object {
        private val utcFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    }

    fun sign(method: String, requestUrl: String, body: String?): SortedMap<String, String> {
        val timestamp = utcFormatter.format(ZonedDateTime.now(ZoneOffset.UTC))
        val encryptText = "$timestamp${method.toUpperCase()}$requestUrl${body ?: ""}"
                .sha256(apiSecret)
                .toHex()

        val param = sortedMapOf(
                "ACCESS-KEY" to apiKey,
                "ACCESS-SIGN" to encryptText,
                "ACCESS-TIMESTAMP" to encryptText
        )

        return param
    }
}
