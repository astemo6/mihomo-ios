package io.github.astemo6.mihomo.ui.components

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color as AColor
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.ui.theme.LocalAppColors

/** QR codes: ZXing core encodes share links / subscription URLs; zxing-android-embedded scans them. */
object QrCodes {
    /** Byte-mode capacity of a version-40 QR code at error correction level L. */
    const val MAX_BYTES = 2953

    fun fits(text: String): Boolean = text.isNotEmpty() && text.toByteArray(Charsets.UTF_8).size <= MAX_BYTES

    /** Black-on-white QR bitmap (one pixel per module plus a quiet zone; scale it up with nearest-neighbour). Null when too long. */
    fun encode(text: String): Bitmap? {
        if (!fits(text)) return null
        return runCatching {
            val hints = mapOf(
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.MARGIN to 2,
                // Short links get more redundancy; long subscriptions need the capacity of level L.
                EncodeHintType.ERROR_CORRECTION to if (text.length < 600) ErrorCorrectionLevel.M else ErrorCorrectionLevel.L,
            )
            val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
            val w = m.width
            val h = m.height
            val px = IntArray(w * h) { i -> if (m.get(i % w, i / w)) AColor.BLACK else AColor.WHITE }
            Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888)
        }.getOrNull()
    }
}

/**
 * Returns a launcher that asks for the camera permission (if needed), opens the ZXing scanner and passes the
 * decoded text to [onResult]. Cancelling does nothing; a denied permission shows a toast.
 */
@Composable
fun rememberQrScanner(onResult: (String) -> Unit): () -> Unit {
    val context = LocalContext.current
    val prompt = stringResource(R.string.qr_scan_prompt)
    val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
        val text = r.contents
        if (!text.isNullOrBlank()) onResult(text.trim())
    }
    val options = remember(prompt) {
        ScanOptions()
            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            .setPrompt(prompt)
            .setBeepEnabled(false)
            .setOrientationLocked(false)
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) scan.launch(options)
        else Toast.makeText(context, R.string.qr_camera_denied, Toast.LENGTH_LONG).show()
    }
    return remember(scan, permission, options) {
        {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                scan.launch(options)
            } else {
                permission.launch(Manifest.permission.CAMERA)
            }
        }
    }
}

/** Shows [text] as a QR code with copy / share; tells the user when the text is too long for one code. */
@Composable
fun QrCodeDialog(text: String, title: String, onDismiss: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val bmp = remember(text) { QrCodes.encode(text)?.asImageBitmap() }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = c.card,
        title = { Text(title, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        text = {
            Column {
                if (bmp != null) {
                    Image(
                        bmp, contentDescription = title, filterQuality = FilterQuality.None,
                        modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(8.dp))
                            .background(Color.White).padding(6.dp),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(text, fontSize = 11.sp, color = c.secondary, maxLines = 3, overflow = TextOverflow.Ellipsis)
                } else {
                    Text(stringResource(R.string.qr_too_long), fontSize = 13.sp, color = c.bad)
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.qr_close)) } },
        dismissButton = {
            Row {
                TextButton(onClick = { copyText(context, text) }) { Text(stringResource(R.string.qr_copy)) }
                TextButton(onClick = { shareText(context, text, title) }) { Text(stringResource(R.string.qr_share)) }
            }
        },
    )
}

private fun copyText(context: Context, text: String) {
    context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("mihomo", text))
    Toast.makeText(context, R.string.qr_copied, Toast.LENGTH_SHORT).show()
}

private fun shareText(context: Context, text: String, title: String) {
    val i = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    context.startActivity(Intent.createChooser(i, title).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}
