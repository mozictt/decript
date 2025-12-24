<?php
require_once __DIR__ . '/vendor/autoload.php';

/* ======================
   FUNGSI DECRYPT
====================== */

function stringDecrypt($key, $string)
{
    $encrypt_method = 'AES-256-CBC';
    $key_hash = hex2bin(hash('sha256', $key));
    $iv = substr(hex2bin(hash('sha256', $key)), 0, 16);

    return openssl_decrypt(
        base64_decode($string),
        $encrypt_method,
        $key_hash,
        OPENSSL_RAW_DATA,
        $iv
    );
}

function decompress($string)
{
    return \LZCompressor\LZString::decompressFromEncodedURIComponent($string);
}

function decodeVclaimResponse($response, $consid, $secret, $timestamp)
{
    $key = $consid . $secret . $timestamp;

    $decrypted = stringDecrypt($key, $response);
    if (!$decrypted) {
        return ['error' => 'Gagal decrypt data'];
    }

    $decompressed = decompress($decrypted);
    if (!$decompressed) {
        return ['error' => 'Gagal decompress data'];
    }

    return json_decode($decompressed, true);
}

/* ======================
   GENERATE HEADER
====================== */
$generated = [];

if (isset($_POST['generate'])) {
    $consid   = trim($_POST['consid']);
    $secret  = trim($_POST['conspwd']);

    date_default_timezone_set('UTC');
    $timestamp = strval(time());

    $signature = hash_hmac(
        'sha256',
        $consid . "&" . $timestamp,
        $secret,
        true
    );

    $generated = [
        'timestamp' => $timestamp,
        'signature' => base64_encode($signature)
    ];
}

/* ======================
   PROSES DECRYPT
====================== */
$result = null;

if (isset($_POST['decrypt'])) {
    $result = decodeVclaimResponse(
        $_POST['response'],
        $_POST['consid'],
        $_POST['conspwd'],
        $_POST['timestamp']
    );
}
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VClaim BPJS Decrypt Tool</title>
<style>
body { font-family: Arial; background:#f4f6f8; padding:20px }
.container { background:#fff; padding:20px; max-width:900px; margin:auto; border-radius:6px }
label { font-weight:bold; margin-top:15px; display:block }
input, textarea { width:100%; padding:8px; margin-top:5px }
textarea { min-height:140px; font-family:monospace }
button { padding:10px 15px; margin-top:15px; cursor:pointer }
.gen { background:#28a745; color:#fff; border:none }
.dec { background:#007bff; color:#fff; border:none }
pre { background:#111; color:#0f0; padding:15px }
.header-box { background:#eee; padding:10px; margin-top:10px }
</style>
</head>

<body>
<div class="container">
<h2>🔐 VClaim BPJS – Generate Header & Decrypt</h2>

<form method="post">

    <label>Cons ID</label>
    <input type="text" name="consid" required
        value="<?= htmlspecialchars($_POST['consid'] ?? '') ?>">

    <label>screate key</label>
    <input type="text" name="conspwd" required
        value="<?= htmlspecialchars($_POST['conspwd'] ?? '') ?>">

    <button class="gen" name="generate">⚙️ Generate Header</button>

    <?php if ($generated): ?>
        <div class="header-box">
            <strong>Generated Header:</strong><br>
            X-cons-id: <?= htmlspecialchars($_POST['consid']) ?><br>
            X-timestamp: <?= $generated['timestamp'] ?><br>
            X-signature: <?= $generated['signature'] ?>
        </div>
    <?php endif; ?>

    <label>Timestamp (dipakai untuk decrypt)</label>
    <input type="text" name="timestamp" 
        value="<?= htmlspecialchars($generated['timestamp'] ?? $_POST['timestamp'] ?? '') ?>">

    <label>Response Terenkripsi</label>
    <textarea name="response" ><?= htmlspecialchars($_POST['response'] ?? '') ?></textarea>

    <button class="dec" name="decrypt">🔓 Proses Decrypt</button>

</form>

<?php if ($result): ?>
<h3>📄 Hasil Decrypt</h3>
<pre><?= htmlspecialchars(print_r($result, true)) ?></pre>
<?php endif; ?>

</div>
</body>
</html>
