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
   PROSES FORM
====================== */

$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $consid    = trim($_POST['consid']);
    $conspwd  = trim($_POST['conspwd']);
    $timestamp = trim($_POST['timestamp']);
    $response  = trim($_POST['response']);

    $result = decodeVclaimResponse($response, $consid, $conspwd, $timestamp);
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Decrypt VClaim BPJS</title>
    <style>
        body {
            font-family: Arial;
            background: #f4f6f8;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: auto;
            background: #fff;
            padding: 20px;
            border-radius: 6px;
        }
        label {
            font-weight: bold;
            display: block;
            margin-top: 15px;
        }
        input, textarea {
            width: 100%;
            padding: 8px;
            margin-top: 5px;
        }
        textarea {
            min-height: 150px;
            font-family: monospace;
        }
        button {
            margin-top: 20px;
            padding: 10px 20px;
            background: #007bff;
            color: #fff;
            border: none;
            cursor: pointer;
            border-radius: 4px;
        }
        pre {
            background: #111;
            color: #0f0;
            padding: 15px;
            overflow: auto;
        }
    </style>
</head>

<body>
<div class="container">
    <h2>🔐 Decrypt & Decompress VClaim BPJS</h2>

    <form method="post">
        <label>Cons ID</label>
        <input type="text" name="consid" required value="<?= isset($_POST['consid']) ? htmlspecialchars($_POST['consid']) : '' ?>">

        <label>Cons scretkey</label>
        <input type="text" name="conspwd" required value="<?= isset($_POST['conspwd']) ? htmlspecialchars($_POST['conspwd']) : '' ?>">

        <label>Timestamp</label>
        <input type="text" name="timestamp" required placeholder="contoh: 1703400000"
               value="<?= isset($_POST['timestamp']) ? htmlspecialchars($_POST['timestamp']) : '' ?>">

        <label>Response Terenkripsi (response dari VClaim)</label>
        <textarea name="response" required><?= isset($_POST['response']) ? htmlspecialchars($_POST['response']) : '' ?></textarea>

        <button type="submit">🔓 Proses Decrypt</button>
    </form>

    <?php if ($result): ?>
        <h3>📄 Hasil</h3>
        <pre><?= htmlspecialchars(print_r($result, true)) ?></pre>
    <?php endif; ?>
</div>
</body>
</html>
