<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/vendor/autoload.php';

/* ======================
   FUNGSI DECRYPT
====================== */

function stringDecrypt($key, $string)
{
    $encrypt_method = 'AES-256-CBC';

    $key_hash = hex2bin(hash('sha256', $key));
    $iv = substr($key_hash, 0, 16);

    $data = base64_decode($string);

    $output = openssl_decrypt(
        $data,
        $encrypt_method,
        $key_hash,
        OPENSSL_RAW_DATA,
        $iv
    );

    return $output;
}

function decompress($string)
{
    return \LZCompressor\LZString::decompressFromEncodedURIComponent($string);
}

function decodeVclaimResponse($response, $consid, $secret, $timestamp)
{
    $key = $consid . $secret . $timestamp;

    $decrypt = stringDecrypt($key, $response);

    if (!$decrypt) {
        return "Decrypt gagal";
    }

    $decompress = decompress($decrypt);

    if (!$decompress) {
        return "Decompress gagal";
    }

    return json_decode($decompress, true);
}

/* ======================
   GENERATE HEADER
====================== */

$generated = array();

if (isset($_POST['generate'])) {

    $consid = trim($_POST['consid']);
    $secret = trim($_POST['conspwd']);

    date_default_timezone_set('UTC');
    $timestamp = strval(time());

    $signature = base64_encode(
        hash_hmac(
            'sha256',
            $consid . "&" . $timestamp,
            $secret,
            true
        )
    );

    $generated = array(
        'timestamp' => $timestamp,
        'signature' => $signature
    );
}

/* ======================
   PROSES DECRYPT
====================== */

$result = null;

if (isset($_POST['decrypt'])) {

    $consid = $_POST['consid'];
    $secret = $_POST['conspwd'];
    $timestamp = $_POST['timestamp'];
    $response = $_POST['response'];

    $result = decodeVclaimResponse($response, $consid, $secret, $timestamp);
}

?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>BPJS VClaim Decrypt Tool</title>

<style>

body{
font-family:Arial;
background:#f4f6f8;
padding:20px;
}

.container{
background:#fff;
padding:20px;
max-width:900px;
margin:auto;
border-radius:6px;
}

label{
font-weight:bold;
margin-top:15px;
display:block;
}

input,textarea{
width:100%;
padding:8px;
margin-top:5px;
}

textarea{
min-height:150px;
font-family:monospace;
}

button{
padding:10px 15px;
margin-top:15px;
cursor:pointer;
border:0;
}

.gen{
background:#28a745;
color:#fff;
}

.dec{
background:#007bff;
color:#fff;
}

.header-box{
background:#eee;
padding:10px;
margin-top:10px;
}

pre{
background:#111;
color:#0f0;
padding:15px;
overflow:auto;
}

</style>
</head>

<body>

<div class="container">

<h2>🔐 BPJS VClaim Header Generator & Decrypt</h2>

<form method="post">

<label>Cons ID</label>
<input type="text" name="consid"
value="<?php echo isset($_POST['consid']) ? htmlspecialchars($_POST['consid']) : ''; ?>">

<label>Secret Key</label>
<input type="text" name="conspwd"
value="<?php echo isset($_POST['conspwd']) ? htmlspecialchars($_POST['conspwd']) : ''; ?>">

<button class="gen" name="generate">Generate Header</button>

<?php if (!empty($generated)) { ?>

<div class="header-box">

<strong>Header:</strong><br>

X-cons-id :
<?php echo htmlspecialchars($_POST['consid']); ?><br>

X-timestamp :
<?php echo $generated['timestamp']; ?><br>

X-signature :
<?php echo $generated['signature']; ?>

</div>

<?php } ?>

<label>Timestamp (untuk decrypt)</label>
<input type="text" name="timestamp"
value="<?php
if(isset($generated['timestamp'])){
echo $generated['timestamp'];
}else if(isset($_POST['timestamp'])){
echo htmlspecialchars($_POST['timestamp']);
}
?>">

<label>Response Encrypted</label>

<textarea name="response"><?php
if(isset($_POST['response'])){
echo htmlspecialchars($_POST['response']);
}
?></textarea>

<button class="dec" name="decrypt">Decrypt Response</button>

</form>

<?php if ($result != null) { ?>

<h3>Hasil Decrypt</h3>

<pre><?php print_r($result); ?></pre>

<?php } ?>

</div>

</body>
</html>