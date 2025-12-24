<?php

require_once __DIR__ . '/vendor/autoload.php';

/**
 * Decrypt AES-256-CBC
 */
function stringDecrypt($key, $string)
{
    $encrypt_method = 'AES-256-CBC';

    // Hash key (SHA256 → binary)
    $key_hash = hex2bin(hash('sha256', $key));

    // IV 16 bytes
    $iv = substr(hex2bin(hash('sha256', $key)), 0, 16);

    $output = openssl_decrypt(
        base64_decode($string),
        $encrypt_method,
        $key_hash,
        OPENSSL_RAW_DATA,
        $iv
    );

    return $output;
}

/**
 * Decompress LZ-String
 */
function decompress($string)
{
    return \LZCompressor\LZString::decompressFromEncodedURIComponent($string);
}

/**
 * Proses lengkap decrypt + decompress
 */
function decodeVclaimResponse($response, $consid, $secret, $timestamp)
{
    $key = $consid . $secret . $timestamp;

    // 1. Decrypt
    $decrypted = stringDecrypt($key, $response);

    if ($decrypted === false) {
        return null;
    }

    // 2. Decompress
    $decompressed = decompress($decrypted);

    return json_decode($decompressed, true);
}
