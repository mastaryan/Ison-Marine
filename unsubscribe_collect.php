<?php
// ===== Unsubscribe click collector =====
// 1) Logs metadata + recipient token
// 2) Redirects to /unsubscribe.html

// ---- CONFIG ----
$secret   = 'CHANGE_ME_TO_A_LONG_RANDOM_SECRET_STRING';
$logFile  = __DIR__ . '/logs/unsubscribes.csv';
$redirect = '/unsubscribe.html';   // or full URL, e.g. 'https://www.isonmarine.com/unsubscribe.html'

// ---- HELPERS ----
function getClientIp() {
  $keys = ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'];
  foreach ($keys as $k) {
    if (!empty($_SERVER[$k])) {
      $ips = explode(',', $_SERVER[$k]);
      return trim($ips[0]);
    }
  }
  return '';
}
function b64url_encode($data) { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function b64url_decode($data) { return base64_decode(strtr($data), '+/','-_'); }
function sign_payload($payload, $secret) { return hash_hmac('sha256', $payload, $secret, true); }

// ---- TOKEN DECODING (t=) ----
// Token format: base64url(json) . '.' . base64url(hmac_sha256)
// Example payload: {"email":"alice@isonmarine.com","iat":1725400000,"campaign":"q3_training"}
$email    = null;
$campaign = isset($_GET['c']) ? substr($_GET['c'], 0, 64) : '';
$token    = $_GET['t'] ?? '';

if ($token) {
  $parts = explode('.', $token);
  if (count($parts) === 2) {
    $payload = $parts[0];
    $sig     = $parts[1];
    $expected = b64url_encode(sign_payload($payload, $secret));
    if (hash_equals($expected, $sig)) {
      $data = json_decode(b64url_decode($payload), true);
      if (is_array($data) && isset($data['email'])) {
        $email = $data['email'];
        if (isset($data['campaign']) && !$campaign) $campaign = substr($data['campaign'], 0, 64);
      }
    }
  }
}

// ---- COLLECT METADATA ----
$ip    = getClientIp();
$ua    = $_SERVER['HTTP_USER_AGENT']       ?? '';
$lang  = $_SERVER['HTTP_ACCEPT_LANGUAGE']  ?? '';
$ref   = $_SERVER['HTTP_REFERER']          ?? '';   // often empty from email clients
$ts    = gmdate('Y-m-d\TH:i:s\Z');
$path  = $_SERVER['REQUEST_URI']           ?? '';
$host  = $_SERVER['HTTP_HOST']             ?? '';

$line = [$ts, $email, $campaign, $ip, $ua, $lang, $host . $path, $ref];

// ---- WRITE CSV ----
$dir = dirname($logFile);
if (!is_dir($dir)) { mkdir($dir, 0755, true); }
$exists = file_exists($logFile);
if (($fh = fopen($logFile, 'a')) !== false) {
  if (!$exists) {
    fputcsv($fh, ['timestamp_utc','email','campaign','ip','user_agent','accept_language','request','referer']);
  }
  fputcsv($fh, $line);
  fclose($fh);
}

// ---- REDIRECT ----
header('Cache-Control: no-store');
header('Pragma: no-cache');
header('Location: ' . $redirect, true, 302);
exit;
