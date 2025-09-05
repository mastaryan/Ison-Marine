<?php
$secret = 'CHANGE_ME_TO_A_LONG_RANDOM_SECRET_STRING'; // must match unsubscribe_collect.php

function b64url_encode($data) { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function sign_payload($payload, $secret) { return hash_hmac('sha256', $payload, $secret, true); }

function make_token($email, $extra = []) {
  global $secret;
  $payload = array_merge(['email' => $email, 'iat' => time()], $extra);
  $json    = json_encode($payload);
  $b64     = b64url_encode($json);
  $sig     = b64url_encode(sign_payload($b64, $secret));
  return $b64 . '.' . $sig;
}

// Example usage:
$emails = [
  'alice@isonmarine.com',
  'bob@isonmarine.com',
  // add more...
];

$campaign = 'q3_training';

foreach ($emails as $e) {
  $t = make_token($e, ['campaign' => $campaign]);
  $url = 'https://www.isonmarine.com/unsubscribe_collect.php?t=' . $t . '&c=' . urlencode($campaign);
  echo $e . " => " . $url . "\n";
}
