<?php

# note the CBC test should fail due to the faulty padding bit encoding in the test case. For more info soo
# http://www.di-mgt.com.au/cryptopad.html#examplecbc

require_once('../blowfish.php');
switch (strtolower(@$_GET['m'])) {
  case 'cbc':
    $mode = Blowfish::BLOWFISH_MODE_CBC;
    $vectors = file(dirname(__FILE__) . '/vectors_cbc.txt');
    break;
  case 'key':
    $mode = Blowfish::BLOWFISH_MODE_EBC;
    $vectors = file(dirname(__FILE__) . '/vectors_key.txt');
    break;
  default:
    $mode = Blowfish::BLOWFISH_MODE_EBC;
    $vectors = file(dirname(__FILE__) . '/vectors_ecb.txt');
    break;
}

echo '<pre>';
if ($mode == Blowfish::BLOWFISH_MODE_CBC) {
  echo sprintf('%-20s%-50s%-50s%-10s%s', 'Key/IV', 'Plain/Cipher In', 'Plain/Cipher Out', 'Result', PHP_EOL);
  echo sprintf('%-20s%-50s%-50s%-10s%s', '------', '---------------', '----------------', '------', PHP_EOL);  
} else {
  echo sprintf('%-50s%-20s%-20s%-10s%-20s%-20s%-10s%s', 'Key', 'Plain Text', 'Actual Text', 'Result', 'Cipher Text', 'Actual Cipher', 'Result', PHP_EOL);
  echo sprintf('%-50s%-20s%-20s%-10s%-20s%-20s%-10s%s', '---', '----------', '-----------', '------', '-----------', '-------------', '------', PHP_EOL);
}
foreach ($vectors as $v) {
  $v = trim($v);
  if ($v AND ($v[0] != '#')) {
    if ($mode == Blowfish::BLOWFISH_MODE_CBC) {
      list($key, $plaintext, $expected_ciphertext, $iv) = preg_split('/\s+/', $v);
    } else {
      list($key, $plaintext, $expected_ciphertext) = preg_split('/\s+/', $v);
      $iv = NULL;
    }

    $key = trim($key);
    $key = pack('H' . strlen($key), $key);
    
    if ($mode == Blowfish::BLOWFISH_MODE_CBC) {
      $iv = trim($iv);
      $iv = pack('H' . strlen($iv), $iv);
    }
    
    $plaintext = trim($plaintext);
    $plaintext = pack('H' . strlen($plaintext), $plaintext);

    $expected_ciphertext = trim($expected_ciphertext);
    $expected_ciphertext = pack('H' . strlen($expected_ciphertext), $expected_ciphertext);

    # test vectors were created with different padding types
    if ($mode == Blowfish::BLOWFISH_MODE_CBC) {
      $padding = Blowfish::BLOWFISH_PADDING_ZERO;
    } else {
      $padding = Blowfish::BLOWFISH_PADDING_NONE;
    }
    $actual_ciphertext = Blowfish::encrypt($plaintext, $key, $mode, $padding, $iv);
    $actual_deciphered = Blowfish::decrypt($expected_ciphertext, $key, $mode, $padding, $iv);

    $cipher_result = $actual_ciphertext == $expected_ciphertext ? 'PASS' : 'FAIL';
    $plain_result  = $actual_deciphered == $plaintext ? 'PASS' : 'FAIL';
    
    if ($mode != Blowfish::BLOWFISH_MODE_CBC) {
      echo sprintf('%-50s%-20s%-20s%-10s%-20s%-20s%-10s%s',
        base64_encode($key),
        base64_encode($plaintext),
        base64_encode($actual_deciphered),
        $plain_result,
        base64_encode($expected_ciphertext),
        base64_encode($actual_ciphertext),
        $cipher_result,
        PHP_EOL);
    } else {
      echo sprintf('%-21s%-50s%-50s%-10s%s%-21s%-50s%-50s%-10s%s',
        $key,
        base64_encode($plaintext),
        base64_encode($actual_deciphered),
        $plain_result,
        PHP_EOL,
        $iv,
        base64_encode($expected_ciphertext),
        base64_encode($actual_ciphertext),
        $cipher_result,
        PHP_EOL);      
    }
  }
}
