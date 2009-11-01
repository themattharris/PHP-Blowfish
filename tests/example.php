<?php

require_once('../blowfish.php');

$examples = array(
  array(  'd)U>tQwbUWIozi2R"fOvK0Wuxyl79P%Uxr>;7iiy,b0hByATUB',
          'x03nMwK34x&ciSUH0I1got',
          'password'
  ),
  array(  'RiV3wc615X6J2lzK',
          'QndancjtdZ&b_J5aeId62x7Kxu`[dFFt{t7yGcS+O!w7JbAlQe',
          'p'
  ),
  array(  'd)U>tQwbUWIozi2R"fOvK0Wuxyl79P%Uxr>;7iiy,b0hByATUB',
          'x03nMwK34x&ciSUH0I1got',
          'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.'
  ),
  array(  'This is my secret key and it can be plain text',
          'What about this initialisation vector?',
          'I hope you know this invalidates my warranty'
  ),
  array(  'This is my secret key and it can be plain test',
          'What about this initialisation vector?',
          '' # no password
  ),

);

foreach ($examples as $ex) {
  $ciphertext = Blowfish::encrypt(
                  $ex[2],
                  $ex[0], # encryption key
                  Blowfish::BLOWFISH_MODE_CBC, # Encryption Mode
                  Blowfish::BLOWFISH_PADDING_RFC, # Padding Style
                  $ex[1]  # Initialisation Vector - required for CBC
  );

  $deciphered = Blowfish::decrypt(
                  $ciphertext,
                  $ex[0],
                  Blowfish::BLOWFISH_MODE_CBC, # Encryption Mode
                  Blowfish::BLOWFISH_PADDING_RFC, # Padding Style
                  $ex[1]  # Initialisation Vector - required for CBC
  );

  echo '<pre>';
  printf('Plaintext: %s (length %d)%s', $ex[2], strlen($ex[2]), PHP_EOL);
  printf('Ciphertext: %s (length %d)%s', $ciphertext, strlen($ciphertext), PHP_EOL);
  printf('Deciphered text: %s (length %d)%s', $deciphered, strlen($deciphered), PHP_EOL);
}
?>