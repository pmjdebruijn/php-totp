<?php

require('totp.php');

function hotp_test ()
{
  $testcases = array(
    // https://www.ietf.org/rfc/rfc4226.txt page 31
    array("result" => "755224", "algo" => "sha1", "key" => "12345678901234567890", "count" => 0, "length" => 6),
    array("result" => "287082", "algo" => "sha1", "key" => "12345678901234567890", "count" => 1, "length" => 6),
    array("result" => "359152", "algo" => "sha1", "key" => "12345678901234567890", "count" => 2, "length" => 6),
    array("result" => "969429", "algo" => "sha1", "key" => "12345678901234567890", "count" => 3, "length" => 6),
    array("result" => "338314", "algo" => "sha1", "key" => "12345678901234567890", "count" => 4, "length" => 6),
    array("result" => "254676", "algo" => "sha1", "key" => "12345678901234567890", "count" => 5, "length" => 6),
    array("result" => "287922", "algo" => "sha1", "key" => "12345678901234567890", "count" => 6, "length" => 6),
    array("result" => "162583", "algo" => "sha1", "key" => "12345678901234567890", "count" => 7, "length" => 6),
    array("result" => "399871", "algo" => "sha1", "key" => "12345678901234567890", "count" => 8, "length" => 6),
    array("result" => "520489", "algo" => "sha1", "key" => "12345678901234567890", "count" => 9, "length" => 6),
  );

  $ok = TRUE;

  foreach ($testcases as $testcase)
  {
    $test = ($testcase["result"] == hotp($testcase["algo"], $testcase["key"], $testcase["count"], $testcase["length"]));

    echo "HOTP TEST" . " " . $testcase["result"] . " " . ($test ? "PASS" : "FAIL ") . PHP_EOL;

    $ok &= $test;
  }

  return $ok;
}


function totp_test ()
{
  $testcases = array(
    // from https://www.ietf.org/rfc/rfc6238.txt page 15
    array("result" => "94287082", "algo" => "sha1", "key" => "12345678901234567890", "unixtime" => 59, "interval" => 30, "length" => 8),
    array("result" => "07081804", "algo" => "sha1", "key" => "12345678901234567890", "unixtime" => 1111111109, "interval" => 30, "length" => 8),
    array("result" => "14050471", "algo" => "sha1", "key" => "12345678901234567890", "unixtime" => 1111111111, "interval" => 30, "length" => 8),
    array("result" => "89005924", "algo" => "sha1", "key" => "12345678901234567890", "unixtime" => 1234567890, "interval" => 30, "length" => 8),
    array("result" => "69279037", "algo" => "sha1", "key" => "12345678901234567890", "unixtime" => 2000000000, "interval" => 30, "length" => 8),
    array("result" => "65353130", "algo" => "sha1", "key" => "12345678901234567890", "unixtime" => 20000000000, "interval" => 30, "length" => 8),
    // from https://www.ietf.org/rfc/rfc6238.txt page 15, with errata'd secret key
    array("result" => "46119246", "algo" => "sha256", "key" => "12345678901234567890123456789012", "unixtime" => 59, "interval" => 30, "length" => 8),
    array("result" => "68084774", "algo" => "sha256", "key" => "12345678901234567890123456789012", "unixtime" => 1111111109, "interval" => 30, "length" => 8),
    array("result" => "67062674", "algo" => "sha256", "key" => "12345678901234567890123456789012", "unixtime" => 1111111111, "interval" => 30, "length" => 8),
    array("result" => "91819424", "algo" => "sha256", "key" => "12345678901234567890123456789012", "unixtime" => 1234567890, "interval" => 30, "length" => 8),
    array("result" => "90698825", "algo" => "sha256", "key" => "12345678901234567890123456789012", "unixtime" => 2000000000, "interval" => 30, "length" => 8),
    array("result" => "77737706", "algo" => "sha256", "key" => "12345678901234567890123456789012", "unixtime" => 20000000000, "interval" => 30, "length" => 8),
    // from https://www.ietf.org/rfc/rfc6238.txt page 15, with errata'd secret key
    array("result" => "90693936", "algo" => "sha512", "key" => "1234567890123456789012345678901234567890123456789012345678901234", "unixtime" => 59, "interval" => 30, "length" => 8),
    array("result" => "25091201", "algo" => "sha512", "key" => "1234567890123456789012345678901234567890123456789012345678901234", "unixtime" => 1111111109, "interval" => 30, "length" => 8),
    array("result" => "99943326", "algo" => "sha512", "key" => "1234567890123456789012345678901234567890123456789012345678901234", "unixtime" => 1111111111, "interval" => 30, "length" => 8),
    array("result" => "93441116", "algo" => "sha512", "key" => "1234567890123456789012345678901234567890123456789012345678901234", "unixtime" => 1234567890, "interval" => 30, "length" => 8),
    array("result" => "38618901", "algo" => "sha512", "key" => "1234567890123456789012345678901234567890123456789012345678901234", "unixtime" => 2000000000, "interval" => 30, "length" => 8),
    array("result" => "47863826", "algo" => "sha512", "key" => "1234567890123456789012345678901234567890123456789012345678901234", "unixtime" => 20000000000, "interval" => 30, "length" => 8),
  );

  $ok = TRUE;

  foreach ($testcases as $testcase)
  {
    $test = ($testcase["result"] == totp($testcase["algo"], $testcase["key"], $testcase["unixtime"], $testcase["interval"], $testcase["length"]));

    echo "TOTP TEST" . " " . $testcase["result"] . " " . ($test ? "PASS" : "FAIL ") . PHP_EOL;

    $ok &= $test;
  }

  return $ok;
}

hotp_test();
totp_test();

?>
