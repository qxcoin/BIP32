<?php

use QXCoin\BIP32\BIP32;
use QXCoin\BIP32\BitcoinVersionResolver;

require('../vendor/autoload.php');

$seed = '3635ace556665090d13a8010b038cfa4697d917902f70bfa336b14af008cefc9677da51a2822542595e649ca85ddd076f2c4027bbb70775eefc3f63a8841288c';
$versionResolver = new BitcoinVersionResolver();
$bip32 = new BIP32($versionResolver);

$master = $bip32->generateMasterKey($seed);

$account0 = $bip32->derive($master, "m/44'/0'/0'");

var_dump($bip32->serialize($account0));

$address0 = $bip32->derive($account0, "M/0/0");
$address1 = $bip32->derive($account0, "M/0/1");

var_dump(gmp_strval($address0->x, 16), gmp_strval($address0->y, 16));
var_dump(gmp_strval($address1->x, 16), gmp_strval($address1->y, 16));
