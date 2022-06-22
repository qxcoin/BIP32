<?php

namespace QXCoin\BIP32;

use GMP;

final class PrivateChildKey
{
    /**
     * @param string $chainCode Chain code in binary string
     */
    public function __construct(
        public readonly GMP $secret,
        public readonly string $chainCode,
        public readonly int $version,
        public readonly int $depth,
        public readonly int $fingerprint,
        public readonly int $childNumber,
    ) {
        // pass
    }
}
