<?php

namespace Qxcoin\BIP32;

final class PrivateChildKey
{
    /**
     * @param string $key Private key in binary string
     * @param string $chainCode Chain code in binary string
     */
    public function __construct(
        public readonly string $key,
        public readonly string $chainCode,
        public readonly int $version,
        public readonly int $depth,
        public readonly int $fingerprint,
        public readonly int $childNumber,
    ) {
        // pass
    }
}
