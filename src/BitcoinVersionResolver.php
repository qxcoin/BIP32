<?php

namespace QXCoin\BIP32;

use InvalidArgumentException;

final class BitcoinVersionResolver implements VersionResolverInterface
{
    private readonly bool $testnet;

    public function __construct(bool $testnet = false)
    {
        $this->testnet = $testnet;
    }

    public function getPublicVersionBytes(): int
    {
        return $this->testnet ? 0x43587cf : 0x488b21e;
    }

    public function getPrivateVersionBytes(): int
    {
        return $this->testnet ? 0x4358394 : 0x488ade4;
    }

    public function convertVersionBytes(int $bytes): int
    {
        if ($bytes === $this->getPublicVersionBytes()) {
            return $this->getPrivateVersionBytes();
        } elseif ($bytes === $this->getPrivateVersionBytes()) {
            return $this->getPublicVersionBytes();
        } else {
            throw new InvalidArgumentException('Unsupported bytes provided.');
        }
    }
}
