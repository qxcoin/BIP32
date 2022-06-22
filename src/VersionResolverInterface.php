<?php

namespace Qxcoin\BIP32;

interface VersionResolverInterface
{
    /**
     * Retrieves public version bytes.
     */
    public function getPublicVersionBytes(): int;

    /**
     * Retrieves private version bytes.
     */
    public function getPrivateVersionBytes(): int;

    /**
     * Converts private version bytes to public version bytes and vise-versa.
     */
    public function convertVersionBytes(int $bytes): int;
}
