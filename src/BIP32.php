<?php

namespace QXCoin\BIP32;

use GMP;
use InvalidArgumentException;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Primitives\PointInterface;
use Tuupola\Base58;

/**
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
final class BIP32
{
    const HIGHEST_BIT = 0x80000000;

    private VersionResolverInterface $versionResolver;
    private Base58 $base58;
    private GeneratorPoint $ecc;

    public function __construct(VersionResolverInterface $versionResolver)
    {
        $this->versionResolver = $versionResolver;
        $this->base58 = new Base58(['characters' => Base58::BITCOIN]);
        $this->ecc = EccFactory::getSecgCurves()->generator256k1();
    }

    public function generateMasterKey(string $seed): PrivateChildKey
    {
        if (!ctype_xdigit($seed)) {
            throw new InvalidArgumentException('Seed must be a hexadecimal string.');
        }

        $S = pack('H*', $seed);

        $I = hash_hmac('sha512', $S, 'Bitcoin seed', true);

        $I_L = substr($I, 0, 32);
        $I_R = substr($I, 32, 32);

        $privateKey = $this->parse256($I_L);
        $chainCode = $I_R;

        if (!$this->rangeN($privateKey) or gmp_cmp($privateKey, 0) === 0) {
            throw new InvalidArgumentException('Seed results in invalid key.');
        }

        $version = $this->versionResolver->getPrivateVersionBytes();

        return new PrivateChildKey(
            $this->ser256($privateKey), $chainCode, $version, 0, 0x00000000, 0,
        );
    }

    public function CKDpriv(PrivateChildKey $parent, int $i): PrivateChildKey
    {
        $k_par = $this->parse256($parent->key);
        $c_par = $parent->chainCode;

        $key = $c_par;
        if ($i >= self::HIGHEST_BIT) {
            $data = pack('H*', '00') . $this->ser256($k_par) . $this->ser32($i);
        } else {
            $data = $this->serP($this->point($k_par)) . $this->ser32($i);
        }

        $I = hash_hmac('sha512', $data, $key, true);
        $I_L = substr($I, 0, 32);
        $I_R = substr($I, 32, 32);

        $parse_256_I_L = $this->parse256($I_L);
        $k_i = $this->modN(gmp_add($parse_256_I_L, $k_par));

        if (!$this->rangeN($parse_256_I_L) or gmp_cmp($k_i, 0) === 0) {
            return $this->CKDpriv($parent, $i + 1);
        }

        $fingerprint = hexdec(substr($this->hash160($this->serP($this->point($k_par))), 0, 8));

        return new PrivateChildKey(
            $this->ser256($k_i), $I_R, $parent->version, $parent->depth + 1, $fingerprint, $i,
        );
    }

    public function CKDpub(PublicChildKey $parent, int $i): PublicChildKey
    {
        if ($i >= self::HIGHEST_BIT) {
            throw new InvalidArgumentException("CKDpub doesn't support hardened child.");
        }

        $K_par = $this->parseP($parent->key);
        $c_par = $parent->chainCode;

        $key = $c_par;
        $data = $this->serP($K_par) . $this->ser32($i);

        $I = hash_hmac('sha512', $data, $key, true);
        $I_L = substr($I, 0, 32);
        $I_R = substr($I, 32, 32);

        $parse_256_I_L = $this->parse256($I_L);
        $K_i = $this->point($parse_256_I_L)->add($K_par);

        if (!$this->rangeN($parse_256_I_L) or $K_i->isInfinity()) {
            return $this->CKDpub($parent, $i + 1);
        }

        $fingerprint = hexdec(substr($this->hash160($this->serP($K_par)), 0, 8));

        return new PublicChildKey(
            $this->serP($K_i), $I_R, $parent->version, $parent->depth + 1, $fingerprint, $i,
        );
    }

    private function hash160(string $data)
    {
        return hash('ripemd160', hash('sha256', $data, true));
    }

    private function point(GMP $p): PointInterface
    {
        return $this->ecc->mul($p);
    }

    private function serP(PointInterface $P): string
    {
        $prefix = gmp_cmp(gmp_mod($P->getY(), 2), 0) === 0 ? "02" : "03";

        // sometimes X is not 64 bits longs
        // NOTE: converting back from number to hex causes this, because numbers don't have leading zeroes
        $xHex = str_pad(gmp_strval($P->getX(), 16), 64, '0', STR_PAD_LEFT);

        return hex2bin($prefix . $xHex);
    }

    private function parseP(string $P): PointInterface
    {
        $hex = bin2hex($P);

        $prefix = substr($hex, 0, 2);
        $x = gmp_init(substr($hex, 2, 64), 16);

        $y = $this->ecc->getCurve()->recoverYfromX('03' === $prefix, $x);

        return $this->ecc->getCurve()->getPoint($x, $y);
    }

    private function ser32(int $i): string
    {
        return pack('N', $i);
    }

    /**
     * @see https://github.com/btcsuite/btcutil/issues/172
     */
    private function ser256(GMP $p): string
    {
        return pack('H*', str_pad(gmp_strval($p, 16), 64, '0', STR_PAD_LEFT));
    }

    private function parse256(string $p): GMP
    {
        return gmp_init(bin2hex($p), 16);
    }

    private function modN(GMP $number): GMP
    {
        return gmp_mod($number, $this->ecc->getOrder());
    }

    private function rangeN(GMP $number): bool
    {
        return gmp_cmp($number, $this->ecc->getOrder()) < 0;
    }

    public function privateToPublicChildKey(PrivateChildKey $childKey): PublicChildKey
    {
        return new PublicChildKey(
            $this->serP($this->point($this->parse256($childKey->key))),
            $childKey->chainCode,
            $this->versionResolver->convertVersionBytes($childKey->version),
            $childKey->depth,
            $childKey->fingerprint,
            $childKey->childNumber,
        );
    }

    public function deserialize(string $x): PrivateChildKey|PublicChildKey
    {
        $decoded = bin2hex($this->base58->decode($x));

        $handle = fopen('php://memory', 'r+');
        fwrite($handle, $decoded);
        rewind($handle);

        // 4 bytes: version bytes
        $version = hexdec(fread($handle, 4 * 2));
        if ($this->versionResolver->getPublicVersionBytes() === $version) {
            $type = 'public';
        } elseif ($this->versionResolver->getPrivateVersionBytes() === $version) {
            $type = 'private';
        } else {
            throw new InvalidArgumentException('Invalid key version.');
        }

        // 1 byte: depth
        $depth = hexdec(fread($handle, 1 * 2));
        if (!is_int($depth)) {
            throw new InvalidArgumentException('Invalid depth.');
        }

        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        $fingerprint = hexdec(fread($handle, 4 * 2));
        if (0 === $depth and 0x00000000 !== $fingerprint) {
            throw new InvalidArgumentException('Invalid fingerprint.');
        }

        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        $childNumber = hexdec(fread($handle, 4 * 2));
        if (0 === $depth and 0 !== $childNumber) {
            throw new InvalidArgumentException('Invalid child number.');
        }

        // 32 bytes: the chain code
        $chainCode = hex2bin(fread($handle, 32 * 2));

        // 33 bytes: the key
        $key = fread($handle, 33 * 2);
        if ('private' === $type) {
            if ('00' !== substr($key, 0, 1 * 2)) {
                throw new InvalidArgumentException('Invalid private key.');
            } elseif (!$this->rangeN(gmp_init($key = substr($key, 1 * 2), 16))) {
                throw new InvalidArgumentException('Private key not in range [1, n].');
            }
        }
        if ('public' === $type) {
            try {
                $this->parseP(hex2bin($key));
            } catch (\Exception $e) {
                throw new InvalidArgumentException('Invalid public key.', 0, $e);
            }
        }

        // Done!
        fclose($handle);

        $key = hex2bin($key);

        if ('private' === $type) {
            return new PrivateChildKey($key, $chainCode, $version, $depth, $fingerprint, $childNumber);
        } elseif ('public' === $type) {
            return new PublicChildKey($key, $chainCode, $version, $depth, $fingerprint, $childNumber);
        }
    }

    public function serialize(PrivateChildKey|PublicChildKey $childKey): string
    {
        $version = str_pad(dechex($childKey->version), 4 * 2, '0', STR_PAD_LEFT);
        $depth = str_pad(dechex($childKey->depth), 1 * 2, '0', STR_PAD_LEFT);
        $childNumber = str_pad(dechex($childKey->childNumber), 4 * 2, '0', STR_PAD_LEFT);
        $fingerprint = str_pad(dechex($childKey->fingerprint), 4 * 2, '0', STR_PAD_LEFT);

        // see: https://github.com/bitpay/bitcore-lib/issues/47
        // see: https://github.com/iancoleman/bip39/issues/58
        if ($childKey instanceof PrivateChildKey) {
            $key = str_pad(bin2hex($childKey->key), 66, '0', STR_PAD_LEFT);
        } elseif ($childKey instanceof PublicChildKey) {
            $key = bin2hex($childKey->key);
        }
        $chainCode = bin2hex($childKey->chainCode);

        $serialized = $version . $depth . $fingerprint . $childNumber . $chainCode . $key;
        $checksum = substr(hash('sha256', hash('sha256', hex2bin($serialized), true)), 0, 8);

        return $this->base58->encode(hex2bin($serialized . $checksum));
    }

    public function derive(
        PrivateChildKey|PublicChildKey|string $masterKey,
        string $path,
    ): PrivateChildKey|PublicChildKey {
        $masterKey = is_string($masterKey) ? $this->deserialize($masterKey) : $masterKey;

        if (str_starts_with($path, 'm')) {
            return $this->derivePrivate($masterKey, $path);
        } elseif (str_starts_with($path, 'M')) {
            return $this->derivePublic($masterKey, $path);
        } else {
            throw new InvalidArgumentException('Invalid path format.');
        }
    }

    private function derivePrivate(PrivateChildKey $masterKey, string $path): PrivateChildKey
    {
        if (!preg_match("/^m(?:\/\d+'?)*$/", $path)) {
            throw new InvalidArgumentException('Invalid path format.');
        }

        $segments = explode('/', $path);

        /** @var PrivateChildKey $key */
        $key = null;

        foreach ($segments as $i) {
            if ('m' === $i) {
                $key = $masterKey;
            } elseif (str_ends_with($i, "'")) {
                $key = $this->CKDpriv($key, $i = (substr($i, 0, -1) + self::HIGHEST_BIT));
            } else {
                $key = $this->CKDpriv($key, $i);
            }
        }

        return $key;
    }

    private function derivePublic(PrivateChildKey|PublicChildKey $masterKey, string $path): PublicChildKey
    {
        if (!preg_match("/^M(?:\/\d+)*$/", $path)) {
            throw new InvalidArgumentException('Invalid path format.');
        }

        // this allows us to derive public keys from private keys
        if ($masterKey instanceof PrivateChildKey) {
            $masterKey = $this->privateToPublicChildKey($masterKey);
        }

        $segments = explode('/', $path);

        /** @var PublicChildKey $key */
        $key = null;

        foreach ($segments as $i) {
            if ('M' === $i) {
                $key = $masterKey;
            } else {
                $key = $this->CKDpub($key, $i);
            }
        }

        return $key;
    }
}
