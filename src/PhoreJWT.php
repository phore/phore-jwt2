<?php
namespace Phore\JWT2;

use Phore\JWT2\jwks\PhoreJwks;
use Phore\JWT2\jwks\PhoreJwksSecretKey;
use Phore\JWT2\jwt\DecodedJWT;
use Phore\JWT2\keys\KeyInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class PhoreJWT
{
    public readonly PhoreJwks $jwks;

    public function __construct()
    {
        $this->jwks = new PhoreJwks();
    }

    public function decode(string $token): DecodedJWT
    {
        $keyArray = $this->jwks->getKeys();
        $keys = [];
        foreach ($keyArray as $key) {
            $keys[$key->getKid()] = $key->__getFirebaseKeyObject();
        }
        try {
            $decoded = JWT::decode($token, $keys);
        } catch (\Exception $e) {
            throw new PhoreJwtValidationException($e->getMessage());
        }
        $claims = (array) $decoded;
        $this->validateClaims($claims);
        return new DecodedJWT($claims);
    }

    /**
     * @param array|DecodedJWT $payload
     * @param PhoreJwksSecretKey|string $key    The keyid or the key itself
     * @return string
     */
    public function encode(array|DecodedJWT $payload, PhoreJwksSecretKey|string $key): string
    {
        if (is_string($key)) {
            $key = $this->jwks->getKey($key);
        }
        if ($payload instanceof DecodedJWT) {
            $payload = $payload->getAllClaims();
        }
        return JWT::encode($payload, $key->__getFirebaseKeyObject()->getKeyMaterial(), $key->getAlg(), $key->getKid());
    }

    private function validateClaims(array $claims): void
    {
        $now = time();
        if (isset($claims['nbf']) && $claims['nbf'] > $now) {
            throw new PhoreJwtValidationException('Token is not yet valid (nbf).');
        }


        $maxExpiration = $now + (60 * 60 * 24 * 7); // 1 week
        if (isset($claims['exp']) && $claims['exp'] > $maxExpiration) {
            throw new PhoreJwtValidationException('Token expiration time is too far in the future (exp).');
        }
    }
}
