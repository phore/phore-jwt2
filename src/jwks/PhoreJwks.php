<?php

namespace Phore\JWT2\jwks;

class PhoreJwks
{
    private array $keys = [];

    public function __construct()
    {
    }


    private function fetchKeys(string $jwksUri): array
    {
        $response = file_get_contents($jwksUri);
        if ($response === false) {
            throw new \Exception("Unable to fetch JWKS from URI");
        }

        $keysData = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception("Invalid JSON response");
        }

        $keys = [];
        foreach ($keysData['keys'] as $keyData) {
            $keys[] = new PhoreJwksKey($keyData);
        }

        return $keys;
    }

    public function addKey(PhoreJwksKey|PhoreJwksSecretKey $key, string $keyId = null): void
    {
        if ($keyId !== null) {
            $key->setKid($keyId);
        }
        $this->keys[] = $key;
    }

    public function getKey(string $kid): PhoreJwksKey|PhoreJwksSecretKey|null
    {
        foreach ($this->keys as $key) {
            if ($key->getKid() === $kid) {
                return $key;
            }
        }
        return null;
    }

    /**
     * Create a new symmectiric key and add it to the JWKS
     * 
     * @param string $keyId
     * @param string $secret
     * @return PhoreJwksSecretKey
     */
    public function createSymmetricKey(string $secret, string $keyId = null): PhoreJwksSecretKey
    {
        $symmetricKey = PhoreJwkFactory::createSymmetricKey($secret);
        $this->addKey($symmetricKey, $keyId);
        return $symmetricKey;
    }
    
    
    /**
     * @return PhoreJwksKey[]|PhoreJwksSecretKey[]
     */
    public function getKeys(): array
    {
        return $this->keys;
    }
}
