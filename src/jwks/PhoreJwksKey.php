<?php
namespace Phore\JWT2\jwks;

use Firebase\JWT\Key;

class PhoreJwksKey
{
    private array $keyData = [
        "alg" => null
    ];

    public function __construct(array $keyData)
    {
        if ($keyData !== null) {
            $this->keyData = $keyData;
        }
    }

    public function setKid(string $kid): void
    {
        $this->keyData['kid'] = $kid;
    }

    public function getKid(): string
    {
        return $this->keyData['kid'];
    }

    public function getAlg(): string
    {
        return $this->keyData['alg'];
    }

    public function getKty(): string
    {
        return $this->keyData['kty'];
    }

    public function getKeyData(): array
    {
        return $this->keyData;
    }

    public function getPublicKey(): string
    {
        if ($this->getKty() === 'RSA') {
            return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(base64_decode($this->keyData["n"])), 64, "\n") . "-----END PUBLIC KEY-----";
        }
        if ($this->getKty() === 'EC') {
            return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(base64_decode($this->keyData["x"])), 64, "\n") . "-----END PUBLIC KEY-----";
        }
        throw new \InvalidArgumentException("Unsupported key type: {$this->getKty()}");
    }

    public function __getFirebaseKeyObject(): Key
    {
        if ($this->keyData['kty'] === 'oct') {
            return new Key($this->getSecret(), $this->keyData['alg']);
        }
        if ($this->keyData['kty'] === 'RSA') {
            return new Key(openssl_get_publickey($this->getPublicKey()), $this->keyData['alg']);
        }
        if ($this->keyData['kty'] === 'EC') {
            return new Key(openssl_get_publickey($this->getPublicKey()), $this->keyData['alg']);
        }
        throw new \InvalidArgumentException("Unsupported key type: {$this->keyData['kty']}");
    }
}
