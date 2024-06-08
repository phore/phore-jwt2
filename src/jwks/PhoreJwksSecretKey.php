<?php
namespace Phore\JWT2\jwks;

class PhoreJwksSecretKey extends PhoreJwksKey
{
    private string $secret;

    public function __construct(array $keyData, string $secret)
    {
        parent::__construct($keyData);
        $this->secret = $secret;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }
}
