<?php

namespace Phore\JWT2\jwt;

class DecodedJWT
{
    private array $claims;

    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    public function getClaim(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    public function getAllClaims(): array
    {
        return $this->claims;
    }

    public function isExpired(): bool
    {
        return isset($this->claims['exp']) && $this->claims['exp'] < time();
    }

    public function getIssuedAt(): ?int
    {
        return $this->claims['iat'] ?? null;
    }
}
