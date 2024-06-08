<?php
use PHPUnit\Framework\TestCase;
use Phore\JWT2\PhoreJWT;
use Phore\JWT2\jwks\PhoreJwksSecretKey;
use Phore\JWT2\jwt\DecodedJWT;
use Phore\JWT2\Algorithm;
class PhoreJWTTest extends TestCase
{
    public function testDecodeValidToken()
    {
        $jwt = new PhoreJWT();
        $secretKey = \Phore\JWT2\jwks\PhoreJwkFactory::createSymmetricKey('secret');

        $jwt->jwks->addKey($secretKey, "default");
        $token = $jwt->encode(['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022], "default");
        $decoded = $jwt->decode($token);
        $this->assertInstanceOf(DecodedJWT::class, $decoded);
        $this->assertEquals('1234567890', $decoded->getClaim('sub'));
    }
    public function testEncodeAndDecode()
    {
        $jwt = new PhoreJWT();
        $secretKey = new PhoreJwksSecretKey([
            'kty' => 'oct',
            'kid' => 'testkid',
            'use' => 'sig',
            'alg' => 'HS256'
        ], 'secret');
        $jwt->jwks->addKey($secretKey);
        $claims = ['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022];
        $token = $jwt->encode($claims, $secretKey);
        $decoded = $jwt->decode($token);
        $this->assertEquals($claims, $decoded->getAllClaims());
    }
    public function testExpiredToken()
    {
        $this->expectException(\Phore\JWT2\PhoreJwtValidationException::class);
        $jwt = new PhoreJWT();
        $secretKey = new PhoreJwksSecretKey([
            'kty' => 'oct',
            'kid' => 'testkid',
            'use' => 'sig',
            'alg' => 'HS256'
        ], 'secret');
        $jwt->jwks->addKey($secretKey);
        $claims = ['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022, 'exp' => time() - 3600];
        $token = $jwt->encode($claims, $secretKey);
        $jwt->decode($token);
    }
    public function testFutureToken()
    {
        $this->expectException(\Phore\JWT2\PhoreJwtValidationException::class);
        $jwt = new PhoreJWT();
        $secretKey = new PhoreJwksSecretKey([
            'kty' => 'oct',
            'kid' => 'testkid',
            'use' => 'sig',
            'alg' => 'HS256'
        ], 'secret');
        $jwt->jwks->addKey($secretKey);
        $claims = ['sub' => '1234567890', 'name' => 'John Doe', 'iat' => time() + 3600];
        $token = $jwt->encode($claims, $secretKey);
        $jwt->decode($token);
    }

}
