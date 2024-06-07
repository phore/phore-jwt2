<?php
use Phore\JWT2\JWT2;
use PHPUnit\Framework\TestCase;

class JWT2Test extends TestCase
{
    public function testGenerateToken() {
        $jwt2 = new JWT2();
        $key = 'secret';
        $payload = ['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022];
        $token = $jwt2->generateToken($key, $payload);
        $this->assertNotEmpty($token);
    }

    public function testParseToken() {
        $jwt2 = new JWT2();
        $key = 'secret';
        $payload = ['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022];
        $token = $jwt2->generateToken($key, $payload);
        $decoded = $jwt2->parseToken($token, $key);
        $this->assertEquals($payload['sub'], $decoded->sub);
    }

    public function testLoadJWKsFromUrl() {
        $jwt2 = new JWT2();
        $url = 'https://www.googleapis.com/oauth2/v3/certs';
        $jwks = $jwt2->loadJWKsFromUrl($url);
        $this->assertNotEmpty($jwks);
    }
}
