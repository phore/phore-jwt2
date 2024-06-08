<?php
use PHPUnit\Framework\TestCase;
use Phore\JWT2\jwks\PhoreJwkFactory;
use Phore\JWT2\jwks\PhoreJwksSecretKey;
use Phore\JWT2\jwks\PhoreJwksKey;
use Phore\JWT2\Algorithm;

class PhoreJwkFactoryTest extends TestCase
{
    public function testCreateSymmetricKey()
    {
        $secret = 'mysecret';
        $key = PhoreJwkFactory::createSymmetricKey($secret);
        $this->assertInstanceOf(PhoreJwksSecretKey::class, $key);
        $this->assertEquals('oct', $key->getKty());
        $this->assertEquals('HS256', $key->getAlg());
        $this->assertEquals($secret, $key->getSecret());
    }

    public function testCreateAsymmetricKeyRSA()
    {
        $key = PhoreJwkFactory::createAsymmetricKey(Algorithm::RS256);
        $this->assertInstanceOf(PhoreJwksKey::class, $key);
        $this->assertEquals('RSA', $key->getKty());
        $this->assertEquals('RS256', $key->getAlg());
        $this->assertNotEmpty($key->getKeyData()['n']);
        $this->assertNotEmpty($key->getKeyData()['e']);
    }

    public function testCreateAsymmetricKeyEC()
    {
        $key = PhoreJwkFactory::createAsymmetricKey(Algorithm::ES256);
        $this->assertInstanceOf(PhoreJwksKey::class, $key);
        $this->assertEquals('EC', $key->getKty());
        $this->assertEquals('ES256', $key->getAlg());
        $this->assertNotEmpty($key->getKeyData()['x']);
        $this->assertNotEmpty($key->getKeyData()['y']);
    }

    public function testCreateAsymmetricKeyUnsupported()
    {
        $this->expectException(\TypeError::class);
        PhoreJwkFactory::createAsymmetricKey('unsupported_alg');
    }
}
