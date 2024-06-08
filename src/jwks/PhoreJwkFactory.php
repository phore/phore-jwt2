<?php
namespace Phore\JWT2\jwks;

use Phore\JWT2\Algorithm;

class PhoreJwkFactory
{
    public static function createSymmetricKey(string $secret): PhoreJwksSecretKey
    {
        $keyData = [
            'kty' => 'oct',
            'kid' => bin2hex(random_bytes(16)),
            'use' => 'sig',
            'alg' => 'HS256'
        ];
        return new PhoreJwksSecretKey($keyData, $secret);
    }

    public static function createAsymmetricKey(Algorithm $alg = Algorithm::ES512): PhoreJwksKey
    {
        $keyData = [
            'kty' => null,
            'kid' => bin2hex(random_bytes(16)),
            'use' => 'sig',
            'alg' => $alg->value
        ];

        switch ($alg) {
            case Algorithm::RS256:
            case Algorithm::RS384:
            case Algorithm::RS512:
                $keyData['kty'] = 'RSA';
                $res = openssl_pkey_new([
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA
                ]);
                openssl_pkey_export($res, $privateKey);
                $keyDetails = openssl_pkey_get_details($res);
                $keyData['n'] = base64_encode($keyDetails['rsa']['n']);
                $keyData['e'] = base64_encode($keyDetails['rsa']['e']);
                break;
            case Algorithm::ES256:
            case Algorithm::ES384:
            case Algorithm::ES512:
                $keyData['kty'] = 'EC';
                $curveName = match ($alg) {
                    Algorithm::ES256 => 'prime256v1',
                    Algorithm::ES384 => 'secp384r1',
                    Algorithm::ES512 => 'secp521r1',
                };
                $res = openssl_pkey_new([
                    'curve_name' => $curveName,
                    'private_key_type' => OPENSSL_KEYTYPE_EC
                ]);
                openssl_pkey_export($res, $privateKey);
                $keyDetails = openssl_pkey_get_details($res);
                $keyData['x'] = base64_encode($keyDetails['ec']['x']);
                $keyData['y'] = base64_encode($keyDetails['ec']['y']);
                break;
            default:
                throw new \InvalidArgumentException("Unsupported algorithm: $alg");
        }

        return new PhoreJwksKey($keyData);
    }
}
