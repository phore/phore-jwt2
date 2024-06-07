<?php
namespace Phore\JWT2;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

class JWT2 {
    public function generateToken($key, $payload, $alg = 'HS256') {
        return JWT::encode($payload, $key, $alg);
    }

    public function parseToken($token, $key, $allowed_algs = ['HS256']) {
        return JWT::decode($token, $key, $allowed_algs);
    }

    public function loadJWKsFromUrl($url) {
        $json = file_get_contents($url);
        $jwks = json_decode($json, true);
        return JWK::parseKeySet($jwks);
    }
}
