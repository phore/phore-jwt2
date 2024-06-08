<?php

namespace Phore\JWT2\driver;

use Firebase\JWT\JWT;

class FirebaseDriver
{

    public function encode(array $payload)
    {
        return JWT::decode($payload);
    }

    public function decode($jwt)
    {
        return "decoded";
    }

}
