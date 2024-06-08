<?php

namespace Phore\JWT2;
enum Algorithm: string {
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';
}
