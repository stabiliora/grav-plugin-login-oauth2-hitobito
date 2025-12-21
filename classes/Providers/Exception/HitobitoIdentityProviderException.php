<?php

# namespace Omines\OAuth2\Client\Provider\Exception;
namespace Grav\Plugin\Login\OAuth2\Providers\Exception;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\ResponseInterface;

class HitobitoIdentityProviderException extends IdentityProviderException
{
    /**
     * Creates client exception from response.
     *
     * @param mixed $data Parsed response data
     */
    public static function clientException(ResponseInterface $response, $data): IdentityProviderException
    {
        return static::fromResponse(
            $response,
            #isset($data['message']) ? $data['message'] : $response->getReasonPhrase()
            serialize($data)
        );
    }

    /**
     * Creates oauth exception from response.
     *
     * @param ResponseInterface $response Response received from upstream
     * @param array $data Parsed response data
     */
    public static function oauthException(ResponseInterface $response, $data): IdentityProviderException
    {
        return static::fromResponse(
            $response,
            isset($data['error']) ? $data['error'] : $response->getReasonPhrase()
        );
    }

    /**
     * Creates identity exception from response.
     *
     * @param ResponseInterface $response Response received from upstream
     * @param string|null $message        Parsed message
     */
    protected static function fromResponse(ResponseInterface $response, $message = null): IdentityProviderException
    {
        return new static($message, $response->getStatusCode(), (string) $response->getBody());
    }
}
