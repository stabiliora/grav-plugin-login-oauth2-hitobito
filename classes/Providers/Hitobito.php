<?php

namespace Grav\Plugin\Login\OAuth2\Providers;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Grav\Plugin\Login\OAuth2\Providers\Exception\HitobitoIdentityProviderException;
use Psr\Http\Message\ResponseInterface;


class Hitobito extends AbstractProvider
{
    use BearerAuthorizationTrait;

    # const PATH_API_USER = '/api/v4/user';
    const PATH_API_USER = '/de/oauth/profile'; 
    const PATH_AUTHORIZE = '/oauth/authorize';
    const PATH_TOKEN = '/oauth/token';
    const DEFAULT_SCOPE = 'email';
    const SCOPE_SEPARATOR = ' ';

    /** @var string */
    public $domain = 'https://puzzle.ch';

    /**
     * Hitobito constructor.
     */
    public function __construct(array $options, array $collaborators = [])
    {
        if (isset($options['domain'])) {
            $this->domain = $options['domain'];
        }
        parent::__construct($options, $collaborators);

    }

    /**
     * Get authorization url to begin OAuth flow.
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->domain . self::PATH_AUTHORIZE;
    } 

    /**
     * Get access token url to retrieve token.
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->domain . self::PATH_TOKEN;
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $token, array $options = [])
    {
        $response = $this->fetchResourceOwnerDetails($token, $options);

        return $this->createResourceOwner($response, $token);
    }

    /**
     * Requests resource owner details.
     *
     * @param  AccessToken $token
     * @return mixed
     */
    protected function fetchResourceOwnerDetails(AccessToken $token, array $options = [])
    {
        $url = $this->getResourceOwnerDetailsUrl($token);

        $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token, $options);

       
        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    /**
     * Get provider url to fetch user details.
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {       
        return $this->domain . self::PATH_API_USER;
    }

    /**
     * Get the default scopes used by Hitobito.
     *
     * This returns an array with 'email' scope as default.
     */
    protected function getDefaultScopes(): array
    {
        return [self::DEFAULT_SCOPE];
    }

    /**
     * Hitobito uses a space to separate scopes.
     */
    protected function getScopeSeparator(): string
    {
        return self::SCOPE_SEPARATOR;
    }

    /**
     * Check a provider response for errors.
     *
     * @param ResponseInterface $response Parsed response data
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw HitobitoIdentityProviderException::clientException($response, $data);
        } elseif (isset($data['error'])) {
            throw HitobitoIdentityProviderException::oauthException($response, $data);
        }
    }

    /**
     * Generate a user object from a successful user details request.
     */
    protected function createResourceOwner(array $response, AccessToken $token): ResourceOwnerInterface
    {
        $user = new HitobitoResourceOwner($response, $token);

        return $user->setDomain($this->domain);
    }
}
