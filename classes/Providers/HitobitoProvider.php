<?php

namespace Grav\Plugin\Login\OAuth2\Providers;

use Grav\Common\Data\Data;
use Grav\Common\Grav;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;

class HitobitoProvider extends BaseProvider
{
    
    protected $name = 'Hitobito';
    protected $classname = Hitobito::class;

    public function __construct()
    {
        parent::__construct();
        $admin = Grav::instance()['oauth2']->isAdmin();
        $this->config = new Data(Grav::instance()['config']->get('plugins.login-oauth2-hitobito' . ($admin ? '.admin' : '')));
    }

    public function initProvider(array $options): void
    {
        $domain = $this->config->get('providers.hitobito.domain', false);
        $options += [
            'clientId'      => $this->config->get('providers.hitobito.client_id'),
            'clientSecret'  => $this->config->get('providers.hitobito.client_secret')
        ];

        if ($domain) {
            $options += ['domain' => $domain];
        }

        parent::initProvider($options);
    }

    public function getAuthorizationUrl()
    {
        $options = ['state' => $this->state];
        $options['scope'] = $this->config->get('providers.hitobito.options.scope', false);

        return $this->provider->getAuthorizationUrl($options);
    }

    public function getUserData($user)
    {
        $data_user = [
            'id'         => $user->getId(),
            'login'      => $user->getEmail(),
            'email'      => $user->getEmail(),
            'all_data'   => $user->toArray()
        ];

        return $data_user;
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $token): ResourceOwnerInterface
    {
        
        $options = [
            'headers' => [
                'X-Scope' => $this->config->get('providers.hitobito.options.scope')[0]
            ]
        ];
        
        return $this->provider->getResourceOwner($token, $options);
    }

}