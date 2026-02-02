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

        $this->validateAccessPermission($user->getGroupIDs());

        return $data_user;
    }

    /**
     * Validate whether user is allowed to access the application.
     * User is allowed when the users groups (where the user has roles in) matches the configured group IDs.
     * If no group IDs are configured, ALL authenticated users will be permitted.
     * 
     * @param array $groupIDs IDs of the groups the authenticated user has roles in.
     * @return void
     */
    function validateAccessPermission(array $groupIDs) {
        
        # Get config
        $allowed = array_unique(
            array_values(
                array_map(
                    function($var){return $var["group_id"]; },
                    $this->config->get('providers.hitobito.allowed', Array())
                )
            )
        );

        # Allow user login if no groups have been configured
        if ( count($allowed) != 0 ) {
            
            # check if user is in allowed group
            $match = count( array_intersect($allowed, $groupIDs) );

            if ($match < 1) {
                throw new \Exception("User not allowed (has no role in any of the allowed groups)");
            }
        }
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
