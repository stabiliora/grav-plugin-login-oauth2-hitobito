<?php

namespace Grav\Plugin\Login\OAuth2\Providers;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;


class HitobitoResourceOwner implements ResourceOwnerInterface
{
    const PATH_API = '/de/oauth/profile';

    /** @var array */
    private $data;

    /** @var string */
    private $domain;

    /** @var AccessToken */
    private $token;

    /**
     * Creates new resource owner.
     */
    public function __construct(array $response, AccessToken $token)
    {
        $this->data = $response;
        $this->token = $token;
    }

    /**
     * Returns the identifier of the authorized resource owner.
     */
    public function getId(): int
    {
        return (int) $this->get('id');
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    /**
     * @return $this
     */
    public function setDomain(string $domain): self
    {
        $this->domain = $domain;

        return $this;
    }

    /**
     * The full name of the owner.
     */
    public function getName(): string
    {
        return $this->get('name');
    }

    /**
     * Username of the owner.
     */
    public function getUsername(): string
    {
        return $this->get('username');
    }

    /**
     * Email address of the owner.
     */
    public function getEmail(): string
    {
        return $this->get('email');
    }

    public function getToken(): AccessToken
    {
        return $this->token;
    }

    /**
     * Whether the user is active.
     */
    public function isActive(): bool
    {
        return 'active' === $this->get('state');
    }

    /**
     * Roles of the user.
     */
    public function getRoles(): array
    {
        return $this->get('roles');
    }

    /**
     * Group IDs of the user's roles.
     */
    public function getGroupIDs(): array
    {
        $roles = $this->get('roles');
        $map = array_map( function($var){return $var["group_id"]; }, $roles);
        return array_unique( array_values($map) );
    }

    /**
     * Return all of the owner details available as an array.
     */
    public function toArray(): array
    {
        return $this->data;
    }

    /**
     * @param  mixed|null $default
     * @return mixed|null
     */
    protected function get(string $key, $default = null)
    {
        return isset($this->data[$key]) ? $this->data[$key] : $default;
    }
}
