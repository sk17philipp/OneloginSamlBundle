<?php

namespace Hslavich\OneloginSamlBundle\Security\User;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class SamlUserProvider implements UserProviderInterface
{
    protected $userClass;

    public function __construct($userClass)
    {
        $this->userClass = $userClass;
    }

    public function loadUserByUsername($username)
    {
        return new $this->userClass($username, array('ROLE_USER'));
    }

    public function refreshUser(UserInterface $user)
    {
        return $user;
    }

    public function supportsClass($class)
    {
        return $this->userClass === $class || is_subclass_of($class, $this->userClass);
    }
}