<?php

namespace Hslavich\OneloginSamlBundle\Security\User;

use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\ObjectManager;
use Doctrine\Persistence\ObjectRepository;
use Symfony\Bridge\Doctrine\Security\User\UserLoaderInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class SamlUserProvider implements UserProviderInterface
{
    private $registry;
    protected $userClass;
    protected $defaultRoles;

    public function __construct(string $userClass, array $defaultRoles, string $property = null, ManagerRegistry $registry)
    {
        $this->registry = $registry;
        $this->userClass = $userClass;
        $this->property = $property;
        $this->defaultRoles = $defaultRoles;
    }

    public function loadUserByUsername($username)
    {
        $repository = $this->getRepository();
        if (null !== $this->property) {
            $user = $repository->findOneBy([$this->property => $username]);
        } else {
            if (!$repository instanceof UserLoaderInterface) {
                throw new \InvalidArgumentException(sprintf('You must either make the "%s" entity Doctrine Repository ("%s") implement "Symfony\Bridge\Doctrine\Security\User\UserLoaderInterface" or set the "property" option in the corresponding entity provider configuration.', $this->userClass, \get_class($repository)));
            }

            $user = $repository->loadUserByUsername($username);
        }

        if (null === $user) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        return $user;
    }

    public function refreshUser(UserInterface $user)
    {
        return $user;
    }

    public function supportsClass($class)
    {
        return $this->userClass === $class || is_subclass_of($class, $this->userClass);
    }

    private function getRepository(): ObjectRepository
    {
        return $this->registry->getManager()->getRepository($this->userClass);
    }
}

interface_exists(ObjectManager::class);
interface_exists(ObjectRepository::class);
