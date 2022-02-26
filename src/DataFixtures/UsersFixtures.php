<?php

namespace App\DataFixtures;

use App\Entity\Users;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\String\Slugger\SluggerInterface;
use Faker;

class UsersFixtures extends Fixture
{
    public function __construct(
        private UserPasswordHasherInterface $passwordEncorde,
        private SluggerInterface $slugger
    ){}

    public function load(ObjectManager $manager): void
    {   
        $admin = new Users();
        $admin->setEmail('admin@demon.fr');
        $admin->setLastname('admin');
        $admin->setFirstname('admin');
        $admin->setAdress('12 rue su port');
        $admin->setZipcode('25522');
        $admin->setCity('Paris');
        $admin->setPassword($this->passwordEncorde->hashPassword($admin, 'admin'));
        $admin->setRoles(['ROLE_ADMIN']);
        $manager->persist($admin);

        $faker = Faker\Factory::create('fr_FR');

        for ($usr=1; $usr <= 6 ; $usr++) { 
            $user = new Users();
            $user->setEmail($faker->email);
            $user->setLastname($faker->lastName);
            $user->setFirstname($faker->firstName);
            $user->setAdress($faker->streetAddress);
            $user->setZipcode(str_replace(' ', '', $faker->postcode));
            $user->setCity($faker->city);
            $user->setPassword($this->passwordEncorde->hashPassword($user, 'secret'));

            $manager->persist($user);
        }

        $manager->flush();
    }
}