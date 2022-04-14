<?php

namespace App\Controller\Admin;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;


#[Route('/admin/utilisateurs', name: 'admin_users_')]
class UserController extends AbstractController
{   
    #[Route('/', name: 'index')]
    public function index(): Response
    {
        return $this->render('admin/users/index.html.twig');
    }
}