package com.mywebapp.Springsecuritydemo.controller;

import com.mywebapp.Springsecuritydemo.CustomUserDetailsService;
import com.mywebapp.Springsecuritydemo.User;
import com.mywebapp.Springsecuritydemo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Controller
public class HomeController {


    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private UserRepository userRepository;

    @ModelAttribute
    private void userName(Model model, Principal principal) {
        String name = principal.getName();
        System.out.println(name);
        User user = userRepository.findByUsername(name);
        System.out.println(user);

        model.addAttribute("user",user)
        //System.out.println(model.addAttribute("user",user));;
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }


    @GetMapping("/changepass")
    public String changePasswordSite() {
        return "password";
    }

    @PostMapping("/updatePassword")
    public String changePasswordAction() {
        return "fdf";
    }

}
