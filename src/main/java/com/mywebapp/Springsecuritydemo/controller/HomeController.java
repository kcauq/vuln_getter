package com.mywebapp.Springsecuritydemo.controller;

import com.mywebapp.Springsecuritydemo.CustomUserDetailsService;
import com.mywebapp.Springsecuritydemo.User;
import com.mywebapp.Springsecuritydemo.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Controller
public class HomeController {


    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private UserRepository userRepository;

    @ModelAttribute
    private void userName(Model model, Principal principal) {
        String name = principal.getName();
        System.out.println(name);
        User user = userRepository.findByUsername(name);
        System.out.println(user);

        model.addAttribute("user",user);
        //System.out.println(model.addAttribute("user",user));
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
    public String changePasswordAction(Principal principal, @RequestParam("oldPass") String oldPass, @RequestParam("newPass") String newPass, HttpSession session) {
        String name = principal.getName();
        User user = userRepository.findByUsername(name);

        boolean ifOldPassMatches = passwordEncoder().matches(oldPass, user.getPassword());

        if(ifOldPassMatches){
            user.setPassword(passwordEncoder().encode(newPass));
            User updatePassword = userRepository.save(user);

            if(updatePassword!=null){
                session.setAttribute("msg", "Haslo zmienione");
            }else {
                session.setAttribute("msg", "Cos poszlo nie tak");

            }
//            System.out.println("haslo zmienione");
        }else {
            session.setAttribute("msg", "Stare haslo nieprawidlowe");
        }

        return "redirect:/changepass";
    }

}
