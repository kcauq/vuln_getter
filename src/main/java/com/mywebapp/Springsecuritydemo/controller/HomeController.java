package com.mywebapp.Springsecuritydemo.controller;

import com.mywebapp.Springsecuritydemo.CustomUserDetailsService;
import com.mywebapp.Springsecuritydemo.entity.User;
import com.mywebapp.Springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
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
        User user = userRepository.findByUsername(name);
        model.addAttribute("user",user);
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
    public String changePasswordAction(Principal principal, @RequestParam("oldPass") String oldPass, @RequestParam("newPass") String newPass) {

        String name = principal.getName();
        User user = userRepository.findByUsername(name);

        boolean ifOldPassMatches = passwordEncoder().matches(oldPass, user.getPassword());


        if(ifOldPassMatches){
            user.setPassword(passwordEncoder().encode(newPass));
            User updatePassword = userRepository.save(user);

            if(updatePassword!=null){
                return "redirect:/changepass?success";

            }else {
                return "redirect:/changepass?error";

            }
        }else {
            return "redirect:/changepass?error";

        }
    }


}
