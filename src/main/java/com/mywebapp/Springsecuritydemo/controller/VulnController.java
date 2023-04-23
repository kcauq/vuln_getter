package com.mywebapp.Springsecuritydemo.controller;

import com.mywebapp.Springsecuritydemo.JsonParser;
import com.mywebapp.Springsecuritydemo.VulnerabilityModel;
import com.mywebapp.Springsecuritydemo.entity.Vulnerability;
import com.mywebapp.Springsecuritydemo.repository.VulnerabilityRepository;
import com.mywebapp.Springsecuritydemo.service.VulnerabilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;


@Controller
public class VulnController {

    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
    private JsonParser jsonParser;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;
    @Autowired
    private Vulnerability vulnerability;

    @GetMapping("/vulnerabilities")
    public String vulnerabilities(Model model)  {
        List<Vulnerability> vulnerabilityList = vulnerabilityRepository.findAll();
        model.addAttribute("vulnerabilitySubList", vulnerabilityList);
        return "vulnerabilities";
    }

    @PostMapping("/updateVulnerabilities")
    public String updateVulnerabilities() throws IOException, InterruptedException {
//        Vulnerability vulnerability = vulnerabilityService.saveVulnerability()
//        Vulnerability vulnerability = jsonParser.sendVulnsToDB();
        jsonParser.webCommunication();
//        return null;
        return "redirect:/vulnerabilities";
    }

    @GetMapping("/twentyVulnerabilities")
    public String twentyVulnerabilities(Model model)  {
        List<Vulnerability> vulnerabilityList = vulnerabilityRepository.findAll(Sort.by(Sort.Direction.DESC, "lastModifiedDate"));
        List<Vulnerability> vulnerabilitySubList = vulnerabilityList.subList(0, Math.min(vulnerabilityList.size(), 20));
        model.addAttribute("twentyVulnerabilitySubList", vulnerabilitySubList);
        return "twentyVulnerabilities";
    }

}
