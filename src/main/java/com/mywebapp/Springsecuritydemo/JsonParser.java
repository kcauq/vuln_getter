package com.mywebapp.Springsecuritydemo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.mywebapp.Springsecuritydemo.entity.Vulnerability;
import com.mywebapp.Springsecuritydemo.service.VulnerabilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;


@Component
public class JsonParser {

//    @Autowired
//    private Vulnerability vulnerability;

    @Autowired
    private VulnerabilityService vulnerabilityService;

//    private static VulnerabilityRepository vulnerabilityRepository;

    private static final String POSTS_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2023-04-15T00:00:00.000%2B01:00&lastModEndDate=2023-04-15T02:30:00.000%2B01:00";

//    public JsonParser(VulnerabilityRepository vulnerabilityRepository) {
//        this.vulnerabilityRepository = vulnerabilityRepository;
//    }


    public static void webCommunication () throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("accept", "application/json")
                .uri(URI.create(POSTS_API_URL))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        //System.out.println((response.body()));
        String nistJson = response.body();

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(nistJson);
        JsonNode vulnerabilityNode = rootNode.path("vulnerabilities");
        String vulnerabilityNodeToString = vulnerabilityNode.toString();


        ArrayNode arrayNode = (ArrayNode) objectMapper.readTree(vulnerabilityNodeToString);

        List<JsonNode> cveNodesList = new ArrayList<>();

        if(arrayNode.isArray()) {
            for(JsonNode jsonNode:arrayNode) {
//
//                System.out.println(jsonNode);
                cveNodesList.add(jsonNode);
            }
        }

//        System.out.println(cveNodesList.get(1));


        JsonNode cveNodeTree;
        JsonNode idNode;

        // "Enhanced for loop"
        for(JsonNode cveNode:cveNodesList) {
//            System.out.println(cveNode);
            String cveNodeString = cveNode.toString();
            cveNodeTree = objectMapper.readTree(cveNodeString);
//            System.out.println(cveNodeTree);
            idNode = cveNodeTree.path("cve");
            System.out.println(idNode.toPrettyString());

        }

        VulnerabilityModel vulnerabilityModel = new VulnerabilityModel();
        vulnerabilityModel.setCveId("qq");
        vulnerabilityModel.setPublishDate("11");
        vulnerabilityModel.setLastModifiedDate("22");
        vulnerabilityModel.setDescription("33");
        vulnerabilityModel.setVectorString("fdfd");
        vulnerabilityModel.setBaseScore("1");
        vulnerabilityModel.setVulnerableTechnology("sdddd");

    }
    
    public void parseJson(VulnerabilityModel vulnerabilityModel){
        Vulnerability vulnerability = vulnerabilityService.saveVulnerability(vulnerabilityModel);

    }

}
