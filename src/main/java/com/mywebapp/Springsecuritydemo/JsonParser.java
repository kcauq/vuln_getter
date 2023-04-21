package com.mywebapp.Springsecuritydemo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.mywebapp.Springsecuritydemo.entity.Vulnerability;
import com.mywebapp.Springsecuritydemo.service.VulnerabilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
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


    public void webCommunication () throws IOException, InterruptedException {
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
        VulnerabilityModel vulnerabilityModel = new VulnerabilityModel();
        List<JsonNode> idNodesList = new ArrayList<>();


        // "Enhanced for loop"
        for(JsonNode cveNode:cveNodesList) {
//            System.out.println(cveNode);
            String cveNodeString = cveNode.toString();
            cveNodeTree = objectMapper.readTree(cveNodeString);
//            System.out.println(cveNodeTree);
            idNode = cveNodeTree.path("cve");
            idNodesList.add(idNode);
//            String idNodeToString = idNode.toString();
//            System.out.println(idNode.toPrettyString());

        }

        String cveId = new String();
        String value = new String();
        List<JsonNode> descriptionNodesList = new ArrayList<>();
        JsonNode zNode;
        JsonNode cveeDataNode;
        StringBuilder stringBuilder;
        List<JsonNode> nodeNodesList = new ArrayList<>();
        List<JsonNode> cpeMatchList = new ArrayList<>();
        List<JsonNode> CriteriaList = new ArrayList<>();




        
        for (JsonNode x:idNodesList) {
            cveId = x.get("id").toString();
//            System.out.println(cveId);
            // TODO add published Date
            // TODO add last Modified
            JsonNode xNode = objectMapper.readTree(x.toString());
//            System.out.println(xNode);

            JsonNode descriptionNode = xNode.path("descriptions");
//            System.out.println(descriptionNode);

            if(descriptionNode.isArray()) {
                for(JsonNode jsonNode:descriptionNode) {
                    descriptionNodesList.add(jsonNode);
                }
            }

//            System.out.println(descriptionNodesList);
            for (JsonNode v:descriptionNodesList){
//                JsonNode vNode = objectMapper.readTree(v.toString());

                value = v.get("value").toString();
                //TODO add value
//                System.out.println(value);
            }

            JsonNode metricsNode = xNode.path("metrics").path("cvssMetricV31");
//            System.out.println(metricsNode.toPrettyString());

            List<JsonNode> metricsNodesList = new ArrayList<>();


            if(metricsNode.isArray()) {
                for(JsonNode jsonNode:metricsNode) {
                    metricsNodesList.add(jsonNode);
                }
            }


            for (JsonNode z:metricsNodesList){
                zNode = objectMapper.readTree(z.toString());
                cveeDataNode = zNode.path("cvssData");

//                System.out.println(cveeDataNode.get("vectorString"));
//                System.out.println(cveeDataNode.get("baseScore"));
                //TODO add vectorString
                //TODO add baseScore
            }

            JsonNode configurationsNode = xNode.path("configurations");
//            System.out.println(configurationsNode.toPrettyString());

            JsonNode nodeNode = xNode.path("configurations");

            if(configurationsNode.isArray()){
                for(JsonNode jsonNode:configurationsNode){
                    nodeNodesList.add(jsonNode);
                }
            }

            JsonNode cpeMatchNode;
            JsonNode cpeMatchNodeTree;

//            System.out.println(nodeNodesList);

            for (JsonNode n:nodeNodesList){
                nodeNode = n.path("nodes");
//                System.out.println(nodeNode);
//                cpeMatchNode = nodeNode.path("cpeMatch");
//                System.out.println(cpeMatchNode.toPrettyString());

                // linijke ponizej wcisnac gdzies indziej
//                cpeMatchNodeTree = objectMapper.readTree(nodeNode.toString());


//                System.out.println(cpeMatchNodeTree.toPrettyString());

                if(nodeNode.isArray()){
                    for(JsonNode jsonNode:nodeNode){
                        cpeMatchList.add(jsonNode);
                    }
                }

                for(JsonNode jsonNode:cpeMatchList){
//                    cpeMatchNode = cpeMatchNodeTree.path("cpeMatch");
                    cpeMatchNode = jsonNode.path("cpeMatch");
//                    System.out.println(cpeMatchNode);
                    if(cpeMatchNode.isArray()){
//                        System.out.println(cpeMatchNode);
                        for(JsonNode criteriaNode:cpeMatchNode){
//                            System.out.println(criteriaNode);

                            CriteriaList.add(criteriaNode);
                            if(criteriaNode.path("vulnerable").toString().equals("true")){
                                System.out.println(criteriaNode.path("criteria"));

                            }
                        }
                    }


                }

//                System.out.println(CriteriaList);


//                System.out.println(cpeMatchNode.toPrettyString());
            }





//            ArrayNode descriptionArrayNode = (ArrayNode) objectMapper.readTree(cveId);



        }


    }

    public Vulnerability sendVulnsToDB(){
        VulnerabilityModel vulnerabilityModel = new VulnerabilityModel();
        vulnerabilityModel.setCveId("qq");
        vulnerabilityModel.setPublishDate("11");
        vulnerabilityModel.setLastModifiedDate("22");
        vulnerabilityModel.setDescription("33");
        vulnerabilityModel.setVectorString("fdfd");
        vulnerabilityModel.setBaseScore("1");
        vulnerabilityModel.setVulnerableTechnology("sdddd");

        Vulnerability vulnerability = vulnerabilityService.saveVulnerability(vulnerabilityModel);
        return vulnerability;
    }

}
