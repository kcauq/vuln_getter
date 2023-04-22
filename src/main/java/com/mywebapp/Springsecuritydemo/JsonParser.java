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

//        System.out.println(vulnerabilityNode.toPrettyString());


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
        List<VulnerabilityModel> listOfFinalCvs= new ArrayList<>();




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

        String cveId;
        String published;
        String lastModified;
        String value;
        String vectorString;
        String baseScore;
//        String criteria;

        int i=0;

        List<JsonNode> descriptionNodesList = new ArrayList<>();
        JsonNode zNode;
        JsonNode cveeDataNode;
        StringBuilder stringBuilder;
        List<JsonNode> nodeNodesList = new ArrayList<>();
        List<JsonNode> cpeMatchList = new ArrayList<>();
        List<JsonNode> CriteriaList = new ArrayList<>();





        for (JsonNode x:idNodesList) {

            System.out.println("\nCVE " + i + "###################\n");
            ++i;

            cveId = x.get("id").toString();
            published = x.get("published").toString();
            lastModified = x.get("lastModified").toString();

            System.out.println("cve" + cveId);
            System.out.println("published" + published);
            System.out.println("lastModified" + lastModified);

            vulnerabilityModel.setCveId(cveId);
            vulnerabilityModel.setPublishDate(published);
            vulnerabilityModel.setLastModifiedDate(lastModified);

            // TODO published Date
            // TODO last Modified
            JsonNode xNode = objectMapper.readTree(x.toString());

            JsonNode descriptionNode = xNode.path("descriptions");

            if(descriptionNode.isArray()) {
                for(JsonNode jsonNode:descriptionNode) {
                    descriptionNodesList.add(jsonNode);
                }
            }

            for (JsonNode v:descriptionNodesList){

                value = v.get("value").toString();
                System.out.println("value" + value);
                vulnerabilityModel.setDescription(value);

                //TODO value

            }

            JsonNode metricsNode = xNode.path("metrics").path("cvssMetricV31");

            List<JsonNode> metricsNodesList = new ArrayList<>();


            if(metricsNode.isArray()) {
                for(JsonNode jsonNode:metricsNode) {
                    metricsNodesList.add(jsonNode);
                }
            }


            for (JsonNode z:metricsNodesList){
                while(metricsNodesList.size()>1){
                    metricsNodesList.remove(metricsNodesList.size()-1);
                }
                zNode = objectMapper.readTree(z.toString());
                cveeDataNode = zNode.path("cvssData");
                vectorString = cveeDataNode.get("vectorString").toString();
                baseScore = cveeDataNode.get("baseScore").toString();

                System.out.println("vectorString" + vectorString);
                System.out.println("baseScore" + baseScore);

                vulnerabilityModel.setVectorString(vectorString);
                vulnerabilityModel.setBaseScore(baseScore);

                //TODO add vectorString
                //TODO add baseScore
            }

            JsonNode configurationsNode = xNode.path("configurations");

            JsonNode nodeNode;

            if(configurationsNode.isArray()){
                for(JsonNode jsonNode:configurationsNode){
                    nodeNodesList.add(jsonNode);
                }
            }

            JsonNode cpeMatchNode;
            JsonNode cpeMatchNodeTree;


            for (JsonNode n:nodeNodesList){
                nodeNode = n.path("nodes");

                if(nodeNode.isArray()){
                    for(JsonNode jsonNode:nodeNode){
                        cpeMatchList.add(jsonNode);
                    }
                }

                for(JsonNode jsonNode:cpeMatchList){
                    cpeMatchNode = jsonNode.path("cpeMatch");
                    if(cpeMatchNode.isArray()){
                        for(JsonNode criteriaNode:cpeMatchNode){
//                            CriteriaList.add(criteriaNode);
                            if(criteriaNode.path("vulnerable").toString().equals("true")){

                                System.out.println(criteriaNode.path("criteria"));
                                vulnerabilityModel.setVulnerableTechnology(criteriaNode.path("criteria").toString());

                                break;
                            }
                        }
                    }
                }
            }

            descriptionNodesList = new ArrayList<>();
            cpeMatchList = new ArrayList<>();
            nodeNodesList = new ArrayList<>();
            listOfFinalCvs.add(vulnerabilityModel);
            sendVulnsToDB(vulnerabilityModel);
        }
//        sendVulnsToDB(listOfFinalCvs);
    }

    public Vulnerability sendVulnsToDB(VulnerabilityModel vulnerabilityModel) {
//        VulnerabilityModel vulnerabilityModel = new VulnerabilityModel();
//        vulnerabilityModel.setCveId("qq");
//        vulnerabilityModel.setPublishDate("11");
//        vulnerabilityModel.setLastModifiedDate("22");
//        vulnerabilityModel.setDescription("33");
//        vulnerabilityModel.setVectorString("fdfd");
//        vulnerabilityModel.setBaseScore("1");
//        vulnerabilityModel.setVulnerableTechnology("sdddd");

        Vulnerability vulnerability = vulnerabilityService.saveVulnerability(vulnerabilityModel);
        return vulnerability;
    }

}
