package com.mywebapp.Springsecuritydemo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.mywebapp.Springsecuritydemo.entity.Vulnerability;
import com.mywebapp.Springsecuritydemo.repository.VulnerabilityRepository;
import com.mywebapp.Springsecuritydemo.service.VulnerabilityService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;


@Component
public class JsonParser {
    @Autowired
    private VulnerabilityService vulnerabilityService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    public void webCommunication () throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("accept", "application/json")
                .uri(URI.create(generateUrl()))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        String nistJson = response.body();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(nistJson);
        JsonNode vulnerabilityNode = rootNode.path("vulnerabilities");
        String vulnerabilityNodeToString = vulnerabilityNode.toString();
        ArrayNode arrayNode = (ArrayNode) objectMapper.readTree(vulnerabilityNodeToString);
        List<JsonNode> cveNodesList = new ArrayList<>();

        if(arrayNode.isArray()) {
            for(JsonNode jsonNode:arrayNode) {
                cveNodesList.add(jsonNode);
            }
        }

        JsonNode cveNodeTree;
        JsonNode idNode;

        VulnerabilityModel vulnerabilityModel = new VulnerabilityModel();
        List<VulnerabilityModel> listOfFinalCvs= new ArrayList<>();

        List<JsonNode> idNodesList = new ArrayList<>();

        for(JsonNode cveNode:cveNodesList) {
            String cveNodeString = cveNode.toString();
            cveNodeTree = objectMapper.readTree(cveNodeString);
            idNode = cveNodeTree.path("cve");
            idNodesList.add(idNode);
        }

        String cveId;
        String published;
        String lastModified;
        String value;
        String vectorString;
        String baseScore;

        List<JsonNode> descriptionNodesList = new ArrayList<>();
        JsonNode zNode;
        JsonNode cveeDataNode;
        List<JsonNode> nodeNodesList = new ArrayList<>();
        List<JsonNode> cpeMatchList = new ArrayList<>();

        for (JsonNode x:idNodesList) {

            cveId = x.get("id").toString();
            published = x.get("published").toString();
            lastModified = x.get("lastModified").toString();

            String clearString1 = clearQuotes(published);
            String clearString2 = clearQuotes(lastModified);

            vulnerabilityModel.setCveId(cveId);

            String x1 = getProperTimestamp(clearString1);
            String x2 = getProperTimestamp(clearString2);

            Timestamp timestamp1 = Timestamp.valueOf(x1);
            Timestamp timestamp2 = Timestamp.valueOf(x2);

            vulnerabilityModel.setPublishDate(timestamp1);
            vulnerabilityModel.setLastModifiedDate(timestamp2);
            JsonNode xNode = objectMapper.readTree(x.toString());

            JsonNode descriptionNode = xNode.path("descriptions");

            if(descriptionNode.isArray()) {
                for(JsonNode jsonNode:descriptionNode) {
                    descriptionNodesList.add(jsonNode);
                }
            }

            for (JsonNode v:descriptionNodesList){

                value = v.get("value").toString();
                if (v.get("lang").toString().equals("\"en\""))
                {
                    vulnerabilityModel.setDescription(value);
                }
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

                vulnerabilityModel.setVectorString(vectorString);
                vulnerabilityModel.setBaseScore(baseScore);
            }

            JsonNode configurationsNode = xNode.path("configurations");

            JsonNode nodeNode;

            if(configurationsNode.isArray()){
                for(JsonNode jsonNode:configurationsNode){
                    nodeNodesList.add(jsonNode);
                }
            }

            JsonNode cpeMatchNode;

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
                            if(criteriaNode.path("vulnerable").toString().equals("true")){
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
    }

    public Vulnerability sendVulnsToDB(VulnerabilityModel vulnerabilityModel) {
        Vulnerability vulnerability = vulnerabilityService.saveVulnerability(vulnerabilityModel);
        return vulnerability;
    }

    public String generateUrl(){
        String date = Instant.now().toString();
        int length = 23;
        String finishDate = StringUtils.left(date, length);
        String startDate;

        if (getLastModifiedVulnerabilityDate() ==null){
            startDate = "2023-04-20T00:00:00.000";
            System.out.println("baza danych podatnosci byla pusta. Dane zostana pobrane od 2023-04-20T00:00:00.000");
        } else {
            startDate = getLastModifiedVulnerabilityDate();
        }

        String POSTS_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=" + startDate + "&lastModEndDate=" + finishDate;
        return POSTS_API_URL;
    }

    public String getProperTimestamp(String dateToChange){
        int length = 19;
        String string1 = StringUtils.left(dateToChange, length);
        String string2 = string1.replaceFirst("T", " ");
        return string2;
    }

    public String clearQuotes(String string){
        String newString = string.substring(1, string.length()-2);
        return newString;
    }

    public String getLastModifiedVulnerabilityDate() {
        Vulnerability vulnerability = vulnerabilityRepository.findAll(Sort.by(Sort.Direction.DESC, "lastModifiedDate"))
                .stream()
                .findFirst()
                .orElse(null);

        if (vulnerability == null) {
            return null;
        }
        else {
            String lastModifiedDate = vulnerability.getLastModifiedDate().toString();

            int length = 19;
            String string = StringUtils.left(lastModifiedDate, length);
            String string1 = string + ".000";
            String string2 = string1.replaceFirst(" ", "T");
            return string2;
        }
    }
}
