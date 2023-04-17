package com.mywebapp.Springsecuritydemo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.mywebapp.Springsecuritydemo.entity.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.lang.reflect.Array;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@Component
public class JsonParser {

    @Autowired
    private Vulnerability vulnerability;

    private static final String POSTS_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2023-04-15T00:00:00.000%2B01:00&lastModEndDate=2023-04-15T02:30:00.000%2B01:00";


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
        if(arrayNode.isArray()) {
            for(JsonNode jsonNode:arrayNode) {
                System.out.println(jsonNode);
            }
        }

//        List<Vulnerability> v = new ArrayList<>(Vulnerability);

//        System.out.println(vulnerabilityNode);
//
//        JsonNode[] cveNode = new JsonNode[]{objectMapper.readTree(String.valueOf(vulnerabilityNode))};
//
//        cveNode[0].fieldNames();

//
//        System.out.println(cveNode[0].fieldNames());
//        System.out.println("###############################");
//        System.out.println(cveNode[0].toPrettyString());


//        System.out.println(cveNode);

        // Przydatne printowanie listy
//        System.out.println(Arrays.toString(cveNode.toArray()));


    }
    
    public void parseJson(){

    }

}
