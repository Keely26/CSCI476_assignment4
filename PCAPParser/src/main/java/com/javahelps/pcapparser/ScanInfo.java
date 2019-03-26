package com.javahelps.pcapparser;
import java.util.Map;

public class ScanInfo {
    Map<String, Integer> SYN;
    Map<String, Integer> SYNACK;

    public ScanInfo(Map<String, Integer> SYN, Map<String, Integer> SYNACK){
        this.SYN = SYN;
        this.SYNACK = SYNACK;
    }

}
