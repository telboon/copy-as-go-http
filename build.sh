#! /bin/bash
javac -target 1.8 -source 1.8 -cp ~/BurpSuitePro/burpsuite_pro.jar BurpExtender.java -d Build
jar -cvf copy-as-go-http.jar -C Build/ .
