package burp;

import java.util.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.Toolkit;
import java.io.UnsupportedEncodingException;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
    private IExtensionHelpers helpers;

    private final static String NAME = "Copy as Go HTTP";
    private final static String[] GO_ESCAPE = new String[256];
    private int currentID = 0;
    private int currentTotal = 0;

    static {
        for (int i = 0x00; i <= 0xFF; i++) GO_ESCAPE[i] = String.format("\\x%02x", i);
        for (int i = 0x20; i < 0x80; i++) GO_ESCAPE[i] = String.valueOf((char)i);
        GO_ESCAPE['\n'] = "\\n";
        GO_ESCAPE['\r'] = "\\r";
        GO_ESCAPE['\t'] = "\\t";
        GO_ESCAPE['"'] = "\\\"";
        GO_ESCAPE['\\'] = "\\\\";
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(NAME);
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) return null;
        JMenuItem i = new JMenuItem(NAME);
        i.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyMessages(messages);
            }
        });
        return Collections.singletonList(i);
    }

    private void copyMessages(IHttpRequestResponse[] messages) {
        StringBuilder goSrc = new StringBuilder("");
        buildBoilerCodeStart(goSrc);

        this.currentID = 0;
        this.currentTotal = messages.length;

        for (IHttpRequestResponse message : messages) {
            this.currentID += 1;
            IRequestInfo ri = helpers.analyzeRequest(message);
            byte[] req = message.getRequest();

            goSrc.append(String.format("    method"+ this.currentID +" := \"%s\"\n", escapeGoString(ri.getMethod())));
            goSrc.append(String.format("    url"+ this.currentID +" := \"%s\"\n", escapeGoString(ri.getUrl().toString())));
            goSrc.append("\n");
            goSrc.append("    // making body\n");
            processBody(goSrc, req, ri.getBodyOffset());
            buildBoilerCodeRequest(goSrc);
            processHeaders(goSrc, ri.getHeaders());
            buildBoilerCodeSend(goSrc);
        }
        goSrc.append("    return res\n");
        goSrc.append("}\n");

        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(goSrc.toString()), this);
    }

    public String escapeGoString(String src) {
        StringBuilder buildStr = new StringBuilder("");
        for (int i=0;i<src.length(); i++) {
            buildStr.append(GO_ESCAPE[src.charAt(i)]);
        }
        return buildStr.toString();
    }

    public void buildBoilerCodeStart(StringBuilder goBoiler) {
        goBoiler.append("import (\n");
        goBoiler.append("    \"net/http\"\n");
        goBoiler.append("    \"net/http/cookiejar\"\n");
        goBoiler.append("    \"golang.org/x/net/publicsuffix\"\n");
        goBoiler.append("    \"net/url\"\n");
        goBoiler.append("    \"crypto/tls\"\n");
        goBoiler.append("    \"strings\"\n");
        goBoiler.append("    \"log\"\n");
        goBoiler.append("    \"time\"\n");
        goBoiler.append("    )\n");
        goBoiler.append("\n");
        goBoiler.append("// Generated code: Remember to import net/http net/url crypto/tls strings log\n");
        goBoiler.append("func doRequest01() *http.Response {\n");
        goBoiler.append("    var res *http.Response\n");
        goBoiler.append("    // setup cookie jar\n");
        goBoiler.append("    jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})\n");
        goBoiler.append("    if err != nil {\n");
        goBoiler.append("        log.Fatal(\"Cookiejar error\")\n");
        goBoiler.append("    }\n");
        goBoiler.append("\n");
        goBoiler.append("    // if burp proxy is necessary\n");
        goBoiler.append("    proxyUrl, err := url.Parse(\"http://127.0.0.1:8080\")\n");
        goBoiler.append("    if err != nil {\n");
        goBoiler.append("        log.Fatal(\"Proxy error\")\n");
        goBoiler.append("    }\n");
        goBoiler.append("    client := &http.Client{\n");
        goBoiler.append("        Timeout: time.Second * 5,\n");
        goBoiler.append("        Transport: &http.Transport{\n");
        goBoiler.append("        Proxy: http.ProxyURL(proxyUrl),\n");
        goBoiler.append("        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},\n");
        goBoiler.append("        Jar: jar,\n");
        goBoiler.append("        }\n");
        goBoiler.append("\n");
        goBoiler.append("    // setting method & url\n");
    }

    public void buildBoilerCodeRequest(StringBuilder goSrc) {
        goSrc.append("\n");
        goSrc.append("    // making request\n");
        goSrc.append("    newRequest"+ this.currentID +", err := http.NewRequest(method"+ this.currentID +", url"+ this.currentID +", body"+ this.currentID +")\n");
        goSrc.append("    if err != nil {\n");
        goSrc.append("        log.Fatal(\"Error in creating request\")\n");
        goSrc.append("    }\n");
        goSrc.append("\n");
        goSrc.append("    // adding headers\n");
    }

    public void buildBoilerCodeSend(StringBuilder goSrc) {
        goSrc.append("\n");
        goSrc.append("    // sending request\n");
        goSrc.append("    res, err = client.Do(newRequest"+ this.currentID +")\n");
        goSrc.append("    if err != nil {\n");
        goSrc.append("        log.Fatal(\"Error in sending request\")\n");
        goSrc.append("    }\n");
    }

    private void processHeaders(StringBuilder goSrc, List<String> headers) {
        boolean firstHeader = true;
        for (String header : headers) {
            int colonPos = header.indexOf(':');
            if (colonPos == -1) continue;
            if (header.substring(0,colonPos).toLowerCase().equals("cookie")) {
                goSrc.append("    newRequest"+ this.currentID +".Header.Add(\"");
                goSrc.append(header, 0, colonPos);
                goSrc.append("\",\"");
                goSrc.append(header, colonPos + 2, header.length());
                goSrc.append("\")\n");
                goSrc.append("    urlStruct"+ this.currentID +", _ := url.Parse(url"+ this.currentID +")\n");
                goSrc.append("    urlStruct"+ this.currentID +".Path = \"/\"\n");
                goSrc.append("    client.Jar.SetCookies(urlStruct"+ this.currentID +", newRequest"+ this.currentID +".Cookies())\n");
                goSrc.append("    newRequest"+ this.currentID +".Header.Del(\""+header.substring(0,colonPos)+"\")\n");
            } else {
                goSrc.append("    newRequest"+ this.currentID +".Header.Add(\"");
                goSrc.append(header, 0, colonPos);
                goSrc.append("\",\"");
                goSrc.append(header, colonPos + 2, header.length());
                goSrc.append("\")\n");
            }
        }
    }

    private void processBody(StringBuilder goSrc, byte[] fullRequest, int start) {
        byte[] bodyBytes = Arrays.copyOfRange(fullRequest, start, fullRequest.length);
        String str = new String(bodyBytes);
        String bodyStr = String.format("    body"+ this.currentID +" := strings.NewReader(\"%s\")\n", escapeGoString(str));
        goSrc.append(bodyStr);
    }


    @Override
    public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
