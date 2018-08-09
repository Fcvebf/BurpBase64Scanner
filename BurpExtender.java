package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.*;
import java.io.PrintWriter;
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IScannerInsertionPointProvider
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Base64 custom scanner");
        
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        
        // register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(this);
        
        
    }

    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new Base64InputTab(controller, editable);
    }

    //
    // class implementing IMessageEditorTab
    //

    class Base64InputTab implements IMessageEditorTab
    {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public Base64InputTab(IMessageEditorController controller, boolean editable)
        {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override
        public String getTabCaption()
        {
            return "Base64 values";
        }

        @Override
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
            // enable this tab for requests containing a data parameter
            return isRequest && null != helpers.getRequestParameter(content, "data");
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
                // retrieve the data parameter
                IParameter parameter = helpers.getRequestParameter(content, "data");
                
                // deserialize the parameter value
                txtInput.setText(helpers.base64Decode(helpers.urlDecode(parameter.getValue())));
                txtInput.setEditable(editable);
            }
            
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {
            // determine whether the user modified the deserialized data
            if (txtInput.isTextModified())
            {
                // reserialize the data
                byte[] text = txtInput.getText();
                String input = helpers.urlEncode(helpers.base64Encode(text));
                
                // update the request with the new parameter value
                return helpers.updateParameter(currentMessage, helpers.buildParameter("data", input, IParameter.PARAM_BODY));
            }
            else return currentMessage;
        }

        @Override
        public boolean isModified()
        {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
    }


    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
        // retrieve the data parameter
        IParameter dataParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "data");
        if (dataParameter == null)
            return null;
                        
        // if the parameter is present, add a single custom insertion point for it
        List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();
        
        String strData=helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(dataParameter.getValue())));
        String[] strParameters=strData.split("&");
        for(int i=0;i<strParameters.length;i++)
        {
            stdout.println("Creating insertion point:"+i+" from parameter "+strParameters[i].toString());
            insertionPoints.add(new InsertionPoint(baseRequestResponse.getRequest(), strData, strParameters[i]));                
        }       
        
        return insertionPoints;
    }

    //
    // class implementing IScannerInsertionPoint
    //
    private class InsertionPoint implements IScannerInsertionPoint
    {
        private byte[] baseRequest;
        private String insertionPointPrefix;
        private String baseValue;
        private String insertionPointSuffix;
        private String initialMessageParams;
        private String initialParamValue;
        private String name;

        InsertionPoint(byte[] baseRequest, String allparams,String dataParameter)
        {
            this.baseRequest = baseRequest;
            this.initialMessageParams=allparams;
            this.initialParamValue=dataParameter;
            this.name=dataParameter.replace("=", "");
            
            // split the name/value pair
            int start = dataParameter.indexOf("=") + 1;
            insertionPointPrefix = dataParameter.substring(0, start);
            int end =  dataParameter.length();
            baseValue = dataParameter.substring(start, end);
            insertionPointSuffix = dataParameter.substring(end, dataParameter.length());
            
            stdout.println("-----------------------------------");
            stdout.println("Insertion Point created\n");
            stdout.println("insertionPointPrefix="+insertionPointPrefix);
            stdout.println("baseValue="+baseValue);
            stdout.println("insertionPointSuffix="+insertionPointSuffix);
            stdout.println("-----------------------------------");
        }

        // 
        // implement IScannerInsertionPoint
        //
        
        @Override
        public String getInsertionPointName()
        {
            return this.name+"Base64-wrapped input";
        }

        @Override
        public String getBaseValue()
        {
            return baseValue;
        }

        @Override
        public byte[] buildRequest(byte[] payload)
        {
            //SUPPOSE THAT THE BACKEND RECEIVES A DATA PARAM AND ITS MD5DIGEST PARAM
            
            // build the raw data using the provided payload
            String newParamValue = insertionPointPrefix + "#CUSTOM-INJECTION#" + helpers.bytesToString(payload) + insertionPointSuffix;
            String newPayload = this.initialMessageParams.replace(this.initialParamValue, newParamValue);
            stdout.println(newPayload);
            
            // Base64- and URL-encode the data
            String newparam_base64=helpers.base64Encode(newPayload);
            String md5Hash="";
            
            
            //RECOMPUTE THE MD5 DIGEST
            byte[] finalReq=this.baseRequest;
            try{                
            
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(newparam_base64.getBytes());
                byte[] digest = md.digest();
                md5Hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
                                
                finalReq=helpers.addParameter(finalReq, helpers.buildParameter("md5digest", md5Hash, IParameter.PARAM_BODY));                            
                
            }
            catch(Exception e)
            {
                stdout.println(e.toString());        
            }
            
            
            /*RECOMPUTE THE HMAC-SHA512 HASH
            in live cases you may need to retrieve the secret key dynamically from the server with a web call 
            */
            try
            {
                String hmacdigest=this.hmacDigest(newparam_base64, "thesecretkey", "HmacSHA512");
                finalReq=helpers.addParameter(finalReq, helpers.buildParameter("hmac-sha512", hmacdigest, IParameter.PARAM_BODY));                            
                stdout.println("md5:"+md5Hash+" HMAC: "+hmacdigest+" payload: "+newparam_base64);
            }
            catch(Exception e)
            {
                stdout.println(e.toString());           
            }
                    
            newPayload= helpers.urlEncode(newparam_base64);      
            return helpers.updateParameter(finalReq, helpers.buildParameter("data", newPayload, IParameter.PARAM_BODY));
           
        }

        
        public String hmacDigest(String msg, String keyString, String algo) {
            String digest = null;
            try {
                SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo);
                Mac mac = Mac.getInstance(algo);
                mac.init(key);

                byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));

                StringBuffer hash = new StringBuffer();
                for (int i = 0; i < bytes.length; i++) {
                    String hex = Integer.toHexString(0xFF & bytes[i]);
                    if (hex.length() == 1) {
                        hash.append('0');
                    }
                    hash.append(hex);
                }
                digest = hash.toString();
            } catch (UnsupportedEncodingException e) {
            } catch (InvalidKeyException e) {
            } catch (NoSuchAlgorithmException e) {
            }
            return digest;
        }
        
        @Override
        public int[] getPayloadOffsets(byte[] payload)
        {
            // since the payload is being inserted into a serialized data structure, there aren't any offsets 
            // into the request where the payload literally appears
            return null;
        }

        @Override
        public byte getInsertionPointType()
        {
            return INS_EXTENSION_PROVIDED;
        }
    }
    
}
