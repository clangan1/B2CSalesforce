global class AzureB2CAuthProviderPlugin extends Auth.AuthProviderPluginClass {
    
    class AzureB2CAuthProviderPluginException extends Exception {}
    
    public String redirectUrl; // use this URL for the endpoint that the authentication provider calls back to for configuration
    private String key;
    private String secret;
    private String authUrl;    // application redirection to the B2C website for authentication and authorization
    private String accessTokenUrl; // uri to get the new access token from B2C  using the GET verb
    private String customMetadataTypeApiName = 'AzureB2CAuthProvider__mdt'; // api name for the custom metadata type created for this auth provider
    private String userAPIUrl; // api url to access the user in concur
    private String userAPIVersionUrl; // version of the user api url to access data from B2C
    private String policy;
    private String authProvider;
    private String portal;
    
    public class RegPluginException extends Exception {}
    global String getCustomMetadataType() {
        return customMetadataTypeApiName;
    }
    
    global PageReference initiate(Map<string,string> authProviderConfiguration, String stateToPropagate) {
        authUrl = authProviderConfiguration.get('Auth_Url__c');
        key = authProviderConfiguration.get('Consumer_Key__c');
        redirectUrl = authProviderConfiguration.get('Proxy_Redirect_URL__c');
        policy = authProviderConfiguration.get('Policy__c'); 
        String url = authUrl + '?p=' + policy + '&client_id='+ key +'&redirect_uri='+ redirectUrl + '&scope=openid&response_type=code&prompt=login&state=' + stateToPropagate;
        
        return new PageReference(url);
    }
    
    global Auth.AuthProviderTokenResponse handleCallback(Map<string,string> authProviderConfiguration, Auth.AuthProviderCallbackState state ) {
        
        key = authProviderConfiguration.get('Consumer_Key__c');
        secret = authProviderConfiguration.get('Consumer_Secret__c');
        accessTokenUrl = authProviderConfiguration.get('Access_Token_Url__c');
        authProvider = authProviderConfiguration.get('AuthProviderName__c');
		policy = authProviderConfiguration.get('Policy__c'); 
        
        System.debug('handleCallback state:' + state);
        
        
        Map<String,String> queryParams = state.queryParameters;
        String code = queryParams.get('code');
        String sfdcState = queryParams.get('state');
        
        HttpRequest req = new HttpRequest();
        String url = accessTokenUrl+'?p=' + policy;
        req.setEndpoint(url);
        req.setHeader('Content-Type','application/x-www-form-urlencoded');
        req.setMethod('POST');

        String reqbody = 'code=' + code + '&client_id=' + key + '&client_secret=' + secret + '&grant_type=authorization_code';
        req.setBody(reqbody); 
        System.debug('handleCallback req:' + req);
        
        try{
            Http http = new Http();
            HTTPResponse res = http.send(req);
            String responseBody = res.getBody();
            system.debug('RESPONSE_ToString'+res.toString()); 
            system.debug(responseBody);         
            String token = getTokenValueFromResponse(responseBody, 'id_token', false);
            
            System.debug('handleCallback res:' + res);
            System.debug('handleCallback token:' + token);
            
            return new Auth.AuthProviderTokenResponse(authProvider, token, secret, sfdcState);
        } catch(RegPluginException e){
            throw new RegPluginException(e.getMessage());
        }
    }
    
    
    global Auth.UserData  getUserInfo(Map<string,string> authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        String id ;
        String fname;
        String lname;
        String flname;
        String email;
        String locale;
        Map<String,String> provMap = new Map<String,String>();
        
        authProvider = authProviderConfiguration.get('AuthProviderName__c');
        portal = authProviderConfiguration.get('PortalName__c');

        String networkid = [select id, name from network where name =: portal Limit 1].id;
                
        /////This is necessary for the User info method to work as described in a lemma on the documentation for the plugin
        try{
            HttpRequest req = new HttpRequest();
            String url = 'https://login.salesforce.com/';
            req.setEndpoint(url);
            req.setMethod('GET');
            Http http = new Http();
            HTTPResponse res = http.send(req);
        } catch(RegPluginException e){
            throw new RegPluginException('Salesforce mock callout failed. ' + e.getMessage());
        }
        //////
        
        System.Debug('response' +response.OAuthToken);
        
        try{
            List<String> SplitToken =  response.OAuthToken.split('\\.');
            System.debug('SplitToken'+SplitToken);
            
            Blob tokenPayloadBlob = EncodingUtil.base64decode(SplitToken[1]);
            
            String decrypted = tokenPayloadBlob.toString();
            System.debug('decrypted: ' + decrypted);
            
            id = getTokenValueFromResponse(decrypted, 'oid',false);
            fname = getTokenValueFromResponse(decrypted, 'given_name', false);
            lname = getTokenValueFromResponse(decrypted, 'family_name', false);
            flname = fname + ' ' + lname;
            email = getTokenValueFromResponse(decrypted, 'emails', true);
            locale = 'en_AU';
            provMap.put('oid', id);
            provMap.put('sfdc_networkid', networkid);
        } catch(RegPluginException e){
            throw new RegPluginException(key + ' is not available in response.' + e.getMessage());
        }
        return new Auth.UserData(id, fname, lname, flname, email,
                                 null, locale, null, authProvider, null, provMap);
    }
    
    public String getTokenValueFromResponse(String response, String key, Boolean isArray) {
        String ret = null;
        
        try{
            Map<String, Object> jsonResponse =  (Map<String, Object>) json.deserializeUntyped(response);
            System.debug('jsonResponse'+jsonResponse);
            if(!isArray){
                ret=jsonResponse.get(key).toString();
            } else{
                List<Object> emailsArray =  (List<Object>) jsonResponse.get(key);
                ret= emailsArray[0].toString();
            }
            System.debug(key + ': ' +ret);
        } catch(RegPluginException e){
            throw new RegPluginException(key + ' is not available in response.' + e.getMessage());    
        }
        return ret;
        
    }
    
}