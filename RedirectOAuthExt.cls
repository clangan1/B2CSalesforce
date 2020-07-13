public without sharing class RedirectOAuthExt{

    public PageReference redirectMe ()
    {
        //AzureB2CAuthProvider 
        //Valid OAuth Endpoint
        AzureB2CAuthProvider__mdt  authParameters = [SELECT Redirect_Url__c, Forgot_Password_Error_Code__c  FROM AzureB2CAuthProvider__mdt WHERE DeveloperName = 'AzureAD'] ;
        String validOAuth = authParameters.Redirect_Url__c;
        
        //Forgot Password Parameters (fp)
        String FORGOTPASSWORDCODE = authParameters.Forgot_Password_Error_Code__c;
        
        String fpURL =  constructB2CPasswordURL();
        system.debug('fpURL = ' + fpURL);  
    
        String urlvalue = Apexpages.currentPage().getUrl();
        Map<String, String> parameters = ApexPages.currentPage().getParameters();
        Map<String, String> headers = ApexPages.currentPage().getHeaders();

        system.debug('urlvalue = ' + urlvalue );
        system.debug('headers = ' + headers );
        system.debug('parameters = ' + parameters );
                  
        PageReference pRef = new PageReference(validOAuth);

        //If an Error is provided in the parameters - we need to determine if this is the ForgotPassword call.
        if(parameters.containsKey('error_description'))
        {
            if(parameters.get('error_description').contains(FORGOTPASSWORDCODE)) //Confirming ForgotPassword code is received.
            {
                pRef = new PageReference(fpURL);
            } else{
                 pRef = proxyPayload(pRef, parameters,headers);
            }
        }
        else //Handle as a valid OAuth Flow and redirect to the correct endpoint with existing parameters and headers.
        {
             pRef = proxyPayload(pRef, parameters,headers);        
        }
    
        pRef.setRedirect(true);

        system.debug('pRef headers = ' + pRef.getHeaders());        
        system.debug('pRef parameters = ' + pRef.getParameters());

        return pRef;
    }
    
    private static PageReference proxyPayload(PageReference pRef, Map<String, String> parameters, Map<String, String> headers){
    	for(String k : parameters.keySet())
            {
                pRef.getParameters().put(k,parameters.get(k));
            }
            
            for(String k : headers.keySet())
            {
                pRef.getHeaders().put(k,headers.get(k));
            } 
        return pRef;
    }
    
    public static String constructB2CPasswordURL(){
        
        AzureB2CAuthProvider__mdt authParameters = [SELECT Auth_Url__c, Consumer_Key__c , CommunityHome__c, PasswordPolicy__c  FROM AzureB2CAuthProvider__mdt WHERE DeveloperName = 'AzureAD'];
        String Endpoint = authParameters.Auth_Url__c;
        String FixedParameters = '?scope=openid&response_type=code&prompt=login&nonce=defaultNonce';
        String Policy = 'p=' + authParameters.PasswordPolicy__c;
        String ClientId = 'client_id=' + authParameters.Consumer_Key__c;
        String RedirectURL = 'redirect_uri=' + authParameters.CommunityHome__c;
        
        String URL =  Endpoint + FixedParameters + '&' + Policy + '&' + ClientId + '&' + RedirectURL;
        
        return URL;
    }
}
