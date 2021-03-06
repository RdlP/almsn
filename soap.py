passport ='''<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/03/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2004/04/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust">
  <Header>
    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="PPAuthInfo">
           <ps:HostingApp>{7108E71A-9926-4FCB-BCC9-9A9D3F32E423}</ps:HostingApp>
           <ps:BinaryVersion>4</ps:BinaryVersion>
           <ps:UIVersion>1</ps:UIVersion>
           <ps:Cookies></ps:Cookies>
           <ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDMz</ps:RequestParams>
       </ps:AuthInfo>
    <wsse:Security>
       <wsse:UsernameToken Id="user">
         <wsse:Username>%s</wsse:Username> 
         <wsse:Password>%s</wsse:Password>
       </wsse:UsernameToken>
    </wsse:Security>
  </Header>
  <Body>

    <ps:RequestMultipleSecurityTokens xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="RSTS">
      <wst:RequestSecurityToken Id="RST0">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
          <wsa:EndpointReference>				
            <wsa:Address>http://Passport.NET/tb</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
      </wst:RequestSecurityToken>
      <wst:RequestSecurityToken Id="RST1">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
          <wsa:EndpointReference>
            <wsa:Address>messengerclear.live.com</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wsse:PolicyReference URI="MBI_KEY_OLD"></wsse:PolicyReference>
      </wst:RequestSecurityToken>
        <wst:RequestSecurityToken Id="RST2">
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                    <wsa:Address>messenger.msn.com</wsa:Address>
                </wsa:EndpointReference>
            </wsp:AppliesTo>
            <wsse:PolicyReference URI="?id=507"></wsse:PolicyReference>
        </wst:RequestSecurityToken>
        <wst:RequestSecurityToken Id="RST3">
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
            <wsp:AppliesTo>
                <wsa:EndpointReference>
                    <wsa:Address>local-bay.contacts.msn.com</wsa:Address>
                </wsa:EndpointReference>
            </wsp:AppliesTo>
            <wsse:PolicyReference URI="MBI"></wsse:PolicyReference>
        </wst:RequestSecurityToken>
        <wst:RequestSecurityToken Id="RST4">
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
            <wsp:AppliesTo>
                <wsa:EndpointReference>
                    <wsa:Address>messengersecure.live.com</wsa:Address>
                </wsa:EndpointReference>
            </wsp:AppliesTo>
            <wsse:PolicyReference URI="MBI_SSL"></wsse:PolicyReference>
        </wst:RequestSecurityToken>
<wst:RequestSecurityToken Id="RST5">
<wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
<wsp:AppliesTo>
<wsa:EndpointReference>
<wsa:Address>storage.msn.com</wsa:Address>
</wsa:EndpointReference>
</wsp:AppliesTo>
<wsse:PolicyReference URI="MBI">
</wsse:PolicyReference>
</wst:RequestSecurityToken>
    </ps:RequestMultipleSecurityTokens>
  </Body>
</Envelope>'''


membershipList = '''<?xml version='1.0' encoding='utf-8'?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
   <soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <ABApplicationHeader xmlns="http://www.msn.com/webservices/AddressBook">
           <ApplicationId xmlns="http://www.msn.com/webservices/AddressBook">CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>
           <IsMigration xmlns="http://www.msn.com/webservices/AddressBook">false</IsMigration>
           <PartnerScenario xmlns="http://www.msn.com/webservices/AddressBook">Initial</PartnerScenario>
       </ABApplicationHeader>
       <ABAuthHeader xmlns="http://www.msn.com/webservices/AddressBook">
           <ManagedGroupRequest xmlns="http://www.msn.com/webservices/AddressBook">false</ManagedGroupRequest>
           <TicketToken>&tickettoken;</TicketToken>
       </ABAuthHeader>
   </soap:Header>
   <soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <FindMembership xmlns="http://www.msn.com/webservices/AddressBook">
           <serviceFilter xmlns="http://www.msn.com/webservices/AddressBook">
               <Types xmlns="http://www.msn.com/webservices/AddressBook">
                   <ServiceType xmlns="http://www.msn.com/webservices/AddressBook">Messenger</ServiceType>
               </Types>
           </serviceFilter>
           <View xmlns="http://www.msn.com/webservices/AddressBook">Full</View>
        </FindMembership>
   </soap:Body>
</soap:Envelope>\r\n'''

addressBook = '''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
    <soap:Header>
        <ABApplicationHeader xmlns="http://www.msn.com/webservices/AddressBook">
            <ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>
            <IsMigration>false</IsMigration>
            <PartnerScenario>Initial</PartnerScenario>
        </ABApplicationHeader>
        <ABAuthHeader xmlns="http://www.msn.com/webservices/AddressBook">
            <ManagedGroupRequest>false</ManagedGroupRequest>
            <TicketToken>&tickettoken;</TicketToken>
        </ABAuthHeader>
    </soap:Header>
    <soap:Body>
        <ABFindAll xmlns="http://www.msn.com/webservices/AddressBook">
            <abId>00000000-0000-0000-0000-000000000000</abId>
            <abView>Full</abView>
            <lastChange>0001-01-01T00:00:00.0000000-08:00</lastChange>
        </ABFindAll>
    </soap:Body>
</soap:Envelope>\r\n'''

getProfile = '''<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"><soap:Header><StorageApplicationHeader xmlns="http://www.msn.com/webservices/storage/w10"><ApplicationID>Messenger Client 8.5</ApplicationID><Scenario>RoamingSeed</Scenario></StorageApplicationHeader><StorageUserHeader xmlns="http://www.msn.com/webservices/storage/w10"><Puid>0</Puid><TicketToken>&tickettoken;</TicketToken></StorageUserHeader></soap:Header><soap:Body><GetProfile xmlns="http://www.msn.com/webservices/storage/w10"><profileHandle><Alias><Name>%s</Name><NameSpace>MyCidStuff</NameSpace></Alias><RelationshipName>MyProfile</RelationshipName></profileHandle><profileAttributes><ResourceID>true</ResourceID><DateModified>true</DateModified><ExpressionProfileAttributes><ResourceID>true</ResourceID><DateModified>true</DateModified><DisplayName>true</DisplayName><DisplayNameLastModified>true</DisplayNameLastModified><PersonalStatus>true</PersonalStatus><PersonalStatusLastModified>true</PersonalStatusLastModified><StaticUserTilePublicURL>true</StaticUserTilePublicURL><Photo>true</Photo><Flags>true</Flags></ExpressionProfileAttributes></profileAttributes></GetProfile></soap:Body></soap:Envelope>'''
