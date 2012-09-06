import xml.parsers.expat

class SSoParser:
    def __init__(self, xml_raw):
        self.parser = xml.parsers.expat.ParserCreate()
        self.parser.buffer_text = True
        self.parser.returns_unicode = False
        
        self.tokens = {}
        
        self.in_token_response = False
        self.in_address = False
        self.in_binary_secret = False
        self.in_binary_security = False
        
        self.current_tag = ''
        self.current_token = ''
        
        #connect handlers
        self.parser.StartElementHandler = self.start_element
        self.parser.EndElementHandler = self.end_element
        self.parser.CharacterDataHandler = self.char_data
        self.parser.Parse(xml_raw)
        del(xml_raw)
        
    def start_element(self, name, attrs):
        if name == 'RequestSecurityTokenResponse':
            self.in_token_response = True
        elif name == 'wsa:Address':
            self.in_address = True
        elif name == 'wst:BinarySecret':
            self.in_binary_secret = True
        elif name == 'wsse:BinarySecurityToken':
            self.in_binary_security = True
        self.current_tag = name
        
    def end_element(self, name):
        if name == 'RequestSecurityTokenResponse':
            self.in_token_response = False
        elif name == 'wsa:Address':
            self.in_address = False
        elif name == 'wst:BinarySecret':
            self.in_binary_secret = False
        elif name == 'wsse:BinarySecurityToken':
            self.in_binary_security = False

    def char_data(self, data):
        if self.in_address:
            self.tokens.update({data:{}})
            self.current_token = data
        elif self.in_binary_secret:
            self.tokens[self.current_token].update({'secret':data})
        elif self.in_binary_security:
            self.tokens[self.current_token].update({'security':data})



class MembershipParser:
    '''Parse membership xml'''
    def __init__(self, xml_raw):
        '''init parser and setup handlers'''
        self.parser = xml.parsers.expat.ParserCreate()
        self.parser.buffer_text = True
        self.parser.returns_unicode = False
        
        self.memberships = []
        self.members = []
        
        self.in_membership = False
        self.in_member = False
        
        self.membership_data = {}
        self.member_data = {}
        
        self.current_tag = ''
        
        #connect handlers
        self.parser.StartElementHandler = self.start_element
        self.parser.EndElementHandler = self.end_element
        self.parser.CharacterDataHandler = self.char_data
        self.parser.Parse(xml_raw)
        del(xml_raw)
        
    def start_element(self, name, attrs):
        '''Start xml element handler'''
        if name == 'Membership':
            self.in_membership = True
        elif name == 'Member':
            self.in_member = True
        self.current_tag = name
        
    def end_element(self, name):
        '''End xml element handler'''
        if name == 'Membership':
            self.in_membership = False
            if len(self.membership_data) > 0:
                self.membership_data.update({'Members':self.members})
                self.memberships.append(self.membership_data)
                self.membership_data = {}
                self.members = []
        if name == 'Member':
            self.in_member = False
            if len(self.member_data) > 0:
                self.members.append(self.member_data)
                self.member_data = {}

    def char_data(self, data):
        '''Char xml element handler'''
        if self.in_member:
            self.member_data.update({self.current_tag:data})
        elif self.in_membership:
            self.membership_data.update({self.current_tag:data})
