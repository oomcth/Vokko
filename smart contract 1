import smartpy as sp


whitelist_id_t = sp.TNat

outbound_whitelists_t = sp.TRecord(
  unrestricted = sp.TBool,
  allowed_whitelists = sp.TSet(t = whitelist_id_t)
)

whitelists_t = sp.big_map(tkey = whitelist_id_t, tvalue = outbound_whitelists_t)

users_t = sp.big_map(tkey = sp.TAddress, tvalue = whitelist_id_t)
''' 
    create the whitelist that will be used to register voters and  check if they have the authorization to vote
'''
class WhitelistContract(sp.Contract):
    def __init__(self, admin, issuer):
        self.init(
            count = 0,
            users = users_t, 
            whitelists = whitelists_t,
            admin = admin,
            issuer = issuer)

    def assertAdmin(self):
        sp.verify((sp.sender == self.data.admin), message = "only admin may update")
        
    def assertNotIssuer(self, user):
        sp.verify(~(self.data.issuer == user), message = "issuer is not a user")
        return user    
    
    def assertUserWhitelist(self, user):
        sp.verify(self.data.users.contains(user), message = "user not on a whitelist")
        return self.data.users[user]
        
    def assertUsersWhitelist(self, user_x, user_y):
        return [self.assertUserWhitelist(user_x), self.assertUserWhitelist(user_y)]
    
    def assertOutboundWhitelists(self, whitelist_id):
        sp.verify(self.data.whitelists.contains(whitelist_id), message ="whitelist does not exist") 
        return self.data.whitelists[whitelist_id]
            
    def assertUnrestrictedOutboundWhitelists(self, outbound_whitelists):
        sp.verify(outbound_whitelists.unrestricted, message = "outbound restricted")
        return outbound_whitelists.allowed_whitelists
        
    def assertAllowedWhitelist(self, allowedWhielistsIds, whitelistId):
        sp.verify(allowedWhielistsIds.contains(whitelistId), message = "outbound not whitelisted")
                
    def _assertReceiver(self, user):
        
        sp.if (user == self.data.issuer):
            pass
        
        sp.else:
            user_whitelist_id = self.assertUserWhitelist(user)
                
            user_outbound_whitelists = self.assertOutboundWhitelists(user_whitelist_id)
                
            user_allowed_whitelist_ids = self.assertUnrestrictedOutboundWhitelists(user_outbound_whitelists)
                
    
    def _assertTransfer(self, transfer_params):
        
        sp.if (transfer_params.from_ == self.data.issuer):
            to_whitelist_id = self.assertUserWhitelist(transfer_params.to_)
            
            to_outbound_whitelists = self.assertOutboundWhitelists(to_whitelist_id)
            
            self.assertUnrestrictedOutboundWhitelists(to_outbound_whitelists)
            
            pass
        
        sp.else:
            
            from_to_whitelists = self.assertUsersWhitelist(transfer_params.from_, transfer_params.to_)
            
            from_whitelist_id = from_to_whitelists[0]
            
            to_whitelist_id = from_to_whitelists[1]
            
            from_outbound_whitelists = self.assertOutboundWhitelists(from_whitelist_id)
            
            from_allowed_whitelist_ids = self.assertUnrestrictedOutboundWhitelists(from_outbound_whitelists)

            to_outbound_whitelists = self.assertOutboundWhitelists(to_whitelist_id)
            
            self.assertUnrestrictedOutboundWhitelists(to_outbound_whitelists)
            
            self.assertAllowedWhitelist(from_allowed_whitelist_ids, to_whitelist_id)
            
            pass 

    def addUserWhitelist(self, user, whitelist_id):
        
        sp.if (whitelist_id.is_some()):
            self.data.users[user] = whitelist_id.open_some()
            
        sp.else:
            del self.data.users[user]
                
    def setOutboundWhitelists(self, whitelist_id, outbound_whitelists_option):

        sp.if (outbound_whitelists_option.is_some()):
            self.data.whitelists[whitelist_id] = outbound_whitelists_option.open_some()
        
        sp.else:
            del self.data.whitelists[whitelist_id]
            
    def getUserWhitelist(self, user):
        sp.verify(self.data.users.contains(user), message = "user not found")
        return self.data.users[user]
        
            
    def getOutboundWhitelists(self, whitelistID):
        sp.verify(self.data.whitelists.contains(whitelistID), message = "whitelist not found")
        return self.data.whitelists[whitelistID]          
    
    def _getAdmin(self, contractAddress):

        admin = self.data.admin
        
        EPtype = sp.TAddress

        c = sp.contract(
                        t = EPtype, 
                        address = contractAddress
                        ).open_some()
                        
        sp.transfer(admin, sp.mutez(0), c)
        
    def _getIssuer(self, contractAddress):

        issuer = self.data.issuer
        
        EPtype = sp.TAddress

        c = sp.contract(
                        t = EPtype, 
                        address = contractAddress
                        ).open_some()
                        
        sp.transfer(issuer, sp.mutez(0), c) 
    
    def _getUser(self, contractAddress, user):

        whitelistID = self.getUserWhitelist(user)
        
        EPtype = whitelist_id_t

        c = sp.contract(
                        t = EPtype, 
                        address = contractAddress
                        ).open_some()
                        
        sp.transfer(whitelistID, sp.mutez(0), c)
    
    def _getWhitelist(self, contractAddress, whitelistID):
        
        whitelistDetails = self.getOutboundWhitelists(whitelistID)
        
        EPtype = outbound_whitelists_t

        c = sp.contract(
                        t = EPtype, 
                        address = contractAddress
                        ).open_some()
                        
        sp.transfer(whitelistDetails, sp.mutez(0), c)    
        
    @sp.entry_point
    def setIssuer(self, new_issuer):
        self.assertAdmin()
        self.data.issuer = new_issuer
        
    @sp.entry_point
    def setAdmin(self, new_admin):
        self.assertAdmin()
        self.data.admin = new_admin
    
    @sp.entry_point
    def setWhitelistOutbound(self, whitelist_outbound_params):
        self.assertAdmin()
        self.setOutboundWhitelists(
            whitelist_outbound_params.new_id_whitelist, 
            whitelist_outbound_params.new_outbound_whitelists
            )
    
    @sp.entry_point
    def addUser(self, new_user_params):
        self.assertAdmin()
        new_user = self.assertNotIssuer(new_user_params.new_user)
        self.addUserWhitelist(new_user, new_user_params.new_user_whitelist)

    @sp.entry_point
    def assertTransfer(self, transfer_params):
        
        self._assertTransfer(transfer_params)
        
    @sp.entry_point
    def assertTransfers(self, transfers_params):
        
        sp.for transfer_params in transfers_params:
            self._assertTransfer(transfer_params)

    @sp.entry_point
    def assertReceiver(self, user):
        
        self._assertReceiver(user)
        
    @sp.entry_point
    def assertReceivers(self, users):
        
        sp.for user in users:
            self._assertReceiver(user)
    
    
    @sp.entry_point
    def getAdmin(self, contractAddress):
        self._getAdmin(contractAddress)
    
    @sp.entry_point
    def getIssuer(self, contractAddress):
        self._getIssuer(contractAddress)
        
    @sp.entry_point
    def getUser(self, contractAddress, user):
        self._getUser(contractAddress, user)
    
    @sp.entry_point
    def getWhitelist(self, contractAddress, whitelistID):
        self._getWhitelist(contractAddress, whitelistID)
    """
    @sp.entry_point
    def vote(Voter_id, id_vote):
        for id in whitelist_id_t:
            if Voter_id == id:
                count = count + 1
                # send token
                break
   
        scenario += whitelistContract.setWhitelistOutbound(
            new_id_whitelist = 6, 
            new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(True), allowed_whitelists = sp.set([7])))
            ).run(sender = admin)
            """
if "templates" not in __name__:
    @sp.add_test(name = "WhitelistContract")
    def test():
        
        admin = sp.address("tz1djN1zPWUYpanMS1YhKJ2EmFSYs6qjf4bW")
        issuer = sp.address("tz1djN1zPWUYpanMS1YhKJ2EmFSYs6qjf4bW")
        
        fakeAdmin = sp.test_account("fakeAdmin")
        fakeIssuer = sp.test_account("fakeIssuer")
        
        hacker = sp.test_account("hacker")
        
        testUser_1 = sp.test_account("testUser_1")
        testUser_2 = sp.test_account("testUser_2")
        testUser_3 = sp.test_account("testUser_3")
        testUser_4 = sp.test_account("testUser_4")
        testUser_5 = sp.test_account("testUser_5")
        testUser_6 = sp.test_account("testUser_6")
        testUser_7 = sp.test_account("testUser_7")

            
        whitelistContract = WhitelistContract(admin, issuer)
            
        scenario = sp.test_scenario()
        scenario.h2("Prod Accounts")
        scenario.show([admin, issuer])
        scenario.h2("Test Accounts")
        scenario.show([fakeAdmin, fakeIssuer, hacker, testUser_1, testUser_2, testUser_3, testUser_4, testUser_5])
            
        scenario.h1("WhitelistContract tests")
            
        scenario += whitelistContract
            
        scenario.h3("Whitelist Contract Issuer")
            
        scenario.show(whitelistContract.data.issuer)
            
        scenario.h3("Whitelist Contract Admin")
            
        scenario.show(whitelistContract.data.admin)
            
        scenario.h2("Begin tests")
            
        scenario.h2("Management Entrypoints tests")
        '''
        a scenario of how we can set a new admin
        '''
        scenario.h2("SetAdmin test group")
            
        scenario.h3("Update admin as non-admin / Should fail")
        scenario += whitelistContract.setAdmin(fakeAdmin.address).run(sender = hacker, valid = False)
            
        scenario.h3("Update admin as admin / Should succeed")
        scenario += whitelistContract.setAdmin(fakeAdmin.address).run(sender = admin)
            
        scenario.h3("Reset old admin as admin / Should succeed")
        scenario += whitelistContract.setAdmin(admin).run(sender = fakeAdmin)

        ''' 
        set who can send an authorization; only existing admins can do such an operation
        '''
        scenario.h2("SetIssuer test group")
            
        scenario.h3("Update issuer as non-admin / Should fail")
        scenario += whitelistContract.setIssuer(fakeIssuer.address).run(sender = hacker, valid = False)
            
        scenario.h3("Update issuer as admin / Should succeed")
        scenario += whitelistContract.setIssuer(fakeIssuer.address).run(sender = admin)
            
        scenario.h3("Reset old issuer as admin / Should succeed")
        scenario += whitelistContract.setIssuer(issuer).run(sender = admin)
        '''
            adding a new user to the whitelist
        '''
        scenario.h2("AddUser test group")
            
            
        scenario.h3("Add user as non-admin / Should fail")
        scenario += whitelistContract.addUser(
                new_user = testUser_1.address, 
                new_user_whitelist = sp.some(1)
                ).run(sender = hacker, valid = False)
            
        scenario.h3("Add Issuer as standard user as admin / Should fail")
        scenario += whitelistContract.addUser(
                new_user = issuer, 
                new_user_whitelist = sp.some(1)
                ).run(sender = admin, valid = False)
            
        scenario.h3("Add User with None as admin / Should succeed")
        scenario += whitelistContract.addUser(
                new_user = testUser_1.address, 
                new_user_whitelist = sp.none
                ).run(sender = admin)
                
        scenario.h3("Add user with Some as admin / Should succeed")
        scenario += whitelistContract.addUser(
                new_user = testUser_1.address, 
                new_user_whitelist = sp.some(1)
                ).run(sender = admin)    
            
        scenario.h2("Assertion Entrypoints tests")

        scenario.h2("AssertReceivers test group")
                
        scenario.h3("Assert receivers with one unexistant user / Should fail")
        scenario += whitelistContract.assertReceivers([testUser_1.address ,testUser_2.address, testUser_3.address]).run(valid = False)
                
        scenario.h3("Assert receivers with one user's whitelistID don't refer to an existing whitelist / Should fail")
                
        scenario += whitelistContract.addUser(
                    new_user = testUser_3.address, 
                    new_user_whitelist = sp.some(3)
                    ).run(sender = admin)
                    
        scenario += whitelistContract.assertReceivers([testUser_1.address ,testUser_2.address, testUser_3.address]).run(valid = False)    
                
        scenario.h3("Assert receivers with one user's whitelist restricted / Should fail")
                
        scenario += whitelistContract.setWhitelistOutbound(
                    new_id_whitelist = 3, 
                    new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(False), allowed_whitelists = sp.set()))
                    ).run(sender = admin)
                
        scenario += whitelistContract.assertReceivers([testUser_1.address ,testUser_2.address, testUser_3.address]).run(valid = False)     
                
        scenario.h3("Assert receivers: all users are existant and unrestricted")
                
        scenario += whitelistContract.setWhitelistOutbound(
                    new_id_whitelist = 3, 
                    new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(True), allowed_whitelists = sp.set()))
                    ).run(sender = admin)
                
        scenario += whitelistContract.assertReceivers([testUser_1.address ,testUser_2.address, testUser_3.address])
                
        scenario.h3("End - AssertReceiver(s) tests")

        scenario.h4("Transfer between two standard users")
            
        scenario.h3("Assert vote between: existant voter and unexistant candidat / Should fail")
            
        scenario += whitelistContract.addUser(
                new_user = testUser_5.address, 
                new_user_whitelist = sp.some(5)
                ).run(sender = admin)
            
        scenario += whitelistContract.assertTransfer(sp.record(from_ = testUser_5.address, to_ = testUser_6.address)).run(valid = False)    
            
        scenario.h3("Assert Trasnfer between: Two existant users with false candidate  whitelistID  / Should fail")
            
        scenario += whitelistContract.addUser(
                new_user = testUser_6.address, 
                new_user_whitelist = sp.some(6)
                ).run(sender = admin)
            
        scenario += whitelistContract.assertTransfer(sp.record(from_ = testUser_5.address, to_ = testUser_6.address)).run(valid = False) 
            
        scenario.h3("Assert Trasnfer between: Two existant users while the voter has already voted / Should fail")
            
        scenario += whitelistContract.setWhitelistOutbound(
                new_id_whitelist = 5, 
                new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(False), allowed_whitelists = sp.set()))
                ).run(sender = admin)
            
        scenario += whitelistContract.assertTransfer(sp.record(from_ = testUser_5.address, to_ = testUser_6.address)).run(valid = False)   
            
        scenario.h3("Assert Trasnfer between: Two existant users while the candidate has been eliminated / Should fail")
            
        scenario += whitelistContract.setWhitelistOutbound(
                new_id_whitelist = 6, 
                new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(False), allowed_whitelists = sp.set()))
                ).run(sender = admin)
            
        scenario += whitelistContract.assertTransfer(sp.record(from_ = testUser_5.address, to_ = testUser_6.address)).run(valid = False) 
            
        scenario.h3("Assert Trasnfer between: Two existant users, receiver's whitelistID is not in sender's whitelist / Should fail")
            
        scenario += whitelistContract.setWhitelistOutbound(
                new_id_whitelist = 5, 
                new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(True), allowed_whitelists = sp.set()))
                ).run(sender = admin)
            
        scenario += whitelistContract.setWhitelistOutbound(
                new_id_whitelist = 6, 
                new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(True), allowed_whitelists = sp.set()))
                ).run(sender = admin)    
            
        scenario += whitelistContract.assertTransfer(sp.record(from_ = testUser_5.address, to_ = testUser_6.address)).run(valid = False) 
            
        scenario.h3("Assert Trasnfer between: Two existants users, voter and candidate are unrestricted, receiver's whitelistID is in the sender's whitelist / Should succeed")
            
        scenario += whitelistContract.setWhitelistOutbound(
                new_id_whitelist = 5, 
                new_outbound_whitelists = sp.some(sp.record(unrestricted = sp.bool(True), allowed_whitelists = sp.set([6])))
                ).run(sender = admin)
            
        scenario += whitelistContract.assertTransfer(sp.record(from_ = testUser_5.address, to_ = testUser_6.address))
