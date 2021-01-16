
import smartpy as sp

def command(self):
  transfer_operation = sp.transfer_operation(
    sp.nat(2),
    sp.mutez(0), 
    sp.contract(None, sp.address("KT1Hg6cTCKopUMojt899L9mNmXX9xyyJds45")
  ).open_some())
  
  operation_list = [ transfer_operation ]
  
  sp.result(operation_list)
