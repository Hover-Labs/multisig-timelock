
import smartpy as sp

def operation(self):
  arg = sp.unit

  transfer_operation = sp.transfer_operation(
    arg,
    sp.mutez(0), 
    sp.contract(sp.TUnit, sp.address("KT1PuT2NwwNjnxKy5XZEDZGHQNgdtLgN69i9"), "foo"
  ).open_some())
  
  operation_list = [ transfer_operation ]
  
  sp.result(operation_list)

sp.add_expression_compilation_target("operation", operation)
