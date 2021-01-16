import smartpy as sp

class Contract(sp.Contract):
  def __init__(self):
    self.init(admin = sp.contract_address(Contract0), storedValue = 0)

  @sp.entry_point
  def default(self, params):
    pass

  @sp.entry_point
  def replace(self, params):
    sp.verify(sp.sender == self.data.admin, message = 'NOT_ADMIN')
    self.data.storedValue = params