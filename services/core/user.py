from solar import Table, ColumnDetails
import uuid

class User(Table):
  __tablename__ = "users"
  id: uuid.UUID = ColumnDetails(primary_key=True)
  email: str
  