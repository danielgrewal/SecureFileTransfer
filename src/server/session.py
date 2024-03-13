from pydantic import BaseModel
from database import Database

class Session(BaseModel):
    session_id: int
    username_initiator: str
    username_responder: str
    role_initiator: str
    address_initiator: str
    port_initiator: int
    aes_key: str
    session_status: str
    created_on: str | None = None
    completed_on: str | None = None


def get_outstanding_sessions(username: str):
    db = Database()
    db.connect()
    params = (username,)
    result = db.callproc('get_outstanding_requests', params)
    db.disconnect()
    return result[0][0]
