from pydantic import BaseModel

class Session(BaseModel):
    session_id: int
    username_initiator: str
    username_responder: str
    public_key_initiator: str
    public_key_responder: str | None = None
    role_initiator: str
    address_initiator: str
    port_initiator: int
    aes_key: str
    session_status: str
    created_on: str | None = None
    completed_on: str | None = None

    