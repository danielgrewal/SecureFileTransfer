from pydantic import BaseModel
from database import Database


def get_outstanding_sessions(username: str):
    db = Database()
    db.connect()
    params = (username,)
    result = db.callproc('get_outstanding_requests', params)
    db.disconnect()
    return result[0][0]

def create_session(params):
    db = Database()
    db.connect()
    result = db.callproc('create_session', params)
    db.disconnect()
    return result[0]
