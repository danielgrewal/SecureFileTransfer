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

def get_first_invite(username):
    db = Database()
    db.connect()
    params = (username,)
    result = db.callproc('get_open_invite', params)
    db.disconnect()
    return result[0]

def close_session(session_id):
    db = Database()
    db.connect()
    params = (session_id,)
    result = db.callproc('end_session', params)
    
    db.disconnect()
    return result[0]