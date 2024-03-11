import mysql.connector
import datetime

HOST = 'sft_db'
PORT = 3306
USERNAME = 'root'
PASSWORD = 'rootpass'
DATABASE = 'sftdb'

class Database:
    def __init__(self):
        connection = None

    def connect(self):
        try:
            self.connection = mysql.connector.connect(
                host = HOST,
                port = PORT,
                user = USERNAME,
                password = PASSWORD,
                database = DATABASE
            )
        except:
            print("Unable to connect to DB!")

    def query(self, query, params=None):
        cursor = self.connection.cursor()
        result = None
        try:
            cursor.execute(query, params)
            result = cursor.fetchall()
            return result
        except:
            print("Unable to query DB!")
    
    def disconnect(self):
        if self.connection:
            self.connection.close()
    