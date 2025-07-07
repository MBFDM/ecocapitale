import mysql.connector
from mysql.connector import Error 

def create_connection():
    host_name = '127.0.0.1'
    user_name = 'root'
    user_password = ''
    port = '3306'
    db_name = 'ecocapital'

    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            password=user_password,
            database=db_name,
            port=port
        )
        if connection.is_connected():
            print("Connection to MySQL DB successful")
            return connection
    except mysql.connector.Error as err:
        print(f"Error: '{err}'")
        return None
    
create_connection()