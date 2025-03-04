import psycopg2

def get_db_connection():
    connection = psycopg2.connect(
        dbname="database-name",
        user="postgres",
        password="password",
        host="localhost",
        port="5432"
    )
    return connection