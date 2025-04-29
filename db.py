# db.py
from sqlalchemy import create_engine, text,URL

# Define your database credentials and connection details
DB_SERVER   = "LAPTOP-RES6G37K"           # or your server name/IP
DB_NAME     = "AdventureWorks2019"  # database name
DB_USERNAME = "salesuser"
DB_PASSWORD = "Sqldb@123"
DB_DRIVER   = "ODBC Driver 17 for SQL Server"  # or appropriate ODBC driver


connection_url = URL.create(
        "mssql+pyodbc",
        username=DB_USERNAME,
        password=DB_PASSWORD,
        host="tcp:" + DB_SERVER,
        port=1433,
        database=DB_NAME,
        query={"driver": "ODBC Driver 17 for SQL Server"}
    )
engine = create_engine(connection_url)
