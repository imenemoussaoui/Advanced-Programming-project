


import pyodbc

def get_db_connection():
    """
    Connexion au Data Warehouse (DW) Northwind_BI1
    Retourne un objet connexion si succès, sinon None.
    """

    server = "localhost"
    database = "python"   
    username = "sa"        
    password = ""    

    conn_str = (
        f"DRIVER={{SQL Server}};"
        f"SERVER=.;"
        f"DATABASE={database};"
        f"UID=sa;"
        f"PWD=imene@20005;"
        f"Trusted_Connection=no;"
    )
    
    try:
        conn = pyodbc.connect(conn_str)
        return conn
    except Exception as e:
        print(f"❌ Erreur de connexion au Data base : {e}")
        return None

def test_connection():
    """
    Test the database connection and print all table names.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print("Connected successfully!\nTables in database:")
        
        # Fetch all table names
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'")
        tables = cursor.fetchall()
        for t in tables:
            print("-", t[0])
        
        conn.close()
    except Exception as e:
        print("Connection failed:", e)


# Run test when executing this file directly
if __name__ == "__main__":
    test_connection()