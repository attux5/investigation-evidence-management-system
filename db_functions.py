import streamlit as st
import mysql.connector

# ✅ Create database connection
@st.cache_resource
def init_connection():
    return mysql.connector.connect(**st.secrets["database"])

# ✅ Check login credentials
def check_login(conn, username, password):
    cursor = conn.cursor(dictionary=True)
    query = "SELECT user_id, password, role, is_active FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    cursor.close()

    if result and result['is_active'] == 1 and password == result['password']:
        return True, result['role'], result['user_id']
    return False, None, None

# ✅ Fetch cases assigned to investigator
def get_assigned_cases(conn, investigator_id):
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT c.case_id, c.title, c.status, c.description
        FROM cases c
        JOIN case_assignments ca ON c.case_id = ca.case_id
        WHERE ca.investigator_id = %s
    """
    cursor.execute(query, (investigator_id,))
    cases = cursor.fetchall()
    cursor.close()
    return cases

# ✅ Fetch all investigators for Supervisor assignment
def get_all_investigators(conn):
    cursor = conn.cursor(dictionary=True)
    query = "SELECT user_id, username FROM users WHERE role = 'Investigator' AND is_active = 1"
    cursor.execute(query)
    data = cursor.fetchall()
    cursor.close()
    return data
