import streamlit as st
import mysql.connector
import os
import bcrypt
import pandas as pd
# We have removed the 'import bcrypt'

# --- Page Configuration ---
st.set_page_config(page_title="Investigation System", layout="wide")

# --- Database Connection ---
def get_db_connection():
    """Establishes a connection to the MySQL database using st.secrets."""
    try:
        conn = mysql.connector.connect(
            # Read credentials directly from st.secrets
            host=st.secrets["database"]["host"],
            user=st.secrets["database"]["user"],
            password=st.secrets["database"]["password"],
            database=st.secrets["database"]["database"]
        )
        return conn
    except mysql.connector.Error as err:
        st.error(f"Error connecting to database: {err}")
        return None
    except Exception as e:
        # This will catch errors if secrets.toml is not set up
        st.error(f"Error reading secrets.toml: {e}")
        st.info("Please make sure you have a .streamlit/secrets.toml file with your [database] credentials.")
        return None

# --- Login Logic (Simple, Insecure Version) ---
def check_login(username, password):
    """
    Checks if username and password match a hashed password in the DB.
    Returns: (is_success, role, user_id)
    """
    conn = get_db_connection()
    if conn is None:
        return False, None, None

    try:
        cursor = conn.cursor(dictionary=True)
        
        # --- MODIFIED QUERY: Only fetch user by username ---
        query = ("SELECT user_id, role, password_hash, is_active FROM users "
                 "WHERE username = %s")
        
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if result and result['is_active']:
            # --- SECURITY CHECK ---
            # Check if the plain-text password matches the stored hash
            password_bytes = password.encode('utf-8')
            hashed_pw_bytes = result['password_hash'].encode('utf-8')
            
            if bcrypt.checkpw(password_bytes, hashed_pw_bytes):
                # --- PASSWORD IS CORRECT ---
                return True, result['role'], result['user_id']
        
        # If user not found, or password invalid, or not active
        return False, None, None

    except mysql.connector.Error as err:
        st.error(f"Database query error: {err}")
        return False, None, None
    except Exception as e:
        # This can catch bcrypt errors if the hash is invalid
        st.error(f"Login check error: {e}")
        return False, None, None
    
def get_investigators(conn, supervisor_id):
    """Fetches all active users with the 'Investigator' role FOR A SPECIFIC SUPERVISOR."""
    try:
        cursor = conn.cursor(dictionary=True)
        
        # --- THIS QUERY IS NOW UPDATED ---
        query = """
            SELECT user_id, username 
            FROM users 
            WHERE role = 'Investigator' 
            AND is_active = 1 
            AND supervisor_id = %s
        """
        
        cursor.execute(query, (supervisor_id,))
        investigators = cursor.fetchall()
        return investigators
    except mysql.connector.Error as err:
        st.error(f"Error fetching investigators: {err}")
        return []
    
def get_recent_activity(conn, supervisor_id, limit=10):
    """Fetches the most recent, human-readable audit log entries FOR A SPECIFIC SUPERVISOR'S TEAM."""
    try:
        cursor = conn.cursor(dictionary=True)
        # --- THE QUERY IS UPDATED ---
        # We've added the "WHERE u.supervisor_id = %s" line
        query = """
            SELECT 
                a.log_timestamp,
                a.action_type,
                a.details,
                u.username,
                c.title AS case_title
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.user_id
            LEFT JOIN cases c ON a.case_id = c.case_id
            WHERE u.supervisor_id = %s
            ORDER BY a.log_timestamp DESC
            LIMIT %s
        """
        # Pass both parameters, in order
        cursor.execute(query, (supervisor_id, limit))
        logs = cursor.fetchall()
        return logs
    except mysql.connector.Error as err:
        st.error(f"Error fetching recent activity: {err}")
        return []
        
def get_pending_requests(conn, supervisor_id):
    """Fetches all pending requests FOR A SPECIFIC SUPERVISOR'S TEAM."""
    try:
        cursor = conn.cursor(dictionary=True)
        # --- THE QUERY IS UPDATED ---
        # We've added the "AND u.supervisor_id = %s" line
        query = """
            SELECT 
                r.request_id,
                r.requested_on,
                r.request_type,
                r.request_value_old,
                r.request_value_new,
                r.request_details,
                u.username AS investigator_name,
                c.title AS case_title,
                c.case_id
            FROM approval_requests r
            JOIN users u ON r.requested_by = u.user_id
            JOIN cases c ON r.case_id = c.case_id
            WHERE r.status = 'Pending' AND u.supervisor_id = %s
            ORDER BY r.requested_on ASC
        """
        # Pass the supervisor_id as a parameter
        cursor.execute(query, (supervisor_id,))
        requests = cursor.fetchall()
        return requests
    except mysql.connector.Error as err:
        st.error(f"Error fetching pending requests: {err}")
        return []   
    
def get_all_users_admin(conn):
    """Fetches a complete list of all users and their supervisor's name, if any."""
    try:
        cursor = conn.cursor(dictionary=True)
        # We use a LEFT JOIN to get the supervisor's username from the same table
        query = """
            SELECT 
                u.user_id, 
                u.username, 
                u.email, 
                u.phone, 
                u.role, 
                u.is_active, 
                s.username AS supervisor_name
            FROM users u
            LEFT JOIN users s ON u.supervisor_id = s.user_id
            ORDER BY u.user_id;
        """
        cursor.execute(query)
        users = cursor.fetchall()
        return users
    except mysql.connector.Error as err:
        st.error(f"Error fetching all users: {err}")
        return []
    
def get_case_details(conn, case_id):
    """Fetches the details for a single case."""
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM cases WHERE case_id = %s"
        cursor.execute(query, (case_id,))
        case = cursor.fetchone()
        return case
    except mysql.connector.Error as err:
        st.error(f"Error fetching case details: {err}")
        return None

def get_court_files_for_case(conn, case_id):
    """Fetches all court files for a specific case."""
    try:
        cursor = conn.cursor(dictionary=True)
        # --- THIS QUERY IS NOW CORRECTED ---
        query = """
            SELECT court_file_id, description, file_path, submission_date 
            FROM courtfiles 
            WHERE case_id = %s 
            ORDER BY submission_date DESC
        """
        cursor.execute(query, (case_id,))
        files = cursor.fetchall()
        return files
    except mysql.connector.Error as err:
        st.error(f"Error fetching court files: {err}")
        return []

def read_file_bytes(file_path):
    """Reads a file from the server and returns its bytes for download."""
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        st.error(f"File not found at {file_path}. It may have been moved or deleted.")
        return None
    except Exception as e:
        st.error(f"Error reading file: {e}")
        return None

def get_case_status_options(current_status):
    """Returns a list of valid next statuses."""
    all_statuses = ['Open', 'Under Review', 'Pending Approval', 'Closed']
    # You can't request a status you already have
    all_statuses.remove(current_status)
    return all_statuses

def get_evidence_for_case(conn, case_id):
    """Fetches all evidence items for a specific case."""
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT evidence_id, description, file_path, submission_date 
            FROM evidence 
            WHERE case_id = %s 
            ORDER BY submission_date DESC
        """
        cursor.execute(query, (case_id,))
        evidence = cursor.fetchall()
        return evidence
    except mysql.connectorError as err:
        st.error(f"Error fetching evidence: {err}")
        return []
    
def get_all_cases_admin(conn):
    """
    Fetches a master list of ALL cases for the admin dashboard.
    Joins to find the *current* investigator for each case.
    """
    try:
        cursor = conn.cursor(dictionary=True)
        # This complex query finds all cases, then LEFT JOINS to find
        # the most recent assignment for each case, then LEFT JOINS
        # to get that investigator's username.
        query = """
            SELECT 
                c.case_id, 
                c.title, 
                c.status, 
                c.created_on, 
                c.last_update,
                COALESCE(u.username, '--- Unassigned ---') AS current_investigator
            FROM cases c
            LEFT JOIN (
                -- This subquery finds the single MOST RECENT assignment for each case
                SELECT ca1.case_id, ca1.investigator_id
                FROM case_assignments ca1
                INNER JOIN (
                    SELECT case_id, MAX(assigned_date) AS max_date
                    FROM case_assignments
                    GROUP BY case_id
                ) ca2 ON ca1.case_id = ca2.case_id AND ca1.assigned_date = ca2.max_date
            ) latest_ca ON c.case_id = latest_ca.case_id
            LEFT JOIN users u ON latest_ca.investigator_id = u.user_id
            ORDER BY c.last_update DESC;
        """
        cursor.execute(query)
        cases = cursor.fetchall()
        return cases
    except mysql.connector.Error as err:
        st.error(f"Error fetching all cases: {err}")
        return []

def get_case_load_report(conn):
    """
    Generates a report of active case loads for all investigators.
    Includes investigators with 0 active cases.
    """
    try:
        cursor = conn.cursor(dictionary=True)
        # This query finds all active investigators, then LEFT JOINS a subquery
        # that counts only non-closed cases for each investigator.
        query = """
            SELECT 
                u.username,
                u.user_id,
                COALESCE(case_counts.active_cases_count, 0) AS active_cases_count
            FROM users u
            LEFT JOIN (
                -- This subquery counts active cases for each investigator
                SELECT 
                    latest_ca.investigator_id, 
                    COUNT(latest_ca.case_id) AS active_cases_count
                FROM (
                    -- This subquery finds the latest investigator for all NON-CLOSED cases
                    SELECT 
                        ca1.investigator_id,
                        ca1.case_id
                    FROM case_assignments ca1
                    INNER JOIN (
                        SELECT case_id, MAX(assigned_date) AS max_date
                        FROM case_assignments
                        GROUP BY case_id
                    ) ca2 ON ca1.case_id = ca2.case_id AND ca1.assigned_date = ca2.max_date
                    JOIN cases c ON ca1.case_id = c.case_id
                    WHERE c.status != 'Closed'
                ) latest_ca
                GROUP BY latest_ca.investigator_id
            ) case_counts ON u.user_id = case_counts.investigator_id
            WHERE u.role = 'Investigator' AND u.is_active = 1
            ORDER BY active_cases_count DESC, u.username;
        """
        cursor.execute(query)
        report = cursor.fetchall()
        return report
    except mysql.connector.Error as err:
        st.error(f"Error generating case load report: {err}")
        return []
    
def get_all_supervisors(conn):
    """Fetches all active users with the 'Supervisor' role."""
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT user_id, username FROM users WHERE role = 'Supervisor' AND is_active = 1"
        cursor.execute(query)
        supervisors = cursor.fetchall()
        return supervisors
    except mysql.connector.Error as err:
        st.error(f"Error fetching supervisors: {err}")
        return []

def get_global_audit_log(conn, limit=50):
    """Fetches the UNFILTERED, global audit log for the admin."""
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
                a.log_timestamp,
                a.action_type,
                a.details,
                u.username,
                c.title AS case_title
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.user_id
            LEFT JOIN cases c ON a.case_id = c.case_id
            ORDER BY a.log_timestamp DESC
            LIMIT %s
        """
        cursor.execute(query, (limit,))
        logs = cursor.fetchall()
        return logs
    except mysql.connector.Error as err:
        st.error(f"Error fetching global audit log: {err}")
        return []
    
def get_assignable_cases(conn):
    """Fetches all cases that are not 'Closed'."""
    try:
        cursor = conn.cursor(dictionary=True)
        # Get cases that are not 'Closed'
        query = "SELECT case_id, title FROM cases WHERE status != 'Closed'"
        cursor.execute(query)
        cases = cursor.fetchall()
        return cases
    except mysql.connector.Error as err:
        st.error(f"Error fetching assignable cases: {err}")
        return []
    
def handle_approval(conn, request_data, supervisor_id, notes):
    """
    Handles the logic for APPROVING a request.
    This is complex: it must update the request AND perform the action.
    """
    cursor = conn.cursor()
    try:
        # --- Step 1: Perform the requested action ---
        if request_data['request_type'] == 'Status Change':
            # ACTION: Update the case status
            update_case_query = "UPDATE cases SET status = %s, last_update = NOW() WHERE case_id = %s"
            cursor.execute(update_case_query, (
                request_data['request_value_new'], 
                request_data['case_id']
            ))
            
            # (Later, we'll add 'elif' for other request types)

        # --- Step 2: Update the approval_requests table ---
        update_req_query = """
            UPDATE approval_requests 
            SET status = 'Approved', handled_by = %s, handled_on = NOW(), handler_notes = %s
            WHERE request_id = %s
        """
        cursor.execute(update_req_query, (
            supervisor_id, 
            notes, 
            request_data['request_id']
        ))

        # --- Step 3: (Optional but Recommended) Log this approval to the audit_log ---
        log_details = f"Approved request {request_data['request_id']} ({request_data['request_type']})"
        log_query = """
            INSERT INTO audit_log (case_id, user_id, action_type, details)
            VALUES (%s, %s, 'Request Approved', %s)
        """
        cursor.execute(log_query, (
            request_data['case_id'],
            supervisor_id,
            log_details
        ))

        conn.commit()
        st.success(f"Request {request_data['request_id']} has been approved.")
        
    except mysql.connector.Error as err:
        conn.rollback()
        st.error(f"Failed to approve request: {err}")
    finally:
        cursor.close()

def handle_rejection(conn, request_id, supervisor_id, notes):
    """Handles the logic for REJECTING a request."""
    cursor = conn.cursor()
    try:
        # --- Step 1: Update the approval_requests table ---
        query = """
            UPDATE approval_requests 
            SET status = 'Rejected', handled_by = %s, handled_on = NOW(), handler_notes = %s
            WHERE request_id = %s
        """
        cursor.execute(query, (supervisor_id, notes, request_id))
        
        # --- Step 2: (Optional) Log this rejection ---
        # (You can add an audit_log insert here if you want)
        
        conn.commit()
        st.warning(f"Request {request_id} has been rejected.")
        
    except mysql.connector.Error as err:
        conn.rollback()
        st.error(f"Failed to reject request: {err}")
    finally:
        cursor.close()
    
def save_uploaded_file(uploaded_file, case_id, upload_dir):
    """Saves an uploaded file to a case-specific directory and returns the path."""
    try:
        # Create a unique, safe directory for the case
        case_dir = os.path.join(upload_dir, f"case_{case_id}")
        if not os.path.exists(case_dir):
            os.makedirs(case_dir)
            
        # Create a safe file path
        # Use a timestamp or unique ID to prevent overwrites
        from datetime import datetime
        filename, file_extension = os.path.splitext(uploaded_file.name)
        unique_filename = f"{filename}_{int(datetime.now().timestamp())}{file_extension}"
        file_path = os.path.join(case_dir, unique_filename)
        
        # Write the file's binary data
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
            
        return file_path
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None

def get_case_details(conn, case_id):
    """Fetches the details for a single case."""
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM cases WHERE case_id = %s"
        cursor.execute(query, (case_id,))
        case = cursor.fetchone()
        return case
    except mysql.connector.Error as err:
        st.error(f"Error fetching case details: {err}")
        return None


def read_file_bytes(file_path):
    """Reads a file from the server and returns its bytes for download."""
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        st.error(f"File not found at {file_path}. It may have been moved or deleted.")
        return None
    except Exception as e:
        st.error(f"Error reading file: {e}")
        return None

def get_case_status_options(current_status):
    """Returns a list of valid next statuses."""
    all_statuses = ['Open', 'Under Review', 'Pending Approval', 'Closed']
    # You can't request a status you already have
    if current_status in all_statuses:
        all_statuses.remove(current_status)
    return all_statuses

def get_investigator_cases(conn, investigator_id):
    """Fetches all cases assigned to a specific investigator."""
    try:
        cursor = conn.cursor(dictionary=True)
        # This query joins cases and case_assignments
        # It finds all cases where this investigator has the *most recent* assignment
        # and the case is not 'Closed'.
        query = """
            SELECT 
                c.case_id, 
                c.title, 
                c.status, 
                c.description,
                c.last_update
            FROM cases c
            JOIN (
                SELECT 
                    case_id, 
                    investigator_id, 
                    assigned_date
                FROM case_assignments ca1
                WHERE ca1.assigned_date = (
                    SELECT MAX(ca2.assigned_date)
                    FROM case_assignments ca2
                    WHERE ca1.case_id = ca2.case_id
                )
            ) AS ca ON c.case_id = ca.case_id
            WHERE ca.investigator_id = %s AND c.status != 'Closed'
            ORDER BY c.last_update DESC;
        """
        cursor.execute(query, (investigator_id,))
        cases = cursor.fetchall()
        return cases
    except mysql.connector.Error as err:
        st.error(f"Error fetching assigned cases: {err}")
        return []

def get_unassigned_cases(conn):
    """Fetches all cases that are not in the case_assignments table."""
    try:
        cursor = conn.cursor(dictionary=True)
        # This query finds cases in 'cases' table that don't have a matching 'case_id' in 'case_assignments'
        query = """
            SELECT c.case_id, c.title 
            FROM cases c
            LEFT JOIN case_assignments ca ON c.case_id = ca.case_id
            WHERE ca.assignment_id IS NULL AND c.status = 'Open'
        """
        cursor.execute(query)
        cases = cursor.fetchall()
        return cases
    except mysql.connector.Error as err:
        st.error(f"Error fetching unassigned cases: {err}")
        return []
    
# --- UI Functions ---
def show_login_page():
    """Displays the login form in the center of the page."""
    
    col1, col2, col3 = st.columns([1,1,1])
    
    with col2:
        # --- UPDATED TEXT ---
        # We can use markdown for styling (like the emoji)
        st.title("INVESTIGATION AND EVIDENCE MANAGEMENT")
        
        # We can put the login text inside the form
        with st.form("login_form"):
            st.subheader("User Login") # Moved subheader inside
            
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")

            if submitted:
                is_success, role, user_id = check_login(username, password)
                
                if is_success:
                    st.session_state['logged_in'] = True
                    st.session_state['username'] = username
                    st.session_state['role'] = role
                    st.session_state['user_id'] = user_id
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
def show_dashboard():
    """Displays the main dashboard after a successful login."""
    
    # --- Sidebar ---
    st.sidebar.success(f"Logged in as {st.session_state['username']}")
    st.sidebar.write(f"Role: **{st.session_state['role']}**")
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.session_state['selected_case_id'] = None # Clear selected case
        st.rerun()

    # --- Main Dashboard Area ---
    # The title is now handled inside each specific dashboard function
    
    conn = get_db_connection()
    if conn is None:
        st.error("Failed to connect to the database. Please check your settings.")
        st.stop()
        
    role = st.session_state['role']
    
    if role == 'Admin':
        show_admin_dashboard(conn) # Pass connection
    elif role == 'Supervisor':
        show_supervisor_dashboard(conn) # Pass connection
    elif role == 'Investigator':
        investigator_id = st.session_state['user_id']
        show_investigator_dashboard(conn, investigator_id) # Pass connection
    else:
        st.error("Your user role is not recognized. Please contact an admin.")
    
    conn.close() # Close connection when done
# --- Specific Dashboard Functions ---

def show_admin_dashboard(conn):
    st.header("Admin Dashboard ")
    st.write("Full control panel for user and system management.")

    tab_audit, tab_reports, tab_users = st.tabs([
        "🛡️ System Audit Log", 
        "📊 Reports & Case Oversight",
        "👤 User Management"
    ])

    # --- TAB 1: SYSTEM AUDIT LOG (Complete) ---
    with tab_audit:
        st.subheader("Global System Audit Log")
        st.markdown("This log shows all major activities from all users across the system.")
        
        global_logs = get_global_audit_log(conn, limit=50)
        
        if not global_logs:
            st.info("No system activity has been logged yet.")
        else:
            for log in global_logs:
                ts = log['log_timestamp'].strftime('%Y-%m-%d %I:%M %p')
                st.markdown(f"**{log['action_type']}**")
                st.markdown(f"""
                * **User:** `{log.get('username', 'N/A')}`
                * **Case:** `{log.get('case_title', 'N/A')}`
                * **Time:** `{ts}`
                * **Details:** *"{log.get('details', 'No details')}"*
                """)
                st.divider()

    # --- TAB 2: REPORTS & CASE OVERSIGHT (Complete) ---
    with tab_reports:
        st.subheader("System Reports and Case Oversight")
        
        st.markdown("### Investigator Case Load")
        st.write("This report shows all active investigators and their current number of *non-closed* cases.")
        case_load_data = get_case_load_report(conn)
        if not case_load_data:
            st.info("No active investigators found.")
        else:
            df_load = pd.DataFrame(case_load_data)
            df_load.rename(columns={
                'username': 'Investigator', 
                'active_cases_count': 'Active Cases'
            }, inplace=True)
            st.dataframe(df_load.set_index('Investigator'), use_container_width=True)

        st.divider()
        
        st.markdown("### All Cases (Master View)")
        st.write("This is a complete list of all cases in the system.")
        all_cases_data = get_all_cases_admin(conn)
        
        if not all_cases_data:
            st.info("No cases found in the system.")
        else:
            df_cases = pd.DataFrame(all_cases_data)
            df_cases = df_cases[[
                'case_id', 
                'title', 
                'status', 
                'current_investigator', 
                'last_update'
            ]]
            st.dataframe(df_cases.set_index('case_id'), use_container_width=True)

    # --- TAB 3: USER MANAGEMENT (NOW FULLY COMPLETE) ---
    with tab_users:
        st.subheader("Create New User Account")
        
        all_supervisors = get_all_supervisors(conn)
        supervisor_map = {sup['username']: sup['user_id'] for sup in all_supervisors}

        role = st.selectbox(
            "Select Role", 
            ['Admin', 'Supervisor', 'Investigator'], 
            key="admin_create_role"
        )
        
        with st.form("create_user_form", clear_on_submit=True):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            email = st.text_input("Email Address")
            phone = st.text_input("Phone Number (Optional)", key="admin_create_phone")
            
            selected_supervisor = None
            
            if role == 'Investigator':
                st.markdown("---")
                st.info("Assign this investigator to a supervisor.")
                if not supervisor_map:
                    st.warning("No Supervisors found. Please create a Supervisor user first.")
                else:
                    sup_name = st.selectbox("Assign to Supervisor", options=supervisor_map.keys())
                    selected_supervisor = supervisor_map[sup_name]
            
            submit_button = st.form_submit_button("Create User")

            if submit_button:
                if not username or not password or not email:
                    st.error("Username, Password, and Email are required.")
                elif role == 'Investigator' and not selected_supervisor:
                    st.error("You must assign an Investigator to a Supervisor.")
                else:
                    try:
                        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                        cursor = conn.cursor()
                        query = """
                            INSERT INTO users 
                            (username, password_hash, role, supervisor_id, is_active, email, phone)
                            VALUES (%s, %s, %s, %s, 1, %s, %s)
                        """
                        cursor.execute(query, (
                            username, hashed_pw, role, selected_supervisor, email, phone
                        ))
                        conn.commit()
                        st.success(f"User '{username}' created successfully!")
                        st.rerun() # Rerun to update the "Manage" table below
                        
                    except mysql.connector.Error as err:
                        if err.errno == 1062:
                            st.error(f"Database Error: An account with that email or username already exists.")
                        else:
                            st.error(f"Database Error: {err}")
                    except Exception as e:
                        st.error(f"An error occurred: {e}")

        st.divider()
        st.subheader("Manage Existing Users")
        
        all_users_data = get_all_users_admin(conn)
        
        if not all_users_data:
            st.info("No users found.")
        else:
            df_users = pd.DataFrame(all_users_data)
            # Format 'is_active' to be readable
            df_users['is_active'] = df_users['is_active'].apply(lambda x: '✅ Active' if x else '❌ Inactive')
            st.dataframe(df_users.set_index('user_id'), use_container_width=True)

            # --- ACTION FORMS ---
            
            # Create maps for our forms
            user_map = {u['username']: u['user_id'] for u in all_users_data}
            investigator_map = {u['username']: u['user_id'] for u in all_users_data if u['role'] == 'Investigator'}
            
            # Use columns for a cleaner layout
            col1, col2 = st.columns(2)
            
            with col1:
                # --- Form 1: Toggle User Status ---
                with st.expander("Activate / Deactivate User"):
                    with st.form("toggle_status_form", clear_on_submit=True):
                        user_to_toggle = st.selectbox("Select User", options=user_map.keys(), key="toggle_user")
                        new_status = st.selectbox("Select New Status", options=[('✅ Active', 1), ('❌ Inactive', 0)], format_func=lambda x: x[0], key="toggle_status")
                        
                        if st.form_submit_button("Update Status"):
                            user_id = user_map[user_to_toggle]
                            status_val = new_status[1] # This is 1 or 0
                            try:
                                cursor = conn.cursor()
                                cursor.execute("UPDATE users SET is_active = %s WHERE user_id = %s", (status_val, user_id))
                                conn.commit()
                                st.success(f"User '{user_to_toggle}' status updated to {new_status[0]}.")
                                st.rerun() # Refresh the page
                            except mysql.connector.Error as err:
                                st.error(f"Database error: {err}")

                # --- Form 2: Change User Role ---
                with st.expander("Change User Role"):
                    with st.form("change_role_form", clear_on_submit=True):
                        user_to_change = st.selectbox("Select User", options=user_map.keys(), key="role_user")
                        new_role = st.selectbox("Select New Role", options=['Admin', 'Supervisor', 'Investigator'], key="role_new")
                        
                        if st.form_submit_button("Update Role"):
                            user_id = user_map[user_to_change]
                            try:
                                cursor = conn.cursor()
                                # Clear supervisor_id when changing role
                                cursor.execute("UPDATE users SET role = %s, supervisor_id = NULL WHERE user_id = %s", (new_role, user_id))
                                conn.commit()
                                st.success(f"User '{user_to_change}'s role updated to {new_role}.")
                                if new_role == 'Investigator':
                                    st.warning("Please use the 'Re-assign' form to assign this new Investigator to a Supervisor.")
                                st.rerun()
                            except mysql.connector.Error as err:
                                st.error(f"Database error: {err}")

            with col2:
                # --- Form 3: Re-assign Investigator ---
                with st.expander("Re-assign Investigator"):
                    if not investigator_map:
                        st.info("No investigators in the system to re-assign.")
                    elif not supervisor_map:
                        st.info("No supervisors in the system to assign to.")
                    else:
                        with st.form("reassign_form", clear_on_submit=True):
                            inv_to_reassign = st.selectbox("Select Investigator", options=investigator_map.keys(), key="reassign_inv")
                            new_sup = st.selectbox("Select New Supervisor", options=supervisor_map.keys(), key="reassign_sup")
                            
                            if st.form_submit_button("Re-assign Investigator"):
                                inv_id = investigator_map[inv_to_reassign]
                                sup_id = supervisor_map[new_sup]
                                try:
                                    cursor = conn.cursor()
                                    cursor.execute("UPDATE users SET supervisor_id = %s WHERE user_id = %s", (sup_id, inv_id))
                                    conn.commit()
                                    st.success(f"Investigator '{inv_to_reassign}' has been re-assigned to {new_sup}.")
                                    st.rerun()
                                except mysql.connector.Error as err:
                                    st.error(f"Database error: {err}")

def show_supervisor_dashboard(conn):
    
    st.title(f"Welcome, {st.session_state['username']}!")
    st.write("---") 

    # --- NEW LAYOUT: Using st.expander ---
    # We will put the forms in two columns
    col1, col2 = st.columns(2)

    with col1:
        # This expander acts like a clickable, drop-down button
        with st.expander("Create New Case", expanded=False):
            st.markdown("#### Enter Case Details")
            # Using a unique form key
            with st.form("new_case_form_expander", clear_on_submit=True):
                case_title = st.text_input("Case Title")
                case_description = st.text_area("Case Description", height=150)
                submit_case = st.form_submit_button("Create Case")

                if submit_case:
                    if not case_title:
                        st.warning("Case Title is required.")
                    else:
                        try:
                            supervisor_id = st.session_state['user_id']
                            cursor = conn.cursor()
                            query = """
                                INSERT INTO cases (title, description, created_by, status) 
                                VALUES (%s, %s, %s, 'Open')
                            """
                            cursor.execute(query, (case_title, case_description, supervisor_id))
                            conn.commit()
                            st.success(f"Case '{case_title}' created.")
                        except mysql.connector.Error as err:
                            st.error(f"Database error: {err}")
                        
                            

    with col2:
        # This is the second expander
        with st.expander("Assign/Reassign Case", expanded=False):
            st.markdown("#### Select Case and Investigator")
            
            if conn:
                current_supervisor_id = st.session_state['user_id']
                investigators = get_investigators(conn, current_supervisor_id)
               
                assignable_cases = get_assignable_cases(conn)
                if not investigators:
                    st.warning("No active 'Investigator' users found.")
                elif not assignable_cases:
                    st.info("No assignable cases found.")
                else:
                    investigator_map = {inv['username']: inv['user_id'] for inv in investigators}
                    case_map = {case['title']: case['case_id'] for case in assignable_cases}
                    
                    # Using a unique form key
                    with st.form("assign_case_form_expander", clear_on_submit=True):
                        selected_case_title = st.selectbox("Select Case", options=case_map.keys())
                        selected_investigator_name = st.selectbox("Assign to", options=investigator_map.keys())
                        submit_assignment = st.form_submit_button("Assign Case")

                        if submit_assignment:
                            case_id = case_map[selected_case_title]
                            investigator_id = investigator_map[selected_investigator_name]
                            try:
                                supervisor_id = st.session_state['user_id']
                                cursor = conn.cursor()
                                query = """
                                    INSERT INTO case_assignments (case_id, investigator_id, assigned_by) 
                                    VALUES (%s, %s, %s)
                                """
                                cursor.execute(query, (case_id, investigator_id, supervisor_id))
                                conn.commit()
                                st.success(f"Case '{selected_case_title}' assigned to {selected_investigator_name}.")
                            except mysql.connector.Error as err:
                                st.error(f"Database error: {err}")
                            
            else:
                st.error("Database connection failed. Cannot load assignment tools.")

    # --- Rest of the Dashboard ---
    st.write("---") 
    
    # --- This is your NEW code ---
    st.subheader("Manage Approval Requests")
    
    # --- This is your NEW line ---
    current_supervisor_id = st.session_state['user_id']
    pending_requests = get_pending_requests(conn, current_supervisor_id)
    
    if not pending_requests:
        st.info("No pending approval requests.")
    else:
        st.write(f"You have **{len(pending_requests)}** pending requests.")
        
        # We use an expander for each request
        for req in pending_requests:
            expander_title = f"**{req['request_type']}** for '{req['case_title']}' from *{req['investigator_name']}*"
            
            with st.expander(expander_title):
                st.markdown(f"**Investigator:** `{req['investigator_name']}`")
                st.markdown(f"**Case:** `{req['case_title']}`")
                st.caption(f"Requested On: {req['requested_on'].strftime('%Y-%m-%d %I:%M %p')}")
                
                # --- Display details based on request type ---
                if req['request_type'] == 'Status Change':
                    st.warning(f"**Request:** Change status from `{req['request_value_old']}` to `{req['request_value_new']}`")
                    st.info(f"**Justification:** {req['request_details']}")
                
                # (Later we will add elif for 'Resource', etc.)
                
                else:
                    st.info(f"**Details:** {req['request_details']}")

                st.write("---")
                
                # --- Approval/Rejection Form ---
                # We use a unique key for each form
                with st.form(key=f"form_req_{req['request_id']}"):
                    handler_notes = st.text_area("Your Notes (Optional)", key=f"notes_{req['request_id']}")
                    
                    # Use columns for the buttons
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.form_submit_button("Approve", use_container_width=True, type="primary"):
                            handle_approval(conn, req, st.session_state['user_id'], handler_notes)
                            st.rerun()
                            
                    with col2:
                        if st.form_submit_button("Reject", use_container_width=True):
                            handle_rejection(conn, req['request_id'], st.session_state['user_id'], handler_notes)
                            st.rerun()
    
    st.subheader("Recent Activity")
    
    # --- This is your NEW line ---
    current_supervisor_id = st.session_state['user_id']
    recent_logs = get_recent_activity(conn, current_supervisor_id, limit=10)
    
    if not recent_logs:
        st.info("No recent activity found.")
    else:
        for log in recent_logs:
            # Format the timestamp to be more readable
            ts = log['log_timestamp'].strftime('%Y-%m-%d %I:%M %p')
            
            # Use markdown for nice formatting
            st.markdown(f"""
            **{log['action_type']}**
            * **User:** `{log['username']}`
            * **Case:** `{log['case_title']}`
            * **Time:** `{ts}`
            * **Details:** *"{log['details']}"*
            """)
            st.divider() # Adds a line between entries
    
def show_investigator_dashboard(conn, investigator_id):
    """
    This function is now a "router".
    It shows the master list or the detail view based on session state.
    """
    # We must initialize 'selected_case_id' if it doesn't exist
    if 'selected_case_id' not in st.session_state:
        st.session_state['selected_case_id'] = None
        
    if st.session_state['selected_case_id'] is None:
        show_investigator_master_view(conn, investigator_id)
    else:
        show_investigator_detail_view(conn, investigator_id, st.session_state['selected_case_id'])

def show_investigator_master_view(conn, investigator_id):
    """Shows the 'folder' view of all assigned cases."""
    st.title(f"Welcome, {st.session_state['username']} 🕵️")
    st.subheader("Your Assigned Cases")

    my_cases = get_investigator_cases(conn, investigator_id)
    
    if not my_cases:
        st.info("You have no active cases assigned.")
        return

    # Create a grid of "folders"
    cols = st.columns(4) # 4 cases per row
    col_index = 0
    
    for case in my_cases:
        with cols[col_index]:
            
            # --- THIS IS THE CORRECTED LINE ---
            # I have removed the 'height=150' argument.
            if st.button(f"📁 **{case['title']}**\n\n_{case['status']}_", use_container_width=True, key=f"case_btn_{case['case_id']}"):
                st.session_state['selected_case_id'] = case['case_id']
                st.rerun()
        
        col_index = (col_index + 1) % 4

def show_investigator_detail_view(conn, investigator_id, case_id):
    """Shows the detailed view for a single selected case."""
    
    case = get_case_details(conn, case_id)
    if not case:
        st.error("Case not found.")
        st.session_state['selected_case_id'] = None
        st.rerun()
        return

    # --- 1. Header and Back Button ---
    if st.button("⬅️ Back to All Cases"):
        st.session_state['selected_case_id'] = None
        st.rerun()

    st.title(case['title'])
    st.caption(f"Status: {case['status']}")
    st.markdown(case['description'])
    st.write("---")

    # --- 2. TABS (Evidence, Court Files, Request Change) ---
    # --- This is your NEW line ---
    tab_evidence, tab_court, tab_request = st.tabs([
        "Evidence", 
        "Court Files", 
        "Request Approval"
    ])

    # --- TAB 1: Evidence ---
    with tab_evidence:
        st.subheader("Manage Evidence")
        
        # Form to add new evidence
        with st.form(f"form_ev_{case_id}", clear_on_submit=True):
            ev_desc = st.text_area("Evidence Description")
            uploaded_file = st.file_uploader(
                "Upload evidence file (drag and drop)", 
                key=f"upload_ev_{case_id}"
            )
            
            if st.form_submit_button("Submit Evidence"):
                if not ev_desc or not uploaded_file:
                    st.warning("Please provide a description and upload a file.")
                else:
                    file_path = save_uploaded_file(uploaded_file, case_id, "uploads/evidence")
                    
                    if file_path:
                        try:
                            cursor = conn.cursor()
                            query = "INSERT INTO evidence (case_id, description, file_path, submitted_by) VALUES (%s, %s, %s, %s)"
                            cursor.execute(query, (case_id, ev_desc, file_path, investigator_id))
                            conn.commit()
                            st.success("Evidence submitted successfully!")
                            st.rerun() # Refresh the tab
                        except mysql.connector.Error as err:
                            st.error(f"Database error: {err}")

        # List of existing evidence
        st.divider()
        st.subheader("Existing Evidence")
        case_evidence = get_evidence_for_case(conn, case_id)
        if not case_evidence:
            st.info("No evidence submitted.")
        else:
            for ev in case_evidence:
                st.markdown(f"**Description:** {ev['description']}")
                st.caption(f"Submitted: {ev['submission_date']}")
                file_data = read_file_bytes(ev['file_path'])
                if file_data:
                    st.download_button(
                        label=f"Download File: {os.path.basename(ev['file_path'])}",
                        data=file_data,
                        file_name=os.path.basename(ev['file_path']),
                        key=f"d_ev_{ev['evidence_id']}"
                    )
                st.write("---")

    # --- TAB 2: Court Files ---
    with tab_court:
        st.subheader("Manage Court Files")
        
        with st.form(f"form_cf_{case_id}", clear_on_submit=True):
            cf_desc = st.text_area("File Description")
            uploaded_file = st.file_uploader(
                "Upload court file (drag and drop)", 
                key=f"upload_cf_{case_id}"
            )
            
            if st.form_submit_button("Submit Court File"):
                if not cf_desc or not uploaded_file:
                    st.warning("Please provide a description and upload a file.")
                else:
                    file_path = save_uploaded_file(uploaded_file, case_id, "uploads/courtfiles")
                    
                    if file_path:
                        try:
                            cursor = conn.cursor()
                            query = "INSERT INTO courtfiles (case_id, description, file_path, submitted_by) VALUES (%s, %s, %s, %s)"
                            cursor.execute(query, (case_id, cf_desc, file_path, investigator_id))
                            conn.commit()
                            st.success("Court file submitted successfully!")
                            st.rerun() # Refresh the tab
                        except mysql.connector.Error as err:
                            st.error(f"Database error: {err}")

        # List of existing court files
        st.divider()
        st.subheader("Existing Court Files")
        case_files = get_court_files_for_case(conn, case_id)
        if not case_files:
            st.info("No court files submitted.")
        else:
            for cf in case_files:
                st.markdown(f"**Description:** {cf['description']}")
                st.caption(f"Submitted: {cf['submission_date']}")
                file_data = read_file_bytes(cf['file_path'])
                if file_data:
                    st.download_button(
                        label=f"Download File: {os.path.basename(cf['file_path'])}",
                        data=file_data,
                        file_name=os.path.basename(cf['file_path']),
                        key=f"d_cf_{cf['court_file_id']}"
                    )
                st.write("---")

   # --- REPLACE your old 'with tab_request:' block with THIS ---

    # --- TAB 3: Request Approval ---
    with tab_request:
        st.subheader("Submit Request for Approval")
        
        # --- This list contains all your new request types ---
        request_options = [
            'Status Change', 
            'Resource Request', 
            'Reassignment Request', 
            'Evidence Verification Request', 
            'Court Submission Approval',
            'Other'
        ]
        
        # --- This dropdown is OUTSIDE the form, so it's interactive ---
        # It will cause the app to rerun and show/hide the fields below.
        req_type = st.selectbox(
            "Select Request Type", 
            options=request_options, 
            key=f"req_type_{case_id}"
        )

        # --- The form starts AFTER the selection ---
        with st.form(f"form_req_{case_id}", clear_on_submit=True):
            
            # --- This field is CONDITIONAL ---
            # It will ONLY appear if 'Status Change' is selected
            if req_type == 'Status Change':
                st.markdown(f"Current case status: **{case['status']}**")
                status_options = get_case_status_options(case['status'])
                
                if not status_options:
                    st.info("This case is 'Closed' or has no other statuses, and its status cannot be changed.")
                    # We can't proceed, so we just stop this part of the form.
                else:
                    # We need to give this widget a name for the code to read it
                    new_status = st.selectbox("Select New Status", options=status_options, key="req_new_status")
            
            # --- This field is COMMON ---
            # It will appear for ALL request types
            justification = st.text_area(
                "Justification / Details",
                height=150,
                placeholder="Provide a clear reason for your request. This is required."
            )
            
            submitted = st.form_submit_button("Submit Request")
            
            if submitted:
                if not justification:
                    st.warning("Please provide a justification for your request.")
                
                # --- Logic for STATUS CHANGE request ---
                elif req_type == 'Status Change':
                    # Check again if the case is closed
                    if not get_case_status_options(case['status']):
                         st.error("This case is closed and its status cannot be changed.")
                    else:
                        try:
                            cursor = conn.cursor()
                            query = """
                                INSERT INTO approval_requests 
                                (case_id, requested_by, request_type, request_value_old, request_value_new, request_details, status)
                                VALUES (%s, %s, 'Status Change', %s, %s, %s, 'Pending')
                            """
                            cursor.execute(query, (
                                case_id, investigator_id, 
                                case['status'], 
                                new_status,  # This comes from the selectbox above
                                justification
                            ))
                            conn.commit()
                            st.success("Status change request submitted.")
                            st.rerun()
                        except mysql.connector.Error as err:
                            st.error(f"Database error: {err}")
                            
                # --- Logic for ALL OTHER request types ---
                else:
                    try:
                        cursor = conn.cursor()
                        query = """
                            INSERT INTO approval_requests 
                            (case_id, requested_by, request_type, request_details, status)
                            VALUES (%s, %s, %s, %s, 'Pending')
                        """
                        cursor.execute(query, (
                            case_id, investigator_id, 
                            req_type,  # This comes from the main selectbox
                            justification
                        ))
                        conn.commit()
                        st.success(f"Your '{req_type}' has been submitted.")
                        st.rerun()
                    except mysql.connector.Error as err:
                        st.error(f"Database error: {err}")
# --- Main App Logic (The "Router") ---

# 1. Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ""
    st.session_state['role'] = ""
    st.session_state['user_id'] = None 
    st.session_state['selected_case_id'] = None # <-- ADD THIS LINE

# 2. Check login status... (rest of the file is the same)

if st.session_state['logged_in']:
    show_dashboard()
else:
    show_login_page()