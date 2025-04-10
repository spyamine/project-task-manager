import streamlit as st
import pandas as pd
import os
import plotly.express as px
from datetime import datetime, timedelta
import bcrypt
import secrets
import string
import uuid
from io import BytesIO
from streamlit_extras.metric_cards import style_metric_cards
import time
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import zipfile

# File paths
USER_FILE = 'users.xlsx'
PROJECT_FILE = 'projects.xlsx'
TASK_FILE = 'tasks.xlsx'
ACTIVITY_LOG_FILE = 'activity_log.xlsx'
RESET_REQUESTS_FILE = 'reset_requests.xlsx'

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_role = None
    st.session_state.username = None
    st.session_state.last_activity = datetime.now()
    st.session_state.session_id = None

# Session timeout in minutes
SESSION_TIMEOUT = 30

# Add this function to validate email format using regex
def is_valid_email(email):
    import re
    # Basic email validation pattern
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

# Add this function to validate username format
def is_valid_username(username):
    import re
    # Allow alphanumeric characters, underscore, dot, minimum 3 characters, maximum 30
    pattern = r"^[a-zA-Z0-9._]{3,30}$"
    return re.match(pattern, username) is not None

# Add this function to validate password strength
def is_strong_password(password):
    # At least 8 characters, at least one uppercase letter, one lowercase letter, and one number
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
        
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
        
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
        
    return True, "Password is strong"

# Create or load data files
def initialize_data_files():
    # Users file
    try:
        # Try to read the file to check if it's valid
        pd.read_excel(USER_FILE)
    except (FileNotFoundError, zipfile.BadZipFile):
        # Create admin user with hashed password
        hashed_pwd = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
        users_df = pd.DataFrame([{
            'Username': 'admin',
            'Password': hashed_pwd,
            'Role': 'Admin',
            'Email': 'admin@example.com',
            'Name': 'Admin User',
            'Status': 'Active',
            'Last Login': None,
            'Created Date': datetime.now(),
            'Modified Date': datetime.now()
        }])
        users_df.to_excel(USER_FILE, index=False)
    
    # Projects file
    try:
        pd.read_excel(PROJECT_FILE)
    except (FileNotFoundError, zipfile.BadZipFile):
        pd.DataFrame(columns=[
            'Project ID', 'Project Name', 'Description', 'Start Date', 
            'End Date', 'Manager', 'Status', 'Created By', 'Created Date'
        ]).to_excel(PROJECT_FILE, index=False)
    
    # Tasks file
    try:
        pd.read_excel(TASK_FILE)
    except (FileNotFoundError, zipfile.BadZipFile):
        pd.DataFrame(columns=[
            'Task ID', 'Project ID', 'Title', 'Description', 'Due Date', 
            'Assignee', 'Status', 'Priority', 'File', 'Created By', 
            'Created Date', 'Modified By', 'Modified Date', 'Comments'
        ]).to_excel(TASK_FILE, index=False)
    
    # Activity log file
    try:
        pd.read_excel(ACTIVITY_LOG_FILE)
    except (FileNotFoundError, zipfile.BadZipFile):
        pd.DataFrame(columns=[
            'Log ID', 'User', 'Action', 'Details', 'Timestamp', 'IP Address'
        ]).to_excel(ACTIVITY_LOG_FILE, index=False)
    
    # Password reset requests file
    try:
        pd.read_excel(RESET_REQUESTS_FILE)
    except (FileNotFoundError, zipfile.BadZipFile):
        pd.DataFrame(columns=[
            'Request ID', 'Username', 'Token', 'Created Date', 'Expiry Date', 'Status'
        ]).to_excel(RESET_REQUESTS_FILE, index=False)


# Load data files
def load_data():
    users_df = pd.read_excel(USER_FILE)
    projects_df = pd.read_excel(PROJECT_FILE)
    tasks_df = pd.read_excel(TASK_FILE)
    activity_log_df = pd.read_excel(ACTIVITY_LOG_FILE)
    reset_requests_df = pd.read_excel(RESET_REQUESTS_FILE)
    
    # Convert date columns to datetime
    for df in [projects_df, tasks_df, activity_log_df, reset_requests_df]:
        for col in df.columns:
            if 'Date' in col or col == 'Timestamp' or col == 'Expiry Date':
                try:
                    df[col] = pd.to_datetime(df[col])
                except:
                    pass
    
    return users_df, projects_df, tasks_df, activity_log_df, reset_requests_df

# Log user activity
def log_activity(username, action, details=""):
    activity_log_df = pd.read_excel(ACTIVITY_LOG_FILE)
    
    new_log = pd.DataFrame([{
        'Log ID': f"LOG{len(activity_log_df)+1}",
        'User': username,
        'Action': action,
        'Details': details,
        'Timestamp': datetime.now(),
        'IP Address': 'N/A'  # In a real app, you would capture the IP
    }])
    
    activity_log_df = pd.concat([activity_log_df, new_log], ignore_index=True)
    activity_log_df.to_excel(ACTIVITY_LOG_FILE, index=False)

# Check session timeout
def check_session_timeout():
    if st.session_state.logged_in:
        current_time = datetime.now()
        elapsed_time = current_time - st.session_state.last_activity
        
        if elapsed_time.total_seconds() > SESSION_TIMEOUT * 60:
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.user_role = None
            st.session_state.session_id = None
            st.warning("Your session has expired. Please log in again.")
            st.rerun()
        else:
            st.session_state.last_activity = current_time

# Authentication functions
def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def authenticate_user(username, password):
    users_df, _, _, _, _ = load_data()
    
    user_row = users_df[users_df['Username'] == username]
    
    if user_row.empty:
        return False, None
    
    user_data = user_row.iloc[0]
    
    if user_data['Status'] != 'Active':
        return False, "Account is inactive. Please contact an administrator."
    
    if verify_password(user_data['Password'], password):
        # Update last login
        users_df.loc[users_df['Username'] == username, 'Last Login'] = datetime.now()
        users_df.to_excel(USER_FILE, index=False)
        
        # Log activity
        log_activity(username, "Login", "User logged in successfully")
        
        return True, user_data['Role']
    
    return False, None

# Generate secure token
def generate_token(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Password reset request
def create_password_reset_request(username):
    users_df, _, _, _, reset_requests_df = load_data()
    
    user_exists = not users_df[users_df['Username'] == username].empty
    
    if not user_exists:
        return False, "Username not found"
    
    # Check if there's an active request
    active_requests = reset_requests_df[
        (reset_requests_df['Username'] == username) & 
        (reset_requests_df['Status'] == 'Active') &
        (reset_requests_df['Expiry Date'] > datetime.now())
    ]
    
    if not active_requests.empty:
        return False, "A reset request is already active for this account"
    
    # Generate new token and request
    token = generate_token()
    expiry = datetime.now() + timedelta(hours=24)
    request_id = str(uuid.uuid4())
    
    new_request = pd.DataFrame([{
        'Request ID': request_id,
        'Username': username,
        'Token': token,
        'Created Date': datetime.now(),
        'Expiry Date': expiry,
        'Status': 'Active'
    }])
    
    reset_requests_df = pd.concat([reset_requests_df, new_request], ignore_index=True)
    reset_requests_df.to_excel(RESET_REQUESTS_FILE, index=False)
    
    # Log activity
    log_activity("System", "Password Reset Request", f"Reset request created for {username}")
    
    return True, request_id

# Validate reset token
def validate_reset_token(token):
    _, _, _, _, reset_requests_df = load_data()
    
    token_row = reset_requests_df[
        (reset_requests_df['Token'] == token) & 
        (reset_requests_df['Status'] == 'Active') &
        (reset_requests_df['Expiry Date'] > datetime.now())
    ]
    
    if token_row.empty:
        return False, None
    
    return True, token_row.iloc[0]['Username']

# Reset password with token
def reset_password_with_token(token, new_password):
    users_df, _, _, _, reset_requests_df = load_data()
    
    valid, username = validate_reset_token(token)
    
    if not valid:
        return False, "Invalid or expired token"
    
    # Update password
    hashed_pwd = hash_password(new_password)
    users_df.loc[users_df['Username'] == username, 'Password'] = hashed_pwd
    users_df.loc[users_df['Username'] == username, 'Modified Date'] = datetime.now()
    users_df.to_excel(USER_FILE, index=False)
    
    # Mark request as used
    reset_requests_df.loc[reset_requests_df['Token'] == token, 'Status'] = 'Used'
    reset_requests_df.to_excel(RESET_REQUESTS_FILE, index=False)
    
    # Log activity
    log_activity(username, "Password Reset", "Password was reset using a token")
    
    return True, "Password has been reset successfully"

# User Interface Components

def login_page():
    st.title("Project Management System")
    st.subheader("Login")
    
    tab1, tab2, tab3 = st.tabs(["Login", "Register", "Forgot Password"])
    
    with tab1:
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            login_button = st.button("Login", use_container_width=True)
        
        if login_button and username and password:
            success, role_or_message = authenticate_user(username, password)
            
            if success:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.user_role = role_or_message
                st.session_state.last_activity = datetime.now()
                st.session_state.session_id = str(uuid.uuid4())
                st.success(f"Welcome back, {username}!")
                time.sleep(1)
                st.rerun()
            else:
                if role_or_message:
                    st.error(role_or_message)
                else:
                    st.error("Invalid username or password")
    
    with tab2:
        st.subheader("Create New Account")
        with st.form("registration_form"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            email = st.text_input("Email")
            full_name = st.text_input("Full Name")
            
            register_submit = st.form_submit_button("Register")
            
            if register_submit:
                if not new_username or not new_password or not confirm_password or not email or not full_name:
                    st.error("All fields are required")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                elif not is_valid_username(new_username):
                    st.error("Username must be 3-30 characters long and can only contain letters, numbers, dots, and underscores")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address")
                else:
                    # Check if username already exists
                    users_df, _, _, _, _ = load_data()
                    if new_username in users_df['Username'].values:
                        st.error("Username already exists. Please choose another username.")
                    # Check if email already exists
                    elif email in users_df['Email'].values:
                        st.error("Email address already in use. Please use another email.")
                    else:
                        # Check password strength
                        is_strong, pwd_message = is_strong_password(new_password)
                        if not is_strong:
                            st.error(pwd_message)
                        else:
                            # Create new user with Collaborator role
                            hashed_pwd = hash_password(new_password)
                        # # Create new user with Collaborator role
                        # hashed_pwd = hash_password(new_password)
                        
                        new_user = pd.DataFrame([{
                            'Username': new_username,
                            'Password': hashed_pwd,
                            'Role': 'Collaborator',  # Default role
                            'Email': email,
                            'Name': full_name,
                            'Status': 'Active',  # Default status
                            'Last Login': None,
                            'Created Date': datetime.now(),
                            'Modified Date': datetime.now()
                        }])
                        
                        users_df = pd.concat([users_df, new_user], ignore_index=True)
                        users_df.to_excel(USER_FILE, index=False)
                        
                        log_activity("System", "User Registration", f"New user {new_username} registered")
                        st.success("Registration successful! You can now log in with your credentials.")
    
    with tab3:
        reset_username = st.text_input("Enter your username", key="reset_username")
        request_reset = st.button("Request Password Reset", use_container_width=True)
        
        if request_reset and reset_username:
            success, message = create_password_reset_request(reset_username)
            
            if success:
                st.success("Password reset request has been sent to the administrator")
                st.info("An administrator will review your request and provide further instructions")
            else:
                st.error(message)


def admin_reset_token_page():
    st.title("Password Reset Requests")
    
    _, _, _, _, reset_requests_df = load_data()
    
    # Filter active requests
    active_requests = reset_requests_df[
        (reset_requests_df['Status'] == 'Active') & 
        (reset_requests_df['Expiry Date'] > datetime.now())
    ]
    
    if active_requests.empty:
        st.info("No active password reset requests")
        return
    
    st.subheader("Active Reset Requests")
    
    # Display each request with options
    for _, request in active_requests.iterrows():
        with st.expander(f"Request for: {request['Username']} ({request['Created Date'].strftime('%Y-%m-%d %H:%M')})"):
            st.write(f"Request ID: {request['Request ID']}")
            st.write(f"Created: {request['Created Date'].strftime('%Y-%m-%d %H:%M:%S')}")
            st.write(f"Expires: {request['Expiry Date'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Approve & Send Token", key=f"approve_{request['Request ID']}"):
                    # In a real app, this would send an email
                    reset_link = f"?token={request['Token']}&action=reset_password"
                    st.code(reset_link, language="text")
                    st.success(f"Token for {request['Username']} has been generated.")
                    log_activity(st.session_state.username, "Password Reset Approved", f"Reset request approved for {request['Username']}")
            
            with col2:
                if st.button("Reject Request", key=f"reject_{request['Request ID']}"):
                    # Update status
                    reset_requests_df.loc[reset_requests_df['Request ID'] == request['Request ID'], 'Status'] = 'Rejected'
                    reset_requests_df.to_excel(RESET_REQUESTS_FILE, index=False)
                    
                    log_activity(st.session_state.username, "Password Reset Rejected", f"Reset request rejected for {request['Username']}")
                    st.warning(f"Request for {request['Username']} has been rejected")
                    st.rerun()

def reset_password_page(token):
    st.title("Reset Your Password")
    
    valid, username = validate_reset_token(token)
    
    if not valid:
        st.error("This reset link is invalid or has expired")
        return
    
    st.write(f"Reset password for user: {username}")
    
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Reset Password"):
        if not new_password or not confirm_password:
            st.error("Please fill in all fields")
        elif new_password != confirm_password:
            st.error("Passwords do not match")
        else:
            success, message = reset_password_with_token(token, new_password)
            
            if success:
                st.success(message)
                st.info("You can now log in with your new password")
            else:
                st.error(message)

def user_management():
    users_df, _, _, _, _ = load_data()
    
    st.title("User Management")
    
    tab1, tab2, tab3 = st.tabs(["Users", "Add User", "User Activity"])
    
    with tab1:
        if not users_df.empty:
            # Drop password column for display
            display_df = users_df.drop(columns=['Password'])
            st.dataframe(display_df, use_container_width=True)
            
            st.subheader("Edit User")
            selected_user = st.selectbox("Select User", users_df['Username'])
            
            user_data = users_df[users_df['Username'] == selected_user].iloc[0]
            
            with st.form("edit_user_form"):
                email = st.text_input("Email", value=user_data['Email'])
                name = st.text_input("Full Name", value=user_data['Name'])
                role = st.selectbox("Role", ["Admin", "Manager", "Collaborator"], index=["Admin", "Manager", "Collaborator"].index(user_data['Role']))
                status = st.selectbox("Status", ["Active", "Inactive"], index=["Active", "Inactive"].index(user_data['Status']))
                reset_pwd = st.checkbox("Reset Password")
                new_pwd = st.text_input("New Password", type="password") if reset_pwd else None
                
                submit = st.form_submit_button("Save Changes")
                
                if submit:
                    users_df.loc[users_df['Username'] == selected_user, ['Email', 'Name', 'Role', 'Status', 'Modified Date']] = [
                        email, name, role, status, datetime.now()
                    ]
                    
                    if reset_pwd and new_pwd:
                        users_df.loc[users_df['Username'] == selected_user, 'Password'] = hash_password(new_pwd)
                        log_activity(st.session_state.username, "Password Reset", f"Admin reset password for {selected_user}")
                    
                    users_df.to_excel(USER_FILE, index=False)
                    log_activity(st.session_state.username, "User Update", f"Updated user {selected_user}")
                    st.success(f"User {selected_user} has been updated")
                    st.rerun()
    
    with tab2:
        with st.form("add_user_form"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            new_email = st.text_input("Email")
            new_name = st.text_input("Full Name")
            new_role = st.selectbox("Role", ["Admin", "Manager", "Collaborator"])
            
            submit_new = st.form_submit_button("Add User")
            


            if submit_new:
                if not new_username or not new_password:
                    st.error("Username and password are required")
                elif not is_valid_username(new_username):
                    st.error("Username must be 3-30 characters long and can only contain letters, numbers, dots, and underscores")
                elif not is_valid_email(new_email):
                    st.error("Please enter a valid email address")
                elif new_username in users_df['Username'].values:
                    st.error("Username already exists")
                elif new_email in users_df['Email'].values:
                    st.error("Email address already in use")
                else:
                    # Check password strength
                    is_strong, pwd_message = is_strong_password(new_password)
                    if not is_strong:
                        st.error(pwd_message)
                    else:
                        hashed_pwd = hash_password(new_password)
            
                    
                        new_user = pd.DataFrame([{
                            'Username': new_username,
                            'Password': hashed_pwd,
                            'Role': new_role,
                            'Email': new_email,
                            'Name': new_name,
                            'Status': 'Active',
                            'Last Login': None,
                            'Created Date': datetime.now(),
                            'Modified Date': datetime.now()
                        }])
                        
                        users_df = pd.concat([users_df, new_user], ignore_index=True)
                        users_df.to_excel(USER_FILE, index=False)
                        
                        log_activity(st.session_state.username, "User Creation", f"Created new user {new_username}")
                        st.success(f"User {new_username} has been created")
                        st.rerun()
    
    with tab3:
        activity_log_df = pd.read_excel(ACTIVITY_LOG_FILE)
        
        if not activity_log_df.empty:
            # Filter options
            filter_user = st.selectbox("Filter by User", ["All Users"] + list(activity_log_df['User'].unique()))
            filter_action = st.selectbox("Filter by Action", ["All Actions"] + list(activity_log_df['Action'].unique()))
            
            filtered_log = activity_log_df
            
            if filter_user != "All Users":
                filtered_log = filtered_log[filtered_log['User'] == filter_user]
            
            if filter_action != "All Actions":
                filtered_log = filtered_log[filtered_log['Action'] == filter_action]
            
            # Sort by timestamp descending
            filtered_log = filtered_log.sort_values(by='Timestamp', ascending=False)
            
            st.dataframe(filtered_log, use_container_width=True)
            
            # Export options
            if st.button("Export Log to Excel"):
                output = BytesIO()
                filtered_log.to_excel(output, index=False)
                b64 = base64.b64encode(output.getvalue()).decode()
                href = f'<a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64}" download="activity_log_export.xlsx">Download Excel File</a>'
                st.markdown(href, unsafe_allow_html=True)
        else:
            st.info("No activity logs found")

def user_profile():
    users_df, _, _, _, _ = load_data()
    
    st.title("My Profile")
    
    user_data = users_df[users_df['Username'] == st.session_state.username].iloc[0]
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Username:** {user_data['Username']}")
        st.write(f"**Role:** {user_data['Role']}")
        st.write(f"**Status:** {user_data['Status']}")
    
    with col2:
        st.write(f"**Email:** {user_data['Email']}")
        st.write(f"**Name:** {user_data['Name']}")
        if pd.notna(user_data['Last Login']):
            st.write(f"**Last Login:** {user_data['Last Login'].strftime('%Y-%m-%d %H:%M')}")
    
    st.divider()
    
    with st.form("update_profile_form"):
        st.subheader("Update Profile")
        
        updated_email = st.text_input("Email", value=user_data['Email'])
        updated_name = st.text_input("Full Name", value=user_data['Name'])
        change_pwd = st.checkbox("Change Password")
        
        if change_pwd:
            current_pwd = st.text_input("Current Password", type="password")
            new_pwd = st.text_input("New Password", type="password")
            confirm_pwd = st.text_input("Confirm New Password", type="password")
        
        submit_profile = st.form_submit_button("Update Profile")
        
        if submit_profile:
            updates_made = False
            
            if updated_email != user_data['Email'] or updated_name != user_data['Name']:
                users_df.loc[users_df['Username'] == st.session_state.username, ['Email', 'Name', 'Modified Date']] = [
                    updated_email, updated_name, datetime.now()
                ]
                updates_made = True
                log_activity(st.session_state.username, "Profile Update", "User updated profile information")
            
            if change_pwd:
                if not current_pwd or not new_pwd or not confirm_pwd:
                    st.error("All password fields are required")
                elif new_pwd != confirm_pwd:
                    st.error("New passwords do not match")
                elif not verify_password(user_data['Password'], current_pwd):
                    st.error("Current password is incorrect")
                else:
                    users_df.loc[users_df['Username'] == st.session_state.username, 'Password'] = hash_password(new_pwd)
                    users_df.loc[users_df['Username'] == st.session_state.username, 'Modified Date'] = datetime.now()
                    updates_made = True
                    log_activity(st.session_state.username, "Password Change", "User changed their password")
            
            if updates_made:
                users_df.to_excel(USER_FILE, index=False)
                st.success("Profile updated successfully")
                st.rerun()

def project_management():
    users_df, projects_df, tasks_df, _, _ = load_data()
    
    st.title("Project Management")
    
    tab1, tab2 = st.tabs(["Projects", "Add Project"])
    
    with tab1:
        if not projects_df.empty:
            # Display projects
            st.dataframe(projects_df, use_container_width=True)
            
            # Project editing
            st.subheader("Edit Project")
            selected_project = st.selectbox("Select Project", projects_df['Project Name'])
            
            project_data = projects_df[projects_df['Project Name'] == selected_project].iloc[0]
            
            with st.form("edit_project_form"):
                name = st.text_input("Project Name", value=project_data['Project Name'])
                desc = st.text_area("Description", value=project_data['Description'])
                start_date = st.date_input("Start Date", value=pd.to_datetime(project_data['Start Date']))
                end_date = st.date_input("End Date", value=pd.to_datetime(project_data['End Date']))
                
                # Get all managers
                managers = users_df[users_df['Role'].isin(['Admin', 'Manager'])]['Username'].tolist()
                manager = st.selectbox("Manager", managers, index=managers.index(project_data['Manager']) if project_data['Manager'] in managers else 0)
                
                status = st.selectbox("Status", ["Planning", "In Progress", "On Hold", "Completed"], 
                                     index=["Planning", "In Progress", "On Hold", "Completed"].index(project_data['Status']) 
                                     if project_data['Status'] in ["Planning", "In Progress", "On Hold", "Completed"] else 0)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    submit_edit = st.form_submit_button("Save Changes")
                
                with col2:
                    delete_project = st.form_submit_button("Delete Project", type="secondary")
                
                if submit_edit:
                    projects_df.loc[projects_df['Project Name'] == selected_project, 
                                    ['Project Name', 'Description', 'Start Date', 'End Date', 'Manager', 'Status']] = [
                        name, desc, start_date, end_date, manager, status
                    ]
                    
                    projects_df.to_excel(PROJECT_FILE, index=False)
                    log_activity(st.session_state.username, "Project Update", f"Updated project {selected_project}")
                    st.success(f"Project {name} has been updated")
                    st.rerun()
                
                if delete_project:
                    # Check if project has tasks
                    project_id = project_data['Project ID']
                    project_tasks = tasks_df[tasks_df['Project ID'] == project_id]
                    
                    if not project_tasks.empty:
                        st.error("Cannot delete project with existing tasks. Delete all tasks first.")
                    else:
                        projects_df = projects_df[projects_df['Project Name'] != selected_project]
                        projects_df.to_excel(PROJECT_FILE, index=False)
                        log_activity(st.session_state.username, "Project Deletion", f"Deleted project {selected_project}")
                        st.warning(f"Project {selected_project} has been deleted")
                        st.rerun()
    
    with tab2:
        st.subheader("Add New Project")
        with st.form("add_project_form"):
            name = st.text_input("Project Name")
            desc = st.text_area("Description")
            start_date = st.date_input("Start Date")
            end_date = st.date_input("End Date")
            
            # Get all managers
            managers = users_df[users_df['Role'].isin(['Admin', 'Manager'])]['Username'].tolist()
            manager = st.selectbox("Manager", managers)
            
            status = st.selectbox("Status", ["Planning", "In Progress", "On Hold", "Completed"])
            
            submitted = st.form_submit_button("Add Project")
            
            if submitted:
                if start_date > end_date:
                    st.error("End date cannot be before start date")
                elif not name:
                    st.error("Project name is required")
                else:
                    project_id = f"P{len(projects_df) + 1}"
                    
                    new_project = pd.DataFrame([{
                        'Project ID': project_id,
                        'Project Name': name,
                        'Description': desc,
                        'Start Date': start_date,
                        'End Date': end_date,
                        'Manager': manager,
                        'Status': status,
                        'Created By': st.session_state.username,
                        'Created Date': datetime.now()
                    }])
                    
                    projects_df = pd.concat([projects_df, new_project], ignore_index=True)
                    projects_df.to_excel(PROJECT_FILE, index=False)
                    
                    log_activity(st.session_state.username, "Project Creation", f"Created new project {name}")
                    st.success(f"Project {name} has been added")
                    st.rerun()

def task_dashboard():
    users_df, projects_df, tasks_df, _, _ = load_data()
    
    st.title("Project Task Dashboard")
    
    if projects_df.empty:
        st.warning("No projects available. Please add a project to begin.")
        return
    
    # Project selection
    selected_project = st.selectbox("Select Project", projects_df['Project Name'])
    project_row = projects_df[projects_df['Project Name'] == selected_project]
    
    if project_row.empty:
        st.error("Selected project not found.")
        return
    
    project_id = project_row.iloc[0]['Project ID']
    filtered_tasks = tasks_df[tasks_df['Project ID'] == project_id]
    
    # Project details
    with st.expander("Project Details", expanded=False):
        project_data = project_row.iloc[0]
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.write(f"**Status:** {project_data['Status']}")
            st.write(f"**Manager:** {project_data['Manager']}")
        
        with col2:
            st.write(f"**Start Date:** {project_data['Start Date'].strftime('%Y-%m-%d')}")
            st.write(f"**End Date:** {project_data['End Date'].strftime('%Y-%m-%d')}")
        
        with col3:
            # st.write(project_data["End Date"])
            days_left = (project_data['End Date'].to_pydatetime().date() - datetime.now().date()).days
            st.write(f"**Days Remaining:** {days_left if days_left > 0 else 'Overdue'}")
        
        st.write(f"**Description:** {project_data['Description']}")
    
    # Task overview metrics
    st.subheader("Task Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    todo_count = len(filtered_tasks[filtered_tasks['Status'] == 'To Do'])
    in_progress = len(filtered_tasks[filtered_tasks['Status'] == 'In Progress'])
    review_count = len(filtered_tasks[filtered_tasks['Status'] == 'Review'])
    done_count = len(filtered_tasks[filtered_tasks['Status'] == 'Done'])
    
    col1.metric("To Do", todo_count)
    col2.metric("In Progress", in_progress)
    # col3.metric("Review", review_count)
    # col4.metric("Done", done_count)
    # style_metric_cards(background_color="#f0f2f6", border_left_color="#1f77b")




    col3.metric("Review", review_count)
    col4.metric("Done", done_count)
    style_metric_cards(background_color="#f0f2f6", border_left_color="#1f77b4")
    
    total_tasks = len(filtered_tasks)
    if total_tasks > 0:
        completion_rate = (done_count / total_tasks) * 100
        st.progress(completion_rate / 100)
        st.caption(f"Project Completion: {completion_rate:.1f}%")
    
    # Task filtering and display
    tab1, tab2, tab3 = st.tabs(["All Tasks", "My Tasks", "Add Task"])
    
    with tab1:
        status_filter = st.multiselect("Filter by Status", 
                                      ["To Do", "In Progress", "Review", "Done"], 
                                      default=["To Do", "In Progress", "Review"])
        
        priority_filter = st.multiselect("Filter by Priority", 
                                       ["Low", "Medium", "High"], 
                                       default=["Low", "Medium", "High"])
        
        display_tasks = filtered_tasks
        
        if status_filter:
            display_tasks = display_tasks[display_tasks['Status'].isin(status_filter)]
        
        if priority_filter:
            display_tasks = display_tasks[display_tasks['Priority'].isin(priority_filter)]
        
        if not display_tasks.empty:
            st.dataframe(display_tasks, use_container_width=True)
        else:
            st.info("No tasks match the selected filters")
    
    with tab2:
        my_tasks = filtered_tasks[filtered_tasks['Assignee'] == st.session_state.username]
        
        if not my_tasks.empty:
            for _, task in my_tasks.iterrows():
                with st.expander(f"{task['Title']} ({task['Status']})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Description:** {task['Description']}")
                        st.write(f"**Due Date:** {task['Due Date'].strftime('%Y-%m-%d')}")
                        st.write(f"**Priority:** {task['Priority']}")
                    
                    with col2:
                        new_status = st.selectbox("Status", 
                                              ["To Do", "In Progress", "Review", "Done"], 
                                              index=["To Do", "In Progress", "Review", "Done"].index(task['Status']),
                                              key=f"status_{task['Task ID']}")
                        
                        if new_status != task['Status']:
                            tasks_df.loc[tasks_df['Task ID'] == task['Task ID'], 'Status'] = new_status
                            tasks_df.loc[tasks_df['Task ID'] == task['Task ID'], 'Modified By'] = st.session_state.username
                            tasks_df.loc[tasks_df['Task ID'] == task['Task ID'], 'Modified Date'] = datetime.now()
                            tasks_df.to_excel(TASK_FILE, index=False)
                            
                            log_activity(st.session_state.username, "Task Update", f"Updated status for task {task['Task ID']} to {new_status}")
                            st.success(f"Task status updated to {new_status}")
                            st.rerun()
        else:
            st.info("You don't have any assigned tasks for this project")
    
    with tab3:
        if st.session_state.user_role in ['Admin', 'Manager']:
            st.subheader("Add New Task")
            with st.form("add_task_form"):
                title = st.text_input("Title")
                desc = st.text_area("Description")
                due_date = st.date_input("Due Date")
                
                # Get active users for assignee dropdown
                active_users = users_df[users_df['Status'] == 'Active']['Username'].tolist()
                assignee = st.selectbox("Assignee", active_users)
                
                status = st.selectbox("Status", ["To Do", "In Progress", "Review", "Done"])
                priority = st.selectbox("Priority", ["Low", "Medium", "High"])
                uploaded_file = st.file_uploader("Attach File")
                
                submitted = st.form_submit_button("Add Task")
                
                if submitted:
                    if not title:
                        st.error("Task title is required")
                    else:
                        task_id = f"T{len(tasks_df)+1}"
                        file_path = ''
                        
                        if uploaded_file:
                            os.makedirs("uploads", exist_ok=True)
                            file_path = f"uploads/{task_id}_{uploaded_file.name}"
                            with open(file_path, "wb") as f:
                                f.write(uploaded_file.read())
                        
                        new_task = pd.DataFrame([{
                            'Task ID': task_id,
                            'Project ID': project_id,
                            'Title': title,
                            'Description': desc,
                            'Due Date': due_date,
                            'Assignee': assignee,
                            'Status': status,
                            'Priority': priority,
                            'File': file_path,
                            'Created By': st.session_state.username,
                            'Created Date': datetime.now(),
                            'Modified By': st.session_state.username,
                            'Modified Date': datetime.now(),
                            'Comments': ''
                        }])
                        
                        tasks_df = pd.concat([tasks_df, new_task], ignore_index=True)
                        tasks_df.to_excel(TASK_FILE, index=False)
                        
                        log_activity(st.session_state.username, "Task Creation", f"Created new task {title} for project {selected_project}")
                        st.success(f"Task '{title}' added successfully")
                        st.rerun()
        else:
            st.info("Only Administrators and Managers can add new tasks")
    
    # Task editing
    if st.session_state.user_role in ['Admin', 'Manager']:
        st.subheader("Edit/Delete Task")
        
        if not filtered_tasks.empty:
            selected_task_id = st.selectbox("Select Task to Edit/Delete", filtered_tasks['Task ID'].tolist())
            task_to_edit = tasks_df[tasks_df['Task ID'] == selected_task_id].iloc[0]
            
            with st.form("edit_task_form"):
                new_title = st.text_input("Title", task_to_edit['Title'])
                new_desc = st.text_area("Description", task_to_edit['Description'])
                new_due_date = st.date_input("Due Date", task_to_edit['Due Date'])
                
                # Get active users for assignee dropdown
                active_users = users_df[users_df['Status'] == 'Active']['Username'].tolist()
                new_assignee = st.selectbox("Assignee", active_users, 
                                           index=active_users.index(task_to_edit['Assignee']) if task_to_edit['Assignee'] in active_users else 0)
                
                new_status = st.selectbox("Status", ["To Do", "In Progress", "Review", "Done"], 
                                         index=["To Do", "In Progress", "Review", "Done"].index(task_to_edit['Status']))
                
                new_priority = st.selectbox("Priority", ["Low", "Medium", "High"], 
                                          index=["Low", "Medium", "High"].index(task_to_edit['Priority']))
                
                new_uploaded_file = st.file_uploader("Replace Attached File (optional)")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    edit_submit = st.form_submit_button("Save Changes")
                
                with col2:
                    delete_submit = st.form_submit_button("Delete Task", type="secondary")
                
                if edit_submit:
                    tasks_df.loc[tasks_df['Task ID'] == selected_task_id, 
                                ['Title', 'Description', 'Due Date', 'Assignee', 'Status', 'Priority', 'Modified By', 'Modified Date']] = [
                        new_title, new_desc, new_due_date, new_assignee, new_status, new_priority, 
                        st.session_state.username, datetime.now()
                    ]
                    
                    if new_uploaded_file:
                        os.makedirs("uploads", exist_ok=True)
                        file_path = f"uploads/{selected_task_id}_{new_uploaded_file.name}"
                        with open(file_path, "wb") as f:
                            f.write(new_uploaded_file.read())
                        tasks_df.loc[tasks_df['Task ID'] == selected_task_id, 'File'] = file_path
                    
                    tasks_df.to_excel(TASK_FILE, index=False)
                    log_activity(st.session_state.username, "Task Update", f"Updated task {selected_task_id}")
                    st.success("Task updated successfully")
                    st.rerun()
                
                if delete_submit:
                    # Add confirmation
                    tasks_df = tasks_df[tasks_df['Task ID'] != selected_task_id]
                    tasks_df.to_excel(TASK_FILE, index=False)
                    log_activity(st.session_state.username, "Task Deletion", f"Deleted task {selected_task_id}")
                    st.warning("Task deleted")
                    st.rerun()

def gantt_chart():
    _, projects_df, tasks_df, _, _ = load_data()
    
    st.title("Gantt Chart View")
    
    if projects_df.empty:
        st.warning("No projects available.")
        return
    
    selected_project = st.selectbox("Select Project", projects_df['Project Name'])
    project_row = projects_df[projects_df['Project Name'] == selected_project]
    
    if project_row.empty:
        st.error("Project not found")
        return
    
    project_id = project_row['Project ID'].values[0]
    filtered_tasks = tasks_df[tasks_df['Project ID'] == project_id]
    
    if filtered_tasks.empty:
        st.warning("No tasks for this project.")
        return
    
    # Filter options
    status_filter = st.multiselect("Filter by Status", 
                                  ["To Do", "In Progress", "Review", "Done"], 
                                  default=["To Do", "In Progress", "Review", "Done"])
    
    assignee_filter = st.multiselect("Filter by Assignee", 
                                   list(filtered_tasks['Assignee'].unique()), 
                                   default=list(filtered_tasks['Assignee'].unique()))
    
    # Apply filters
    if status_filter:
        filtered_tasks = filtered_tasks[filtered_tasks['Status'].isin(status_filter)]
    
    if assignee_filter:
        filtered_tasks = filtered_tasks[filtered_tasks['Assignee'].isin(assignee_filter)]
    
    # Create Gantt data
    gantt_data = filtered_tasks.copy()
    
    # For demonstration, set task durations based on priority
    # In a real app, you might have actual start dates
    gantt_data['Start'] = pd.to_datetime(gantt_data['Due Date']) - pd.to_timedelta(
        gantt_data['Priority'].map({'Low': 3, 'Medium': 5, 'High': 7}), unit='d')
    
    gantt_data['Finish'] = pd.to_datetime(gantt_data['Due Date'])
    gantt_data['Resource'] = gantt_data['Assignee']
    
    # Create Gantt chart
    fig = px.timeline(gantt_data, 
                     x_start="Start", 
                     x_end="Finish", 
                     y="Title", 
                     color="Status", 
                     hover_data=["Assignee", "Priority"],
                     title=f"Gantt Chart - {selected_project}")
    
    fig.update_yaxes(autorange="reversed")
    

    # Add today's date line
    today = datetime.now()
    # today_int = int(today)
    # fig.add_shape(type="line", x0=today_int, y0=0, x1=today_int, y1=len(gantt_data)-1,
    #               line=dict(color="red", width=2, dash="dash"))
    # fig.add_annotation(x=today_int, y=len(gantt_data)-1, text="Today", showarrow=True, arrowhead=2, ax=0, ay=-40)
    # fig.update_layout(title_x=0.5)

    # fig.add_vline(x=today, line_width=2, line_dash="dash", line_color="red", annotation_text="Today")
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Project timeline
    project_data = project_row.iloc[0]
    project_start = pd.to_datetime(project_data['Start Date']).to_pydatetime().date()
    project_end = pd.to_datetime(project_data['End Date']).to_pydatetime().date()
    
    st.subheader("Project Timeline")
    project_days = (project_end - project_start).days
    days_passed = (datetime.now().date() - project_start).days
    
    if project_days > 0:
        progress = min(days_passed / project_days, 1.0)
        st.progress(progress)
        st.caption(f"Project Timeline Progress: {progress*100:.1f}%")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Project Duration", f"{project_days} days")
    col2.metric("Days Passed", f"{max(0, days_passed)} days")
    col3.metric("Days Remaining", f"{max(0, project_days - days_passed)} days")

def dashboard():
    users_df, projects_df, tasks_df, activity_log_df, _ = load_data()
    
    st.title("Project Management Dashboard")
    
    # User welcome
    st.write(f"Welcome, **{st.session_state.username}** ({st.session_state.user_role})")
    
    col1, col2, col3 = st.columns(3)
    
    # Overall metrics
    with col1:
        st.metric("Projects", len(projects_df))
    
    with col2:
        st.metric("Total Tasks", len(tasks_df))
    
    with col3:
        active_projects = len(projects_df[projects_df['Status'].isin(['Planning', 'In Progress'])])
        st.metric("Active Projects", active_projects)
    
    # Get user's projects based on role
    user_projects = []
    if st.session_state.user_role == 'Admin':
        user_projects = projects_df
    elif st.session_state.user_role == 'Manager':
        user_projects = projects_df[projects_df['Manager'] == st.session_state.username]
    
    # For collaborators, find projects they have tasks in
    if st.session_state.user_role == 'Collaborator':
        user_tasks = tasks_df[tasks_df['Assignee'] == st.session_state.username]
        user_project_ids = user_tasks['Project ID'].unique()
        user_projects = projects_df[projects_df['Project ID'].isin(user_project_ids)]
    
    # My Projects Section
    st.subheader("My Projects")
    
    if not user_projects.empty:
        for _, project in user_projects.iterrows():
            with st.expander(f"{project['Project Name']} ({project['Status']})"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Description:** {project['Description']}")
                    st.write(f"**Manager:** {project['Manager']}")
                    st.write(f"**Timeline:** {project['Start Date'].strftime('%Y-%m-%d')} to {project['End Date'].strftime('%Y-%m-%d')}")
                
                with col2:
                    project_tasks = tasks_df[tasks_df['Project ID'] == project['Project ID']]
                    
                    total_tasks = len(project_tasks)
                    completed_tasks = len(project_tasks[project_tasks['Status'] == 'Done'])
                    
                    if total_tasks > 0:
                        progress = completed_tasks / total_tasks
                        st.progress(progress)
                        st.caption(f"Completion: {progress*100:.1f}%")
                    
                    st.write(f"**Tasks:** {total_tasks}")
                    st.write(f"**Completed:** {completed_tasks}")
                
                # View project button
                if st.button("View Tasks", key=f"view_{project['Project ID']}"):
                    st.session_state.selected_project = project['Project ID']
                    st.rerun()
    else:
        st.info("You don't have any projects assigned")
    
    # My Tasks Section
    st.subheader("My Tasks")
    
    my_tasks = tasks_df[tasks_df['Assignee'] == st.session_state.username]
    
    if not my_tasks.empty:
        # Group by status
        task_status = st.radio("View Tasks", ["To Do", "In Progress", "Review", "Done", "All"], horizontal=True)
        
        filtered_tasks = my_tasks if task_status == "All" else my_tasks[my_tasks['Status'] == task_status]
        
        if not filtered_tasks.empty:
            for _, task in filtered_tasks.iterrows():
                project_name = projects_df[projects_df['Project ID'] == task['Project ID']].iloc[0]['Project Name']
                
                with st.expander(f"{task['Title']} ({project_name})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Description:** {task['Description']}")
                        st.write(f"**Due Date:** {task['Due Date'].strftime('%Y-%m-%d')}")
                        
                        # Calculate days remaining or overdue
                        days_remaining = (task['Due Date'] - datetime.now().date()).days
                        if days_remaining >= 0:
                            st.write(f"**Days Remaining:** {days_remaining}")
                        else:
                            st.error(f"**Overdue by {abs(days_remaining)} days**")
                    
                    with col2:
                        st.write(f"**Priority:** {task['Priority']}")
                        st.write(f"**Status:** {task['Status']}")
                        
                        # Quick status update
                        new_status = st.selectbox("Update Status", 
                                               ["To Do", "In Progress", "Review", "Done"], 
                                               index=["To Do", "In Progress", "Review", "Done"].index(task['Status']),
                                               key=f"update_{task['Task ID']}")
                        
                        if st.button("Update", key=f"update_btn_{task['Task ID']}"):
                            tasks_df.loc[tasks_df['Task ID'] == task['Task ID'], 'Status'] = new_status
                            tasks_df.loc[tasks_df['Task ID'] == task['Task ID'], 'Modified By'] = st.session_state.username
                            tasks_df.loc[tasks_df['Task ID'] == task['Task ID'], 'Modified Date'] = datetime.now()
                            tasks_df.to_excel(TASK_FILE, index=False)
                            
                            log_activity(st.session_state.username, "Task Update", f"Updated status for task {task['Task ID']} to {new_status}")
                            st.success("Status updated")
                            st.rerun()
        else:
            st.info(f"You don't have any {task_status} tasks")
    else:
        st.info("You don't have any assigned tasks")
    
    # Recent Activity (for Admin)
    if st.session_state.user_role == 'Admin':
        st.subheader("Recent Activity")
        
        recent_logs = activity_log_df.sort_values(by='Timestamp', ascending=False).head(10)
        
        if not recent_logs.empty:
            for _, log in recent_logs.iterrows():
                st.write(f"**{log['User']}** {log['Action']} - {log['Timestamp'].strftime('%Y-%m-%d %H:%M')}")
                if log['Details']:
                    st.caption(log['Details'])

# Main App
def main():
    # Initialize data files
    initialize_data_files()
    
    # Set page config
    st.set_page_config(
        page_title="Project Management System",
        page_icon="📋",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Parse URL parameters for password reset
    # query_params = st.query_params()
    token = st.query_params.get("token", [None])[0]
    action = st.query_params.get("action", [None])[0]
    
    # Check if we're handling a password reset
    if token and action == "reset_password":
        reset_password_page(token)
        return
    
    # Check session timeout if logged in
    if st.session_state.logged_in:
        check_session_timeout()
    
    # Login or main app
    if not st.session_state.logged_in:
        login_page()
    else:
        # Sidebar menu
        st.sidebar.title("Navigation")
        
        # Different menu options based on role
        if st.session_state.user_role == 'Admin':
            menu = st.sidebar.radio("Menu", [
                "Dashboard", 
                "Project Management", 
                "Task Dashboard", 
                "Gantt Chart", 
                "User Management",
                "Password Reset Requests",
                "My Profile", 
                "Logout"
            ])
        elif st.session_state.user_role == 'Manager':
            menu = st.sidebar.radio("Menu", [
                "Dashboard", 
                "Project Management", 
                "Task Dashboard", 
                "Gantt Chart", 
                "My Profile", 
                "Logout"
            ])
        else:  # Collaborator
            menu = st.sidebar.radio("Menu", [
                "Dashboard", 
                "Task Dashboard", 
                "Gantt Chart", 
                "My Profile", 
                "Logout"
            ])
        
        # Display selected page
        if menu == "Dashboard":
            dashboard()
        elif menu == "Project Management" and st.session_state.user_role in ['Admin', 'Manager']:
            project_management()
        elif menu == "Task Dashboard":
            task_dashboard()
        elif menu == "Gantt Chart":
            gantt_chart()
        elif menu == "User Management" and st.session_state.user_role == 'Admin':
            user_management()
        elif menu == "Password Reset Requests" and st.session_state.user_role == 'Admin':
            admin_reset_token_page()
        elif menu == "My Profile":
            user_profile()
        elif menu == "Logout":
            log_activity(st.session_state.username, "Logout", "User logged out")
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.user_role = None
            st.session_state.session_id = None
            st.rerun()
        
        # Display session info in footer
        with st.sidebar.expander("Session Info", expanded=False):
            st.write(f"**User:** {st.session_state.username}")
            st.write(f"**Role:** {st.session_state.user_role}")
            st.write(f"**Last Activity:** {st.session_state.last_activity.strftime('%H:%M:%S')}")
            
            session_progress = (datetime.now() - st.session_state.last_activity).total_seconds() / (SESSION_TIMEOUT * 60)
            st.progress(min(session_progress, 1.0))
            
            time_left = SESSION_TIMEOUT - int((datetime.now() - st.session_state.last_activity).total_seconds() / 60)
            st.caption(f"Session expires in: {time_left} minutes")

if __name__ == "__main__":
    main()