import streamlit as st
import pandas as pd
import os
from datetime import datetime
from io import BytesIO
from streamlit_extras.metric_cards import style_metric_cards
import plotly.express as px

# Initialize session state for authentication
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_role = None
    st.session_state.username = None

# Dummy user database
users = {
    'admin': {'password': 'admin123', 'role': 'Admin'},
    'manager1': {'password': 'manager123', 'role': 'Manager'},
    'collab1': {'password': 'collab123', 'role': 'Collaborator'}
}

# Load or create data
project_file = 'projects.xlsx'
task_file = 'tasks.xlsx'

if not os.path.exists(project_file):
    pd.DataFrame(columns=['Project ID', 'Project Name', 'Description', 'Start Date', 'End Date', 'Manager']).to_excel(project_file, index=False)

if not os.path.exists(task_file):
    pd.DataFrame(columns=['Task ID', 'Project ID', 'Title', 'Description', 'Due Date', 'Assignee', 'Status', 'Priority', 'File']).to_excel(task_file, index=False)

# Load data
projects_df = pd.read_excel(project_file)
tasks_df = pd.read_excel(task_file)

# Login system
def login():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = users.get(username)
        if user and user['password'] == password:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.user_role = user['role']
            st.success(f"Logged in as {username} ({user['role']})")
            st.rerun()
        else:
            st.error("Invalid credentials")

# Project management
def project_management():
    global projects_df
    st.title("Project Management")

    st.subheader("Existing Projects")
    st.dataframe(projects_df)

    st.subheader("Add New Project")
    with st.form("add_project_form"):
        name = st.text_input("Project Name")
        desc = st.text_area("Description")
        start_date = st.date_input("Start Date")
        end_date = st.date_input("End Date")
        manager = st.text_input("Manager")
        submitted = st.form_submit_button("Add Project")

        if submitted:
            project_id = f"P{len(projects_df)+1}"
            new_project = pd.DataFrame([{
                'Project ID': project_id,
                'Project Name': name,
                'Description': desc,
                'Start Date': start_date,
                'End Date': end_date,
                'Manager': manager
            }])
            projects_df = pd.concat([projects_df, new_project], ignore_index=True)
            projects_df.to_excel(project_file, index=False)
            st.success("Project added successfully")

            
            
            st.rerun()
            # Go to Dashboard
            


# Gantt chart

def gantt_chart():
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

    gantt_data = filtered_tasks.copy()
    gantt_data['Start'] = pd.to_datetime(gantt_data['Due Date']) - pd.to_timedelta(7, unit='d')
    gantt_data['Finish'] = pd.to_datetime(gantt_data['Due Date'])
    gantt_data['Resource'] = gantt_data['Assignee']

    fig = px.timeline(gantt_data, x_start="Start", x_end="Finish", y="Title", color="Status", title="Gantt Chart")
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True)

# Task dashboard
def task_dashboard():
    global tasks_df
    st.title("Project Task Dashboard")
    user_role = st.session_state.user_role

    if projects_df.empty:
        st.warning("No projects available. Please add a project to begin.")
        return

    selected_project = st.selectbox("Select Project", projects_df['Project Name'])
    project_row = projects_df[projects_df['Project Name'] == selected_project]

    if project_row.empty:
        st.error("Selected project not found.")
        return

    project_id = project_row['Project ID'].values[0]
    filtered_tasks = tasks_df[tasks_df['Project ID'] == project_id]

    st.subheader("Task Overview")
    col1, col2, col3 = st.columns(3)
    col1.metric("To Do", len(filtered_tasks[filtered_tasks['Status'] == 'To Do']))
    col2.metric("In Progress", len(filtered_tasks[filtered_tasks['Status'] == 'In Progress']))
    col3.metric("Done", len(filtered_tasks[filtered_tasks['Status'] == 'Done']))
    style_metric_cards(background_color="#f0f2f6", border_left_color="#1f77b4")

    st.subheader("Tasks")
    status_filter = st.radio("Filter by status", ["All", "To Do", "In Progress", "Done"])
    if status_filter != "All":
        filtered_tasks = filtered_tasks[filtered_tasks['Status'] == status_filter]

    st.dataframe(filtered_tasks)

    if user_role in ['Manager', 'Admin']:
        st.subheader("Add New Task")
        with st.form("add_task_form"):
            title = st.text_input("Title")
            desc = st.text_area("Description")
            due_date = st.date_input("Due Date")
            assignee = st.text_input("Assignee")
            status = st.selectbox("Status", ["To Do", "In Progress", "Done"])
            priority = st.selectbox("Priority", ["Low", "Medium", "High"])
            uploaded_file = st.file_uploader("Attach File")
            submitted = st.form_submit_button("Add Task")

            if submitted:
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
                    'File': file_path
                }])
                tasks_df = pd.concat([tasks_df, new_task], ignore_index=True)
                tasks_df.to_excel(task_file, index=False)
                st.success("Task added successfully")

        st.subheader("Edit/Delete Task")
        if not filtered_tasks.empty:
            selected_task_id = st.selectbox("Select Task to Edit/Delete", filtered_tasks['Task ID'].tolist())
            task_to_edit = tasks_df[tasks_df['Task ID'] == selected_task_id].iloc[0]

            with st.form("edit_task_form"):
                new_title = st.text_input("Title", task_to_edit['Title'])
                new_desc = st.text_area("Description", task_to_edit['Description'])
                new_due_date = st.date_input("Due Date", task_to_edit['Due Date'])
                new_assignee = st.text_input("Assignee", task_to_edit['Assignee'])
                new_status = st.selectbox("Status", ["To Do", "In Progress", "Done"], index=["To Do", "In Progress", "Done"].index(task_to_edit['Status']))
                new_priority = st.selectbox("Priority", ["Low", "Medium", "High"], index=["Low", "Medium", "High"].index(task_to_edit['Priority']))
                new_uploaded_file = st.file_uploader("Replace Attached File (optional)")
                edit_submit = st.form_submit_button("Save Changes")
                delete_submit = st.form_submit_button("Delete Task")

                if edit_submit:
                    tasks_df.loc[tasks_df['Task ID'] == selected_task_id, ['Title', 'Description', 'Due Date', 'Assignee', 'Status', 'Priority']] = [
                        new_title, new_desc, new_due_date, new_assignee, new_status, new_priority
                    ]
                    if new_uploaded_file:
                        os.makedirs("uploads", exist_ok=True)
                        file_path = f"uploads/{selected_task_id}_{new_uploaded_file.name}"
                        with open(file_path, "wb") as f:
                            f.write(new_uploaded_file.read())
                        tasks_df.loc[tasks_df['Task ID'] == selected_task_id, 'File'] = file_path
                    tasks_df.to_excel(task_file, index=False)
                    st.success("Task updated successfully")

                if delete_submit:
                    tasks_df = tasks_df[tasks_df['Task ID'] != selected_task_id]
                    tasks_df.to_excel(task_file, index=False)
                    st.warning("Task deleted")

# Main app logic
if not st.session_state.logged_in:
    login()
else:
    menu = st.sidebar.radio("Menu", ["Dashboard", "Gantt View", "Projects", "Logout"])

    if menu == "Dashboard":
        task_dashboard()
    elif menu == "Gantt View":
        gantt_chart()
    elif menu == "Projects" and st.session_state.user_role in ['Admin', 'Manager']:
        project_management()
    elif menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.user_role = None
        st.rerun()
