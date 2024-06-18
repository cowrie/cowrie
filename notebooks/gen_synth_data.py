#!pip install names

import os
import random
import string
import subprocess
import csv
import sys
import shutil
import datetime
import names

# Function to generate a random alphanumeric string of given length
def generate_random_string(length=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

# Function to generate random patient names
def generate_random_patient_name():
    first_names = [names.get_first_name() for _ in range(20)]
    last_names = [names.get_last_name() for _ in range(20)]
    return f"{random.choice(first_names)}_{random.choice(last_names)}"

# Function to generate random doctor names
def generate_random_doctor_name():
    first_names = [names.get_first_name() for _ in range(20)]
    last_names = [names.get_last_name() for _ in range(20)]
    return f"Dr_{random.choice(first_names)}_{random.choice(last_names)}"

# Function to generate random medication names
def generate_random_medication_name():
    prefixes = ['Acetaminophen', 'Amoxicillin', 'Ibuprofen', 'Aspirin', 'Ciprofloxacin', 'Metformin', 'Lisinopril', 'Omeprazole', 'Simvastatin', 'Gabapentin']
    suffixes = ['Tablet', 'Capsule', 'Injection', 'Syrup', 'Cream', 'Ointment', 'Patch', 'Drops']
    return f"{random.choice(prefixes)}_{random.choice(suffixes)}"

# Function to generate random test names
def generate_random_test_name():
    tests = ['Blood Test', 'Urine Test', 'MRI Scan', 'X-ray', 'CT Scan', 'Ultrasound', 'EKG', 'Colonoscopy', 'Endoscopy', 'Biopsy']
    return f"{random.choice(tests)}"

# Function to generate random administrative document names
def generate_random_admin_document_name():
    documents = ['Patient Privacy Policy', 'Data Security Policy', 'Financial Report', 'Audit Report', 'Budget Summary', 'Policy Manual']
    return f"{random.choice(documents)}"

# Function to generate random backup names
def generate_random_backup_name():
    return f"Backup_{generate_random_string(6)}"

# Function to generate random patient data
def generate_random_patient_data():
    return {
        generate_random_patient_name(): {
            "details": f"{generate_random_string(8)}_details.txt",
            "medical_history": f"{generate_random_string(8)}_medical_history.txt",
            "prescriptions": [
                f"{generate_random_string(8)}_prescription1.txt",
                f"{generate_random_string(8)}_prescription2.txt"
            ]
        }
    }

# Function to generate random doctor data
def generate_random_doctor_data():
    return {
        generate_random_doctor_name(): {
            "schedule": f"{generate_random_string(8)}_schedule.txt",
            "patients_assigned": {
                generate_random_patient_name(): f"{generate_random_string(8)}_patient.txt"
            },
            "notes": f"{generate_random_string(8)}_notes.txt"
        }
    }

# Function to generate random pharmacy data
def generate_random_pharmacy_data():
    return {
        "prescriptions": {
            generate_random_patient_name(): {
                f"{generate_random_string(8)}_prescription": f"{generate_random_string(8)}_prescription.txt"
            }
        },
        "inventory": {
            generate_random_medication_name(): {
                "stock": f"{generate_random_string(8)}_stock.txt",
                "expiration_dates": f"{generate_random_string(8)}_expiration.txt"
            }
        }
    }

# Function to generate random lab data
def generate_random_lab_data():
    return {
        "test_results": {
            generate_random_patient_name(): {
                generate_random_test_name(): f"{generate_random_string(8)}_test.txt"
            }
        },
        "equipment": {
            f"{generate_random_string(8)}_equipment": {
                "status": f"{generate_random_string(8)}_status.txt",
                "maintenance_log": f"{generate_random_string(8)}_maintenance.txt"
            }
        }
    }

# Function to generate random administrative data
def generate_random_admin_data():
    return {
        "staff_records": {
            "nurses": [
                f"{generate_random_string(8)}_nurse.txt"
            ],
            "doctors": [
                f"{generate_random_string(8)}_doctor.txt"
            ]
        },
        "policies": {
            generate_random_admin_document_name(): f"{generate_random_string(8)}_policy.txt"
        },
        "financial_reports": {
            str(random.choice(range(2015, 2025))): {
                str(random.choice(range(1, 13))): f"{generate_random_string(8)}_{random.choice(['report', 'summary', 'audit'])}.txt"
            }
        }
    }

# Function to generate random backup data
def generate_random_backups():
    return {
        str(random.choice(range(2015, 2025))): {
            str(random.choice(range(1, 13))): generate_random_backup_name()
        }
    }

# Function to create a random hospital file system structure
def create_random_hospital_file_system(root_dir, max_depth=3, current_depth=1):
    if current_depth > max_depth:
        return
    
    num_departments = random.randint(2, 5)  # Random number of departments at this level
    
    for _ in range(num_departments):
        departments = ['radiology', 'optician', 'mri', 'skin', 'general']
        #department_name = generate_random_string(random.randint(5, 10))
        department_name = random.choice(departments) + "_" + str(random.randint(1, 100))
        department_path = os.path.join(root_dir, department_name)
        
        os.makedirs(department_path, exist_ok=True)
        
        # Randomly choose which types of data to populate within this department
        data_types = ['patients', 'doctors', 'pharmacy', 'lab', 'administration', 'backups']
        random.shuffle(data_types)
        
        for data_type in data_types[:random.randint(1, len(data_types))]:
            if data_type == 'patients':
                create_file_system(os.path.join(department_path, 'patients'), generate_random_patient_data())
            elif data_type == 'doctors':
                create_file_system(os.path.join(department_path, 'doctors'), generate_random_doctor_data())
            elif data_type == 'pharmacy':
                create_file_system(os.path.join(department_path, 'pharmacy'), generate_random_pharmacy_data())
            elif data_type == 'lab':
                create_file_system(os.path.join(department_path, 'lab'), generate_random_lab_data())
            elif data_type == 'administration':
                create_file_system(os.path.join(department_path, 'administration'), generate_random_admin_data())
            elif data_type == 'backups':
                create_file_system(os.path.join(department_path, 'backups'), generate_random_backups())
        
        # Recursively create sub-departments
        create_random_hospital_file_system(department_path, max_depth, current_depth + 1)

# Function to create the file system within a given directory
def create_file_system(root_dir, data):
    for key, value in data.items():
        current_path = os.path.join(root_dir, key)
        
        if isinstance(value, dict):
            os.makedirs(current_path, exist_ok=True)
            create_file_system(current_path, value)
        elif isinstance(value, list):
            os.makedirs(current_path, exist_ok=True)
            for item in value:
                if isinstance(item, dict):
                    for sub_key, sub_value in item.items():
                        sub_path = os.path.join(current_path, sub_key)
                        os.makedirs(sub_path, exist_ok=True)
                        create_file_system(sub_path, sub_value)
                else:
                    with open(os.path.join(current_path, item), 'w') as f:
                        txt = "Personal records: Medical Coding for now until we retrain"
                        f.write(txt)


def generate_random_text(max_length=700):
    characters = string.ascii_letters + string.digits + string.punctuation + ' '
    text_length = random.randint(1, max_length)
    random_text = ''.join(random.choice(characters) for _ in range(text_length))
    return random_text
    
# Create random text file
def create_random_text_file(path):
    filename = ''.join(random.choices(string.ascii_lowercase, k=5)) + '.txt'
    filepath = os.path.join(path, filename)
    with open(filepath, 'w') as f:
        #f.write(generate_random_text())
        txt = "Personal records: Medical Coding for now until we retrain"
        f.write(txt)

# Function to create random directory tree
def create_random_directory_tree(root_path, current_level, max_level):
    if current_level > max_level:
        return
    
    num_subdirs = random.randint(0, 3)
    for _ in range(num_subdirs):
        dir_name = ''.join(random.choices(string.ascii_lowercase, k=5))
        dir_path = os.path.join(root_path, dir_name)
        os.makedirs(dir_path, exist_ok=True)
        create_random_directory_tree(dir_path, current_level + 1, max_level)
    
    num_files = random.randint(0, 2)
    for _ in range(num_files):
        create_random_text_file(root_path)

# Function to generate the file system
def generate_file_system(root_path):
    os.makedirs(root_path, exist_ok=True)
    create_random_directory_tree(root_path, 0, 3)

# execute command
def execute_command(command, path):
    try:

        # print the current directory
        process = subprocess.Popen("pwd", cwd=path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        datafile.write("pwd" + "\n")
        
        index = stdout.rfind("/root")
        datafile.write(stdout[index:] + "\n")
        
        # run the command
        process = subprocess.Popen(command, cwd=path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return stdout
        
    except subprocess.CalledProcessError as e:
        return f'Error: {e.stderr}'

# traverse file system

ls_versions = [
    'ls',
    'ls -l',
    'ls -al',
    'ls -h',
    'ls -S',
    'ls -t',
    'ls -r',
    'ls -R',
    'ls -i',
    'ls -d'
]

def traverse_filesystem(starting_directory):

    command = f'cd {starting_directory}'
    stdout = execute_command(command, starting_directory)
    datafile.write(command + "\n")
    datafile.write(stdout + "\n")
    
    # Run commands for listing directories and files in the starting directory
    command = 'ls -l'
    command = f'{command}'
    stdout = execute_command(command, starting_directory)
    datafile.write(command + "\n")
    datafile.write(stdout + "\n")
    
    # Traverse through subdirectories
    for root, dirs, files in os.walk(starting_directory):

        for dir in dirs:
            subdirectory_path = os.path.join(root, dir)

            # print the tree
            command = f'cd {starting_directory}'
            stdout = execute_command("tree | tr -d '[:space:]' | sed '/^$/d'", starting_directory)
            datafile.write(command + "\n")
            datafile.write(stdout + "\n")

            #run the command
            command = random.choice(ls_versions)
            command = f'{command}'
            stdout = execute_command(command, subdirectory_path)
            datafile.write(command + "\n")
            datafile.write(stdout + "\n")

            # List files in the current subdirectory
            file_list = os.listdir(subdirectory_path)

            # Print the list of files (or process it as needed)
            for file in file_list:
                
                if os.path.isfile(subdirectory_path + "/" + file):
                    command = 'cat {0}'.format(file)
                    stdout = execute_command(command, subdirectory_path)
                    datafile.write(command + "\n")
                    datafile.write(stdout + "\n")

                # Do an echo
                command = 'echo $USER $HOME $SHELL'
                stdout = execute_command(command, subdirectory_path)
                datafile.write(command + "\n")
                datafile.write(stdout + "\n")

                # Do an printenv
                #command = 'printenv'
                #stdout = execute_command(command, subdirectory_path)
                #datafile.write(command + "\n")
                #datafile.write(stdout + "\n")
            
# main
if __name__ == "__main__":

    # Every thing must run under a root directory. 
    # Create it if does not exist
    # must create manually for simplicity and run this under root
    
    # number of iterations
    iterations = 10000

    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"data_{current_datetime}.txt"
    global datafile
    datafile = open(filename, 'w')

    user_dir = names.get_last_name()
    
    for i in range(iterations):

        # remove existing user directory system
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)

        user_dir = names.get_first_name() + "_" + names.get_last_name()

        # Generate the file system    
        #generate_file_system(root_dir)
        create_random_hospital_file_system(user_dir, max_depth=1, current_depth=1)
        
        # traverse the file system 
        traverse_filesystem(user_dir)

    datafile.close()

    # Clean Up

    # remove existing user directory system
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)