import os
import hashlib
import csv


###############################################################################
# Comp 530 - Data Privacy and Security
# Homework 4
# Sitare Arslantürk
###############################################################################

###############################################################################
# Create a dictionary attack using RockYou.txt
###############################################################################

def create_attack_dictionary(pwd_file: str):
    attack_dict = {}
    with open(pwd_file) as f:
        for row in f:
            pwd = row.rstrip()
            pwd_encoded = pwd.encode()
            hashed_pwd = hashlib.sha512(pwd_encoded).hexdigest()
            attack_dict[str(pwd)] = str(hashed_pwd)
    return attack_dict


###############################################################################
# Generate attack_dict.csv that contains the dictionary attack table
###############################################################################

def write_dictionary_attack(attack_dict, path):
    file_name = os.path.join(path, "attack_dict.csv")
    with open(file_name, 'w') as csv_file:
        writer = csv.writer(csv_file, quoting=csv.QUOTE_ALL)
        for key, value in attack_dict.items():
            writer.writerow([str(key), str(value)])


###############################################################################
# Read the stolen data from digitalcorp.txt
###############################################################################

def read_stolen_file(path):
    stolen_dict = {}
    file_name = os.path.join(path, "digitalcorp.txt")
    with open(file_name, "r") as stolen_file:
        next(stolen_file)
        for line in stolen_file:
            row = line.split(",")
            stolen_dict[row[0]] = row[1].rstrip("\n")
    return stolen_dict


###############################################################################
#  Infer the passwords using the attack_dict and stolen_dict by
#  Comparing the hashed passwords of Alice, Bob, Charlie, Henry from stolen_dict
#  To the hashed passwords from the rockyou.txt which is the attack_dict
#  Return the real passwords for each user pwd_dict
###############################################################################

def infer_password(path):
    file_name = os.path.join(path, "rockyou.txt")
    attack_dict = create_attack_dictionary(file_name)
    stolen_dict = read_stolen_file(path)
    pwd_dict = {}
    for stolen_key, stolen_value in stolen_dict.items():
        for attack_key, attack_value in attack_dict.items():
            if attack_value.strip() == stolen_value.strip():
                pwd_dict[stolen_key] = attack_key
                # print("{}'s pwd: {}".format(stolen_key, attack_key))
    print(pwd_dict)
    write_dictionary_attack(attack_dict, path)
    return pwd_dict


###############################################################################
# Read the stolen data with salts from digitalcorp.txt
###############################################################################

def read_stolen_file_salty(path):
    stolen_dict = {}
    file_name = os.path.join(path, "salty-digitalcorp.txt")
    with open(file_name, "r") as stolen_file:
        next(stolen_file)
        for line in stolen_file:
            row = line.split(",")
            stolen_dict[row[0]] = (row[1], row[2].rstrip("\n"))
    return stolen_dict


###############################################################################
# Read rockyou.txt file that contains passwords into a list
###############################################################################

def read_rockyou(path):
    file_name = os.path.join(path, "rockyou.txt")
    attack_lst = []
    with open(file_name) as f:
        for row in f:
            pwd = row.rstrip()
            attack_lst.append(pwd)
    return attack_lst


###############################################################################
# Create a dictionary of passwords with salts appended and hashed
###############################################################################

def create_salty_attack_dict(salty_dict, attack_lst):
    salty_attack_dict = {}
    for salty_value in salty_dict.values():
        for pwd in attack_lst:
            salty_pwd = salty_value[0] + pwd
            pwd_encoded = salty_pwd.encode()
            hashed_pwd = hashlib.sha512(pwd_encoded).hexdigest()
            salty_attack_dict[(salty_value[0], pwd)] = hashed_pwd
    return salty_attack_dict


###############################################################################
#  Infer the passwords using the salty_dict and stolen_dict by
#  Comparing the hashed passwords of Alice, Bob, Charlie, Henry from stolen_dict
#  To the hashed passwords from the rockyou.txt which is the salty_dict
#  Return the real passwords for each user pwd_dict
###############################################################################

def infer_salty_pwd(path):
    pwd_dict = {}
    salty_dict = read_stolen_file_salty(path)
    attack_lst = read_rockyou(path)
    salty_attack_dict = create_salty_attack_dict(salty_dict, attack_lst)
    for salty_key, salty_value in salty_dict.items():
        for key, value in salty_attack_dict.items():
            if salty_value[1].split() == value.split():
                pwd_dict[salty_key] = key[1]
                # print("{}'s pwd: {} --> found with salt: {}".format(salty_key, key[1], key[0]))
    print(pwd_dict)
    return pwd_dict


###############################################################################
# Main
# Change the path to the directory where the rockyou.txt,
# digitalcorp.txt and salty-digitalcorp.txt files are in.
###############################################################################

def main():
    path = "/Users/sitarearslanturk/Desktop/HW4/Question1"
    infer_password(path)
    infer_salty_pwd(path)


if __name__ == '__main__':
    main()
