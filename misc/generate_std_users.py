#!/usr/bin/env python3
#
#
# Regenerate files in example_conf
import argparse
import getpass
from datetime import datetime

from cork import Cork

def populate_conf_directory(out_dir):
    cork = Cork(out_dir, initialize=True)

    cork._store.roles['admin'] = 100
    cork._store.roles['portal'] = 70
    cork._store.roles['experimenter'] = 60
    cork._store.save_roles()

    tstamp = str(datetime.utcnow())
    
    username, password, role ='admin','admin','admin'
    user_cork = {
    'role': role,
    'hash': cork._hash(username, password),
    'email_addr': username + '@localhost.local',
    'desc': username + ' test user',
    'creation_date': tstamp
    }
    
    cork._store.users[username] = user_cork 
    
    if 0:
    
        username, password, role ='root','root','experimenter'
        user_cork = {
        'role': role,
        'hash': cork._hash(username, password),
        'email_addr': username + '@localhost.local',
        'desc': username + ' test user',
        'creation_date': tstamp
        }
        
        cork._store.users[username] = user_cork 

        
        username, password, role ='portal','portal','portal'
        user_cork = {
        'role': role,
        'hash': cork._hash(username, password),
        'email_addr': username + '@localhost.local',
        'desc': username + ' test user',
        'creation_date': tstamp
        }
        
        cork._store.users[username] = user_cork

    cork._store.save_users()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create username and password for experimenter manager.')
    parser.add_argument('outdir', help='output dir of the cork files')

    args = parser.parse_args()
    populate_conf_directory(args.outdir)
