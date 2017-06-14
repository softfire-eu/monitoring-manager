#!/usr/bin/env bash

for arg in "$@"; do
    if [ "--debug" == "$arg" ]; then
        set -x
        set -e
    fi
done

BASE_URL="https://github.com/softfire-eu/"
MANAGERS="experiment-manager"
VENV_NAME="$HOME/.softfire"
SESSION_NAME="softfire"
CODE_LOCATION="/opt/softfire"
CONFIG_LOCATION="/etc/softfire"
CONFIG_FILE_LINKS="https://raw.githubusercontent.com/softfire-eu/experiment-manager/master/etc/experiment-manager.ini \
https://raw.githubusercontent.com/softfire-eu/monitoring-manager/master/etc/monitoring-manager.ini"
CONFIG_FILE_USERS_LINKS="https://raw.githubusercontent.com/softfire-eu/experiment-manager/master/etc/experiment-manager.ini \
https://raw.githubusercontent.com/softfire-eu/monitoring-manager/master/etc/monitoring-manager.ini"

function install_requirements {
    sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password password root'
    sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password root'
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --force-yes virtualenv git tmux mysql-server python3-pip build-essential libmysqlclient-dev libssl-dev libffi-dev python-dev
}

function install_manager() {
    manager_name=$1
    if [ "$2" == "--upgrade" ]; then
        pip install --upgrade ${manager_name}
    else
        pip install ${manager_name}
    fi
}

function enable_virtualenv {
  echo "Creating virtualenv"
  if [ ! -d ${VENV_NAME} ]; then
    virtualenv --python=python3 ${VENV_NAME}
   fi
   echo "created virtual env"
  . "$VENV_NAME/bin/activate"
}

function usage {
    echo "$0 <action>"
    echo ""
    echo "actions:    [install|update|clean|start|codestart|codeupdate|codeinstall|clean|purge]"
    exit 1

}

function create_folders {
for dir in ${CONFIG_LOCATION} "/var/log/softfire" "${CONFIG_LOCATION}/users" "${CONFIG_LOCATION}/monitoring-manager"; do
    if [ ! -d ${dir} ]; then
        sudo mkdir -p ${dir}
        sudo chown ${USER} ${dir}
    fi
done
}

function download_gui {

    if [ ! -d "${CONFIG_LOCATION}/views" ]; then
        pushd /etc/softfire
        git clone https://github.com/softfire-eu/views.git
    else
        pushd /etc/softfire/views
        git pull
    fi
    popd
}

function copy_config_files {
    pushd ${CONFIG_LOCATION}

    for url in ${CONFIG_FILE_LINKS}; do
        file_name=${url##*/}
        echo "Checking $file_name"
        if [ ! -f ${file_name} ]; then
            wget ${url}
        fi
    done

    popd
    
}



function main {

    if [ "0" == "$#" ]; then
        usage
    fi
    if [ "1" == "$#" -a "--debug" == "$1" ]; then
        usage
    fi

    for var in "$@";
    do
        case ${var} in
        "setup")

            install_requirements
            create_folders
            copy_config_files
            download_gui
            pip3 install bottle-cork
            python3 generate_std_users.py ${CONFIG_LOCATION}/users/
        ;;

        "codeinstall")
            rm -Rf ${CODE_LOCATION}
            sudo mkdir ${CODE_LOCATION}
            sudo chown -R ${USER} ${CODE_LOCATION}
            
            pushd /opt/softfire
            git clone -b develop https://github.com/softfire-eu/experiment-manager.git

            
            
        ;;

         
        esac

    done

}


main $@
