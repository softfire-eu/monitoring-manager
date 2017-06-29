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
CONFIG_FILE_LINKS="https://raw.githubusercontent.com/softfire-eu/experiment-manager/master/etc/experiment-manager.ini https://raw.githubusercontent.com/softfire-eu/experiment-manager/develop/etc/mapping-managers.json"

function install_requirements {

	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --force-yes virtualenv git tmux python3-pip build-essential libmysqlclient-dev libssl-dev libffi-dev python3-dev openvpn

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
    echo "actions:    [setup]"
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
            ln -s /root/git/monitoring-manager/etc/monitoring-manager.ini /etc/softfire/monitoring-manager.ini
            download_gui
            python3 ~/git/monitoring-manager/misc/generate_std_users.py ${CONFIG_LOCATION}/users/
        ;;



         
        esac

    done

}


main $@
