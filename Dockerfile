FROM python:3.5
# File Author / Maintainer
MAINTAINER SoftFIRE

RUN mkdir -p /var/log/softfire && mkdir -p /etc/softfire 
WORKDIR /app

COPY setup.py /app
COPY monitoring-manager /app

RUN pip install .

COPY etc/monitoring-manager.ini /etc/softfire/
COPY etc/openstack-credentials.json /etc/softfire/ 
COPY . /app

EXPOSE 50059

CMD ./monitoring-manager
