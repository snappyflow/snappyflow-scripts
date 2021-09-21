#!/bin/bash
#  * Copyright(c)2021 MapleLabs Inc
#  *
#  * This Shell script deploys snappyflow on-prem saas
#  *

set +x
set -e
echo "-------------------SnappyFlow On-prem-saas Google cloud------------------"
echo "-------------------------------------------------------------------------"

DEFAULT_UNIQUE_NAME_PREFIX=onprem-sfapm
DEFAULT_REGION=us-west2
DEFAULT_ZONE=$DEFAULT_REGION-c
DEFAULT_CLUSTER_INSTANCE_TYPE=e2-standard-4
DEFAULT_CLUSTER_MIN_NODE=4
DEFAULT_CLUSTER_MAX_NODE=6
DEFAULT_ES_TYPE=internal
    
#Account details
DATA=$1
if [ ! $DATA ]
then
    echo "Prompt for user input"
elif [ $DATA == "--quiet" ]
then
    SKIP=True
elif [ $DATA == "--help" ]
then
    HELP=True
else
    while getopts n:r:z:i:m:M:e:q:h: flag 
    do
        case "${flag}" in
            n) UNIQUE_NAME_PREFIX=${OPTARG};;
            r) REGION=${OPTARG};;
            z) ZONE=${OPTARG};;
            i) CLUSTER_INSTANCE_TYPE=${OPTARG};;
            m) CLUSTER_MIN_NODE=${OPTARG};;
            M) CLUSTER_MAX_NODE=${OPTARG};;
            e) ES_TYPE=${OPTARG};;
            *) HELP=True;
        esac
        SKIP=True
    done
fi

if [ $HELP ]
then
    echo "NAME:"
    echo "  gke-onrepm-apm-installer.sh: Script to install on-prem SaaS version of SnappyFlow on GKE cluster"
    echo "SYNOPSIS:"
    echo "  sh gke-onrepm-apm-installer.sh [-r REGION] [-z ZONE] 
            [-i CLUSTER_INSTANCE_TYPE] [-m CLUSTER_MAX_NODE]
            [-e ES_TYPE]"
    echo "FlAGS:"
    echo "  -n : Unique Name Prefix for resources created e.g. cluster name or instance name [Default: $DEFAULT_UNIQUE_NAME_PREFIX]"
    echo "  -r : Region [Default: $DEFAULT_REGION]"
    echo "  -z : Zone [Default: $DEFAULT_ZONE]"
    echo "  -i : Cluster instance type [Default: $DEFAULT_CLUSTER_INSTANCE_TYPE, Options: e2-standard-4, e2-standard-8, e2-standard-16]"
    echo "  -m : GKE cluster minimum node count [Default: $DEFAULT_CLUSTER_MIN_NODE]"
    echo "  -M : GKE cluster maximum node count for auto scaling [Default: $DEFAULT_CLUSTER_MAX_NODE]"
    echo "  -e : Elasticsearch Installation type [Default: $DEFAULT_ES_TYPE, Options: internal, external]"
    echo "  --quiet: Disables all interactive prompts and use default values"
    exit 0
fi

project_id=$(gcloud config list --format="value(core.project)")
if [ ! $project_id ]
then
    echo "ERROR: The required property [project] is not currently set."
    echo "You may set it for your current workspace by running:"
    echo "$ gcloud config set project <VALUE>"
    exit 0
fi
PROJECT_ID=$project_id


if [ ! $UNIQUE_NAME_PREFIX ]
then
    if [ ! "$SKIP" ]; then
        echo
        read -p "Enter Unique Prefix Name[Default: $DEFAULT_UNIQUE_NAME_PREFIX]:- " UNIQUE_NAME_PREFIX
    fi
    if [ ! $UNIQUE_NAME_PREFIX ]
    then
        UNIQUE_NAME_PREFIX=$DEFAULT_UNIQUE_NAME_PREFIX
        echo "Setting Default name prefix:- $UNIQUE_NAME_PREFIX"
    fi
fi

#Region and zone details
if [ ! $REGION ]
then
    if [ ! "$SKIP" ]; then
        echo
        read -p "Enter Region Name[Default value : $DEFAULT_REGION]:- " REGION
    fi
    if [ ! $REGION ]
    then
        REGION=$DEFAULT_REGION
        echo "Setting Default Region:- $REGION"
    fi
fi

if [ ! $ZONE ]
then
    if [ ! "$SKIP" ]; then
        echo
        read -p "Enter Zone Name[Default value : $REGION-c]:- " ZONE
    fi
    if [ ! $ZONE ]
    then
        ZONE=$REGION-c
        echo "Setting Default Zone:- $ZONE"
    fi
fi

LOG_FILE=$UNIQUE_NAME_PREFIX-output.log
exec > >(tee $LOG_FILE) 2>&1
exec 2> >(tee $LOG_FILE) 2>&1

#Network details
NETWORK=$UNIQUE_NAME_PREFIX-network
SUBNET=$UNIQUE_NAME_PREFIX-subnet
SUBNET_CIDR=10.50.0.0/16
NAT_ROUTER=$UNIQUE_NAME_PREFIX-nat-router
NAT=$UNIQUE_NAME_PREFIX-nat

#Bastion Instance and K8S Cluster details
BASTION_INSTANCE=$UNIQUE_NAME_PREFIX-linux-bastion
CLUSTER=$UNIQUE_NAME_PREFIX-k8s
CLUSTER_DISK_SIZE=100
CLUSTER_VERSION=1.20
CLUSTER_NODE_TAG=$UNIQUE_NAME_PREFIX-k8s-nodes
CLUSTER_MASTER_CIDR=172.16.0.64/28

if [ ! $CLUSTER_INSTANCE_TYPE ]
then
    if [ ! "$SKIP" ]; then
        echo
        echo "Select Any Cluster Instance type number below:-"
        echo "[1] e2-standard-4"
        echo "[2] e2-standard-8"
        echo "[3] e2-standard-16"
        read -p "Enter Cluster Instance type number[Default value :[1] e2-standard-4]:- " CLUSTER_INSTANCE_TYPE
    fi
    if [ ! $CLUSTER_INSTANCE_TYPE ]
    then
        CLUSTER_INSTANCE_TYPE=$DEFAULT_CLUSTER_INSTANCE_TYPE
        echo "Setting Default Cluster Instance type:- $CLUSTER_INSTANCE_TYPE"
    elif [ $CLUSTER_INSTANCE_TYPE == 1 ]
    then
        CLUSTER_INSTANCE_TYPE=e2-standard-4
    elif [ $CLUSTER_INSTANCE_TYPE == 2 ]
    then
        CLUSTER_INSTANCE_TYPE=e2-standard-8
    elif [ $CLUSTER_INSTANCE_TYPE == 3 ]
    then
        CLUSTER_INSTANCE_TYPE=e2-standard-16
    else
        echo "Invalid value"
        CLUSTER_INSTANCE_TYPE=$DEFAULT_CLUSTER_INSTANCE_TYPE
        echo "Setting Default Cluster Instance type:- $CLUSTER_INSTANCE_TYPE"
    fi
fi

if [ ! $CLUSTER_MIN_NODE ]
then
    if [ ! "$SKIP" ]; then
        echo
        read -p "Enter Cluster minimum nodes[Default: $DEFAULT_CLUSTER_MIN_NODE]:- " CLUSTER_MIN_NODE
    fi
    if [ ! $CLUSTER_MIN_NODE ]
    then
        CLUSTER_MIN_NODE=$DEFAULT_CLUSTER_MIN_NODE
        echo "Setting Default Cluster minimum nodes:- $CLUSTER_MIN_NODE"
    fi
fi

if [ ! $CLUSTER_MAX_NODE ]
then
    if [ ! "$SKIP" ]; then
        echo
        read -p "Enter Cluster maximum nodes[$DEFAULT_CLUSTER_MAX_NODE]:- " CLUSTER_MAX_NODE
    fi
    if [ ! $CLUSTER_MAX_NODE ]
    then
        CLUSTER_MAX_NODE=$DEFAULT_CLUSTER_MAX_NODE
        echo "Setting Default Cluster maximum nodes:- $CLUSTER_MAX_NODE"
    fi
fi

#External Elasticsearch details
if [ ! $ES_TYPE ]
then
    if [ ! "$SKIP" ]; then
        echo
        echo "Select Any Elasticsearch type number below:-"
        echo "[1] internal"
        echo "[2] external"
        read -p "Enter Elasticsearch type number[Default:[1] internal]:-" ES_TYPE
    fi
    if [ ! $ES_TYPE ]
    then
        ES_TYPE=$DEFAULT_ES_TYPE
        echo "Setting Elasticsearch deployment type:- $ES_TYPE"
    elif [ $ES_TYPE == 1 ]
    then
        ES_TYPE=internal
    elif [ $ES_TYPE == 2 ]
    then
        ES_TYPE=external
    else
        echo "Invalid value"
        ES_TYPE=$DEFAULT_ES_TYPE
        echo "Setting default Elasticsearch deployment type:- $ES_TYPE"
    fi
fi

ES_INSTANCE_1=$UNIQUE_NAME_PREFIX-es-instance-1
ES_INSTANCE_2=$UNIQUE_NAME_PREFIX-es-instance-2
ES_INSTANCE_3=$UNIQUE_NAME_PREFIX-es-instance-3
ES_NODE_TAG=$UNIQUE_NAME_PREFIX-es-nodes
ES_INSTANCE_TYPE=e2-standard-4

#Firewall details
SSH_FIREWALL=$UNIQUE_NAME_PREFIX-ssh-firewall
SFAPM_FIREWALL=$UNIQUE_NAME_PREFIX-allow-sfapm
HEALTHCHECK_FIREWALL=$UNIQUE_NAME_PREFIX-k8-allow-health-check
ES_FIREWALL=$UNIQUE_NAME_PREFIX-es-firewall
K8S_MASTER_FIREWALL=$UNIQUE_NAME_PREFIX-allow-master

#Load Balancer details
LB_IP_NAME=$UNIQUE_NAME_PREFIX-lb-ip
HEALTHCHECK_NAME=$UNIQUE_NAME_PREFIX-k8s-http-hc
LB_BACKEND_SERVICE=$UNIQUE_NAME_PREFIX-backend-service
LB_NAME=$UNIQUE_NAME_PREFIX-sfapm-lb
LB_HTTP_PROXY=$UNIQUE_NAME_PREFIX-http-lb-proxy
LB_HTTP_FORWARDING_RULE=$UNIQUE_NAME_PREFIX-http-content-rule
LB_SSL_CERT_NAME=$UNIQUE_NAME_PREFIX-ssl-selfsigned-cert
LB_HTTPS_PROXY=$UNIQUE_NAME_PREFIX-https-lb-proxy
LB_HTTPS_FORWARDING_RULE=$UNIQUE_NAME_PREFIX-https-content-rule

GCP_HEALTHCHECK_CIDR="130.211.0.0/22,35.191.0.0/16,209.85.152.0/22,209.85.204.0/22"

echo "-------------------------------------------------------------------------"
echo "Values Set"
echo "-------------------------------------------------------------------------"
echo "PROJECT_ID : $PROJECT_ID"
echo "UNIQUE_NAME_PREFIX : $UNIQUE_NAME_PREFIX"
echo "REGION : $REGION"
echo "ZONE : $ZONE"
echo "CLUSTER_INSTANCE_TYPE: $CLUSTER_INSTANCE_TYPE"
echo "CLUSTER_MIN_NODE : $CLUSTER_MIN_NODE"
echo "CLUSTER_MAX_NODE : $CLUSTER_MAX_NODE"
echo "CLUSTER_DISK_SIZE : $CLUSTER_DISK_SIZE"
echo "CLUSTER_VERSION : $CLUSTER_VERSION"
echo "ES_TYPE : $ES_TYPE"

DEFAULT_SERVICE_ACCOUNT=`gcloud iam service-accounts list | grep developer.gserviceaccount.com | head -1 | awk '{print $2}'`
PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID | grep projectNumber | awk '{print $2}' | cut -d"'" -f 2`
SERVICE_ACCOUNT=$PROJECT_NUMBER-compute@developer.gserviceaccount.com
if [ ! $DEFAULT_SERVICE_ACCOUNT ]
then
    echo "ERROR: default service account $SERVICE_ACCOUNT does not exist."
    exit 0
fi

gcloud_init()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "Gcloud Init"
    echo "-------------------------------------------------------------------------"
    echo
    echo "Setting gcloud region to $REGION"
    gcloud config set compute/region $REGION
    echo
    echo "Setting gcloud zone to $ZONE"
    gcloud config set compute/zone $ZONE
    echo
    echo "Enable compute and container api services"
    gcloud services enable compute.googleapis.com
    gcloud services enable container.googleapis.com
}  

create_service_account()
{
    echo "Create new service account for GKE"
    SERVICE_ACCOUNT_NAME=$UNIQUE_NAME_PREFIX-sa
    SERVICE_ACCOUNT=$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com
    gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME 
        --display-name=$SERVICE_ACCOUNT_NAME
        
    echo -e "\nAdd permissions for service account"
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member "serviceAccount:$SERVICE_ACCOUNT" \
        --role roles/container.admin

    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member "serviceAccount:$SERVICE_ACCOUNT" \
        --role roles/compute.admin
        
    gcloud projects add-iam-policy-binding PROJECT_ID \
        --member "serviceAccount:$SERVICE_ACCOUNT" \
        --role roles/logging.logWriter

    gcloud projects add-iam-policy-binding PROJECT_ID \
        --member "serviceAccount:$SERVICE_ACCOUNT" \
        --role roles/monitoring.metricWriter

    gcloud projects add-iam-policy-binding PROJECT_ID \
        --member "serviceAccount:$SERVICE_ACCOUNT" \
        --role roles/monitoring.viewer

    gcloud projects add-iam-policy-binding PROJECT_ID \
        --member "serviceAccount:$SERVICE_ACCOUNT" \
        --role roles/stackdriver.resourceMetadata.writer
}

set_service_account_permission()
{
    gcloud projects add-iam-policy-binding $PROJECT_ID  \
       --member serviceAccount:$SERVICE_ACCOUNT  \
       --role "roles/container.admin"
       
    gcloud projects add-iam-policy-binding $PROJECT_ID  \
       --member serviceAccount:$SERVICE_ACCOUNT  \
       --role "roles/storage.admin"

    echo "Generate key file for service account"
    gcloud iam service-accounts keys create ./$UNIQUE_NAME_PREFIX-sa-key.json --iam-account=$SERVICE_ACCOUNT
}

setup_network()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "Network and NAT Setup"
    echo "-------------------------------------------------------------------------"
    echo -e "\nCreating network $NETWORK"
    gcloud compute networks create $NETWORK --subnet-mode=custom
    echo -e "\nCreating subnet $SUBNET"
    gcloud compute networks subnets create $SUBNET \
        --network=$NETWORK \
        --range=$SUBNET_CIDR
    echo -e "\nCreating NAT Router $NAT_ROUTER"
    gcloud compute routers create $NAT_ROUTER \
        --network $NETWORK \
        --region $REGION
    echo -e "\nCreating NAT $NAT"
    gcloud compute routers nats create $NAT \
        --router-region $REGION \
        --router $NAT_ROUTER \
        --nat-all-subnet-ip-ranges \
        --auto-allocate-nat-external-ips
    echo -e "\nCreating firewall rule to allow SSH in the network"
    gcloud compute firewall-rules create $SSH_FIREWALL \
        --network $NETWORK \
        --allow tcp:22
}

create_bastion_instance()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "Bastion instance setup"
    echo "-------------------------------------------------------------------------"
    echo -e "\nCreating Bastion Linux instance $BASTION_INSTANCE"
    gcloud compute instances create $BASTION_INSTANCE  \
        --subnet=$SUBNET \
        --scopes cloud-platform \
        --machine-type=e2-micro \
        --image=centos-7-v20210817 \
        --image-project=centos-cloud \
        --zone=$ZONE \
        --service-account=$SERVICE_ACCOUNT
}

create_gke_setup()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "GKE Cluster setup"
    echo "-------------------------------------------------------------------------"
    echo -e "\nCreating GKE Cluster $CLUSTER"
    BASTION_INSTANCE_IP=`gcloud compute instances describe $BASTION_INSTANCE  --format="value(networkInterfaces[0].networkIP)"` 
    gcloud container clusters create $CLUSTER  \
        --master-ipv4-cidr=$CLUSTER_MASTER_CIDR \
        --network $NETWORK \
        --subnetwork=$SUBNET \
        --enable-ip-alias \
        --enable-private-nodes \
        --enable-private-endpoint \
        --master-authorized-networks $BASTION_INSTANCE_IP/32 \
        --enable-master-authorized-networks \
        --cluster-version $CLUSTER_VERSION \
        --release-channel "None" \
        --machine-type $CLUSTER_INSTANCE_TYPE \
        --image-type "COS_CONTAINERD" \
        --disk-type "pd-standard" \
        --disk-size $CLUSTER_DISK_SIZE \
        --num-nodes $CLUSTER_MIN_NODE \
        --enable-autoscaling --min-nodes $CLUSTER_MIN_NODE --max-nodes $CLUSTER_MAX_NODE \
        --tags $CLUSTER_NODE_TAG \
        --logging=SYSTEM \
        --monitoring=SYSTEM \
        --addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver \
        --scopes cloud-platform \
        --workload-pool=$PROJECT_ID.svc.id.goog \
        --workload-metadata=GKE_METADATA \
        --zone=$ZONE \
        --service-account=$SERVICE_ACCOUNT

    echo -e "\nAdd member workloadIdentityUser in Service account"
    gcloud iam service-accounts add-iam-policy-binding \
      --role roles/iam.workloadIdentityUser \
      --member "serviceAccount:$PROJECT_ID.svc.id.goog[kafka/archival-service-account]" \
      $SERVICE_ACCOUNT

    gcloud iam service-accounts add-iam-policy-binding \
      --role roles/iam.workloadIdentityUser \
      --member "serviceAccount:$PROJECT_ID.svc.id.goog[apm/apm-sfapm-python3]" \
      $SERVICE_ACCOUNT

    echo -e "\nCreating firewall rules for cluster instances to allow SnappyFlow Ports"
    gcloud compute firewall-rules create $SFAPM_FIREWALL \
        --target-tags=$CLUSTER_NODE_TAG \
        --rules=tcp:80,tcp:443 \
        --action=allow \
        --network=$NETWORK
        
    gcloud compute firewall-rules create $HEALTHCHECK_FIREWALL \
        --target-tags=$CLUSTER_NODE_TAG \
        --rules=tcp:30000-32767,tcp:10256 \
        --action=allow \
        --source-ranges=$GCP_HEALTHCHECK_CIDR \
        --network=$NETWORK
        
    gcloud compute firewall-rules create $K8S_MASTER_FIREWALL \
        --target-tags=$CLUSTER_NODE_TAG \
        --rules=tcp:6443 \
        --action=allow \
        --source-ranges=$CLUSTER_MASTER_CIDR \
        --network=$NETWORK
}

setup_loadbalancer()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "LoadBalancer Setup"
    echo "-------------------------------------------------------------------------"
    echo -e "\nSet named ports in instance group $INSTANCE_GROUP"
    INSTANCE_GROUP=`gcloud compute instance-groups list --filter="network:( $NETWORK )" | grep $CLUSTER | awk '{print $1}'`
    gcloud compute instance-groups set-named-ports $INSTANCE_GROUP \
        --named-ports http:30009,https:30010 \
        --zone $ZONE

    echo -e "\nCreating static IP for LoadBalancer with name $LB_IP_NAME"
    gcloud compute addresses create $LB_IP_NAME \
        --ip-version=IPV4 \
        --global
        
    LB_IP=`gcloud compute addresses describe $LB_IP_NAME --format="get(address)" --global`
    echo -e "\nLoadBalancer IP created is $LB_IP"

    echo -e "\nCreating health-check for GKE Cluster"
    gcloud compute health-checks create http $HEALTHCHECK_NAME \
        --port=10256 \
        --request-path=/healthz \
        --check-interval=8 --timeout=5 \
        --unhealthy-threshold=3 \
        --healthy-threshold=3

    echo -e "\nCreating LoadBalancer backend service $LB_BACKEND_SERVICE"
    gcloud compute backend-services create $LB_BACKEND_SERVICE \
        --protocol=HTTP \
        --port-name=http \
        --health-checks=$HEALTHCHECK_NAME \
        --global
        
    gcloud compute backend-services add-backend $LB_BACKEND_SERVICE \
        --instance-group=$INSTANCE_GROUP \
        --instance-group-zone=$ZONE \
        --global

    echo -e "\nCreating LoadBalancer URL Map $LB_NAME"
    gcloud compute url-maps create $LB_NAME \
        --default-service $LB_BACKEND_SERVICE

    echo -e "\nCreating self signed SSL certificate"
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout sfapm.key \
        -out sfapm.crt \
        -subj "/C=US/ST=CA/L=SF/O=Dis/CN=SnappyFlow"

    echo -e "\nCreating LoadBalancer frontend service"
    gcloud compute ssl-certificates create $LB_SSL_CERT_NAME \
        --certificate=./sfapm.crt \
        --private-key=./sfapm.key \
        --global
        
    gcloud compute target-https-proxies create $LB_HTTPS_PROXY  \
      --url-map=$LB_NAME  \
      --ssl-certificates=$LB_SSL_CERT_NAME

    gcloud compute forwarding-rules create $LB_HTTPS_FORWARDING_RULE \
        --address=$LB_IP \
        --global \
        --target-https-proxy=$LB_HTTPS_PROXY \
        --ports=443
        
}



create_es_instances()
{
    if [ "$ES_TYPE" = "internal" ]
    then
        return
    fi
    echo
    echo "-------------------------------------------------------------------------"
    echo "Create instances for Elasticsearch"
    echo "-------------------------------------------------------------------------"
    echo -e "\nCreating 3 instances for Elasticsearch with names $ES_INSTANCE_1, $ES_INSTANCE_2, $ES_INSTANCE_3"
    gcloud compute instances create $ES_INSTANCE_1 $ES_INSTANCE_2 $ES_INSTANCE_3 \
        --labels=name=snappyflow_es \
        --tags=$ES_NODE_TAG \
        --machine-type=$ES_INSTANCE_TYPE \
        --subnet=$SUBNET \
        --image-family=ubuntu-2004-lts \
        --image-project=ubuntu-os-cloud \
        --boot-disk-size=500GB \
        --scopes default \
        --no-address \
	--zone=$ZONE \
        --service-account=$SERVICE_ACCOUNT
}

setup_external_elasticsearch()
{   
    if [ "$ES_TYPE" = "internal" ]
    then
        return
    fi
    echo
    echo "-------------------------------------------------------------------------"
    echo "Install Elasticsearch"
    echo "-------------------------------------------------------------------------"
    echo -e "\nCreating firewall rule for ES nodes"
    CLUSTER_POD_CIDR=$(gcloud container clusters describe $CLUSTER --zone $ZONE | grep podIpv4CidrBlock | awk '{print $2}')
    gcloud compute firewall-rules create $ES_FIREWALL \
        --target-tags=$ES_NODE_TAG \
        --rules=tcp:80,tcp:443,tcp:9200,tcp:9300,tcp:8585,tcp:9100 \
        --source-ranges=$SUBNET_CIDR,$CLUSTER_POD_CIDR \
        --action=allow \
        --network=$NETWORK
        
    IP1=$(gcloud compute instances describe $ES_INSTANCE_1 --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    IP2=$(gcloud compute instances describe $ES_INSTANCE_2 --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    IP3=$(gcloud compute instances describe $ES_INSTANCE_3 --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    cat > ./$UNIQUE_NAME_PREFIX-es-install.sh << 'EOF'
#!/bin/bash
#sudo yum update -y
sudo yum install -y lsof psmisc sysstat ansible sysstat


curl -u apmuser:apmpass https://d22pmbnqrnrgp5.cloudfront.net/ansible/elasticsearch/ansible-es.tar.gz -o ansible-es.tar.gz
tar -xvf ansible-es.tar.gz


gcloud compute config-ssh --quiet

sleep 30
cat .ssh/google_compute_engine > ansible-es/keys/user-dev-aws-ssh.pem
chmod 600 ansible-es/keys/user-dev-aws-ssh.pem

sed -i "s/master-0 ansible_host=/master-0 ansible_host=$IP1/" ansible-es/hosts
sed -i "s/master-1 ansible_host=/master-1 ansible_host=$IP2/" ansible-es/hosts
sed -i "s/master-2 ansible_host=/master-2 ansible_host=$IP3/" ansible-es/hosts
cd ansible-es
# sed -i "s/ubuntu/$USER/g" install.sh
# sh install.sh
# exit 0
EOF
    chmod +x ./$UNIQUE_NAME_PREFIX-es-install.sh
    gcloud compute scp ./$UNIQUE_NAME_PREFIX-es-install.sh ubuntu@$BASTION_INSTANCE:~/es-configure.sh

    echo -e "\nSSH to bastion instance and run ES Ansible script"
    gcloud compute ssh ubuntu@$BASTION_INSTANCE \
        --command "IP1=$IP1 IP2=$IP2 IP3=$IP3 ./es-configure.sh"
        
    gcloud compute ssh ubuntu@$BASTION_INSTANCE \
        --command "cd ansible-es; sh install.sh"
}



# Presto nodes
PRESTO_COORDINATOR=$UNIQUE_NAME_PREFIX-presto-coordinator
PRESTO_WORKER_1=$UNIQUE_NAME_PREFIX-presto-worker-1
PRESTO_WORKER_2=$UNIQUE_NAME_PREFIX-presto-worker-2
PRESTO_COORDINATOR_INSTANCE_TYPE=e2-standard-4
PRESTO_WORKER_INSTANCE_TYPE=e2-standard-4
PRESTO_NODE_TAG=$UNIQUE_NAME_PREFIX-presto-nodes
PRESTO_FIREWALL=$UNIQUE_NAME_PREFIX-presto-firewall
PRESTO_CLUSTER_FIREWALL=$UNIQUE_NAME_PREFIX-presto-k8-firewall

create_presto_instances()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "Create Presto Instances"
    echo "-------------------------------------------------------------------------"

    echo -e "\nCreating Presto coordinator node "
    gcloud compute instances create $PRESTO_COORDINATOR \
        --labels=name=presto-coordinator \
        --tags=$PRESTO_NODE_TAG \
        --machine-type=$PRESTO_COORDINATOR_INSTANCE_TYPE \
        --subnet=$SUBNET \
        --image-family=ubuntu-1804-lts \
        --image-project=ubuntu-os-cloud \
        --boot-disk-size=40GB \
        --scopes default \
        --no-address \
	--zone=$ZONE \
        --service-account=$SERVICE_ACCOUNT
        

    echo -e "\nCreating Presto worker nodes "
    gcloud compute instances create $PRESTO_WORKER_1 $PRESTO_WORKER_2 \
        --labels=name=presto-worker \
        --tags=$PRESTO_NODE_TAG \
        --machine-type=$PRESTO_WORKER_INSTANCE_TYPE \
        --subnet=$SUBNET \
        --image-family=ubuntu-1804-lts \
        --image-project=ubuntu-os-cloud \
        --boot-disk-size=40GB \
        --scopes default \
        --no-address \
	--zone=$ZONE \
        --service-account=$SERVICE_ACCOUNT
}

setup_presto()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "Setup Presto Instances"
    echo "-------------------------------------------------------------------------"

    echo -e "\nCreating firewall rule for presto nodes"
    CLUSTER_POD_CIDR=$(gcloud container clusters describe $CLUSTER --zone $ZONE | grep podIpv4CidrBlock | awk '{print $2}')
    gcloud compute firewall-rules create $PRESTO_FIREWALL \
        --target-tags=$PRESTO_NODE_TAG \
        --rules=tcp:8080,tcp:8081 \
        --source-ranges=$SUBNET_CIDR,$CLUSTER_POD_CIDR \
        --action=allow \
        --network=$NETWORK
        
    echo -e "\nCreating firewall rule from presto to cluster"
    gcloud compute firewall-rules create $PRESTO_CLUSTER_FIREWALL \
        --target-tags=$CLUSTER_NODE_TAG \
        --rules=tcp:32500 \
        --source-tags=$PRESTO_NODE_TAG \
        --action=allow \
        --network=$NETWORK

    echo "Copy service account key file to presto instances"
    gcloud compute scp ./$UNIQUE_NAME_PREFIX-sa-key.json ubuntu@$PRESTO_COORDINATOR:~/gcs_access.json
    gcloud compute scp ./$UNIQUE_NAME_PREFIX-sa-key.json ubuntu@$PRESTO_WORKER_1:~/gcs_access.json
    gcloud compute scp ./$UNIQUE_NAME_PREFIX-sa-key.json ubuntu@$PRESTO_WORKER_2:~/gcs_access.json

    PRESTO_COORDINATOR_IP=$(gcloud compute instances describe $PRESTO_COORDINATOR --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)

    wget https://presto-hive.s3.us-west-2.amazonaws.com/GcpPrestoCoordinatorInit.sh -O ./GcpPrestoCoordinatorInit.sh

    chmod +x ./GcpPrestoCoordinatorInit.sh

    wget https://presto-hive.s3.us-west-2.amazonaws.com/GcpPrestoWorkerInit.sh -O ./GcpPrestoWorkerInit.sh 
    chmod +x ./GcpPrestoWorkerInit.sh 
    
    sed -i "s/PRESTO_COORD_IP/${PRESTO_COORDINATOR_IP}/g" ./GcpPrestoWorkerInit.sh
    cp ./GcpPrestoWorkerInit.sh ./GcpPrestoWorker1Init.sh
    cp ./GcpPrestoWorkerInit.sh ./GcpPrestoWorker2Init.sh

    sed -i "s/PRESTO_COORDINATOR_NAME/$PRESTO_COORDINATOR/g" ./GcpPrestoCoordinatorInit.sh
    sed -i "s/PRESTO_WORKER_NAME/$PRESTO_WORKER_1/g" ./GcpPrestoWorker1Init.sh
    sed -i "s/PRESTO_WORKER_NAME/$PRESTO_WORKER_2/g" ./GcpPrestoWorker2Init.sh

    gcloud compute scp ./GcpPrestoCoordinatorInit.sh ubuntu@$PRESTO_COORDINATOR:~/GcpPrestoCoordinatorInit.sh

    echo -e "\nSSH to Presto coordinator instance and run Init script"
    gcloud compute ssh ubuntu@$PRESTO_COORDINATOR \
        --command "sudo sh ~/GcpPrestoCoordinatorInit.sh"
        
    gcloud compute scp ./GcpPrestoWorker1Init.sh ubuntu@$PRESTO_WORKER_1:~/GcpPrestoWorkerInit.sh 
    echo -e "\nSSH to Presto worker-1 instance and run Init script"
    gcloud compute ssh ubuntu@$PRESTO_WORKER_1 \
        --command "sudo sh ~/GcpPrestoWorkerInit.sh"
        
    gcloud compute scp ./GcpPrestoWorker2Init.sh ubuntu@$PRESTO_WORKER_2:~/GcpPrestoWorkerInit.sh 
    echo -e "\nSSH to Presto worker-2 instance and run Init script"
    gcloud compute ssh ubuntu@$PRESTO_WORKER_2 \
        --command "sudo sh ~/GcpPrestoWorkerInit.sh"
}

install_apm()
{
    echo
    echo "-------------------------------------------------------------------------"
    echo "Install SnappyFlow components on GKE Cluster"
    echo "-------------------------------------------------------------------------"
    cat > ./$UNIQUE_NAME_PREFIX-apm-install.sh << 'EOF'
#!/bin/bash
## APM Installation script to run from bastion instance
echo "SnappyFlow Installation started"
sudo yum install -y kubectl git

curl -L https://get.helm.sh/helm-v3.0.1-linux-amd64.tar.gz | tar zxv
sudo chmod +x ./linux-amd64/helm
sudo mv ./linux-amd64/helm /usr/local/bin

gcloud container clusters get-credentials $CLUSTER \
    --zone $ZONE \
    --internal-ip
   
kubectl version

kubectl create ns apm 
kubectl create ns es 
kubectl create ns kafka 

#kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

kubectl create secret docker-registry snappyflowdockersecret \
    --docker-username=snappyflowml \
    --docker-password=85fcbdf0-1c90-47b0-abf9-6c4f808e8675 \
    --docker-email=admin@maplelabs.com \
    -n apm
    
kubectl create secret docker-registry snappyflowdockersecret \
    --docker-username=snappyflowml \
    --docker-password=85fcbdf0-1c90-47b0-abf9-6c4f808e8675 \
    --docker-email=admin@maplelabs.com \
    -n kafka

/usr/local/bin/helm repo add snappyflow https://snappyflow.github.io/helm-charts/
/usr/local/bin/helm repo update

/usr/local/bin/helm install ingress snappyflow/nginx-ingress \
    --set controller.service.type=NodePort

if [ "$ES_TYPE" = "internal" ]
then
    /usr/local/bin/helm install es snappyflow/elasticsearchv1 -n es
    ES_HOST=elasticsearch-master-headless.es
    ES_USER=""
    ES_PASS=""
else
    IP1=$(gcloud compute instances describe $ES1 --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    IP2=$(gcloud compute instances describe $ES2 --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    IP3=$(gcloud compute instances describe $ES3 --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    /usr/local/bin/helm install esnginx snappyflow/sfnginxv1 --set config.es1=$IP1 --set config.es2=$IP2 --set config.es3=$IP3
    ES_HOST=esnginx-sfnginxv1.default
    ES_USER=apmuser
    ES_PASS=apmpass
fi    

/usr/local/bin/helm install kafka snappyflow/kafka-cluster -n kafka

/usr/local/bin/helm install postgres snappyflow/postgresql \
    -n apm \
    --set multidb="snappyflow;vizbuilder;archival;hive_metastore" \
    --set multidbUser=snappyflow --set multidbUserPassord=maplelabs
kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=postgresql \
    -n apm \
    --timeout 300s

server_id=`kubectl get ns kube-system --output jsonpath='{.metadata.uid}'`
kafka_url="https://sf-datapath-nginx-ingress-controller.kafka:443"
arhive_url="$PRESTO_COORD_IP:8080"

#kubectl delete apiservice v1beta1.custom.metrics.k8s.io

git clone https://github.com/snappyflow/helm-charts -b gcp-dev


spark_bucket_name=spark-$RANDOM$RANDOM-hdfs
helm install archival ./helm-charts/charts/sf-archival \
    -n kafka \
    --set global.imagePullSecrets[0].name="snappyflowdockersecret" \
    --set global.secrets.aws.enable="false" \
    --set global.secrets.gcs.enable="true" \
    --set global.secrets.gcs.GCP_DEFAULT_REGION=$REGION \
    --set global.secrets.gcs.GCP_DEFAULT_ZONE=$ZONE \
    --set global.secrets.gcs.GCP_SERVICE_ACCOUNT_EMAIL=$SERVICE_ACCOUNT \
    --set global.snappyflowProjectName="snappyflow-app" \
    --set global.snappyflowAppName="archival" \
    --set spark-history-server.enabled="false" \
    --set spark-history-server.gcs.logDirectory="$spark_bucket_name/spark" \
    --set spark-manager.jobserver.sparkProperties.logDirectory="$spark_bucket_name/spark" \
    --set global.kafkaBrokers="kafka-cp-kafka-headless:9092" \
    --set global.postgresql.host="postgres-postgresql.apm" \
    --set global.postgresql.postgresqlUsername="snappyflow" \
    --set global.postgresql.postgresqlPassword="maplelabs" \
    --set global.postgresql.postgresqlDatabase="archival"

helm install sf-datapath ./helm-charts/charts/sf-datapath \
    -n kafka \
    --set global.imagePullSecrets[0].name=snappyflowdockersecret  \
    --set global.ingress.enabled="true" \
    --set global.snappyflowProjectName="snappyflow-app" \
    --set global.snappyflowAppName="sf-data-path"  \
    --set global.kafkaBrokers="kafka-cp-kafka-headless:9092" \
    --set global.postgresql.host="postgres-postgresql.apm" \
    --set global.postgresql.postgresqlUsername="snappyflow" \
    --set global.postgresql.postgresqlPassword="maplelabs" \
    --set global.sfAgentInput.host="$LB_IP" \
    --set global.secrets.aws.enable="false" \
    --set global.secrets.gcs.enable="true"

kubectl wait --for=condition=ready pod \
    -l release=sf-datapath \
    -n kafka \
    --timeout 100s

#kubectl delete apiservice v1beta1.custom.metrics.k8s.io
/usr/local/bin/helm install apm snappyflow/sfapm-python3 \
    -n apm \
    --set sfapmui.tls.enabled=false \
    --set imagePullSecrets[0].name=snappyflowdockersecret \
    --set sftrace.output.token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0IjoiYWRtaW4vYWRtaW4iLCJpc3MiOiJsb2dhcmNoaXZhbCJ9.Aqhl-amaKaKDoXDc0-8TN4hhI7FFkLa76GwDMBTmR8s" \
    --set sftrace.output.port=8082 \
    --set sftrace.output.host="sf-datapath-cp-kafka-rest-external.kafka" \
    --set sfapm.serverid=$server_id \
    --set sfapm.ingress.enabled=true \
    --set sfapm.ingress.es_host="$ES_HOST" \
    --set sfapm.ingress.es_port=9200 \
    --set sfapm.ingress.es_user="$ES_USER" \
    --set sfapm.ingress.es_pass="$ES_PASS" \
    --set sfapm.ingress.kafka_api=$kafka_url \
    --set sfapm.ingress.arhiver_url=$arhive_url \
    --set sfapm.ingress.kafka_user="control" \
    --set sfapm.ingress.kafka_pwd="admin321" \
    --set cloud.aws.enable=false \
    --set cloud.gcs.enable=true \
    --set cloud.gcs.region=$REGION \
    --set cloud.gcs.region=$ZONE \
    --set cloud.gcs.service_accoount=$SERVICE_ACCOUNT \
    --set postgresql.enabled=false \
    --set postgresql.external.dbHost="postgres-postgresql.apm" \
    --set postgresql.external.dbPort=5432 \
    --set postgresql.external.dbUser=snappyflow \
    --set postgresql.external.dbPassword=maplelabs

kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=sfapm-python3 \
    -n apm \
    --timeout 300s
echo "SnappyFlow Installation completed"
EOF

    chmod +x ./$UNIQUE_NAME_PREFIX-apm-install.sh
    gcloud compute scp ./$UNIQUE_NAME_PREFIX-apm-install.sh ubuntu@$BASTION_INSTANCE:~/apm-install.sh
    LB_IP=$(gcloud compute addresses describe $LB_IP_NAME --format="get(address)" --global)
    PRESTO_COORD_IP=$(gcloud compute instances describe $PRESTO_COORDINATOR --format='get(networkInterfaces[0].networkIP)' --zone $ZONE)
    echo -e "\nSSH to bastion instance and run SnappyFlow installations script"
    gcloud compute ssh ubuntu@$BASTION_INSTANCE \
        --command "LB_IP=$LB_IP CLUSTER=$CLUSTER SERVICE_ACCOUNT=$SERVICE_ACCOUNT ZONE=$ZONE REGION=$REGION ES_TYPE=$ES_TYPE ES1=$ES_INSTANCE_1 ES2=$ES_INSTANCE_2 ES3=$ES_INSTANCE_3 PRESTO_COORD_IP=$PRESTO_COORD_IP ./apm-install.sh"
    echo -e "\nStop bastion instance"
    gcloud compute instances stop $BASTION_INSTANCE

}

export_properties()
{
    cat > ./properties-$UNIQUE_NAME_PREFIX.sh << EOF
# setup details
UNIQUE_NAME_PREFIX=$UNIQUE_NAME_PREFIX
REGION=$REGION
ZONE=$ZONE
PROJECT_ID=$PROJECT_ID
CLUSTER=$CLUSTER
CLUSTER_NODE_TAG=$CLUSTER_NODE_TAG
NETWORK=$NETWORK
SUBNET=$SUBNET
BASTION_INSTANCE=$BASTION_INSTANCE
NAT_ROUTER=$NAT_ROUTER
NAT=$NAT
SSH_FIREWALL=$SSH_FIREWALL
SFAPM_FIREWALL=$SFAPM_FIREWALL
K8S_MASTER_FIREWALL=$K8S_MASTER_FIREWALL

#LB details
HEALTHCHECK_FIREWALL=$HEALTHCHECK_FIREWALL
LB_IP_NAME=$LB_IP_NAME
HEALTHCHECK_NAME=$HEALTHCHECK_NAME
LB_BACKEND_SERVICE=$LB_BACKEND_SERVICE
LB_NAME=$LB_NAME
LB_SSL_CERT_NAME=$LB_SSL_CERT_NAME
LB_HTTPS_PROXY=$LB_HTTPS_PROXY
LB_HTTPS_FORWARDING_RULE=$LB_HTTPS_FORWARDING_RULE

# ES details
ES_INSTANCE_1=$ES_INSTANCE_1
ES_INSTANCE_2=$ES_INSTANCE_2
ES_INSTANCE_3=$ES_INSTANCE_3
ES_NODE_TAG=$ES_NODE_TAG
ES_FIREWALL=$ES_FIREWALL
ES_TYPE=$ES_TYPE

# Presto nodes
PRESTO_COORDINATOR=$PRESTO_COORDINATOR
PRESTO_WORKER_1=$PRESTO_WORKER_1
PRESTO_WORKER_2=$PRESTO_WORKER_2
PRESTO_NODE_TAG=$PRESTO_NODE_TAG
PRESTO_FIREWALL=$PRESTO_FIREWALL
PRESTO_CLUSTER_FIREWALL=$PRESTO_CLUSTER_FIREWALL

NEW_SERVICE_ACCOUNT=$NEW_SERVICE_ACCOUNT
SERVICE_ACCOUNT=$SERVICE_ACCOUNT

SERVICE_ACCOUNT_KEY_ID=$(cat ./$UNIQUE_NAME_PREFIX-sa-key.json | grep private_key_id | cut -d '"' -f 4)

EOF

}

echo
echo "-------------------------------------------------------------------------"
echo "Start On-Premise SnappyFlow Installation on GKE Cluster"
echo "-------------------------------------------------------------------------"

gcloud_init

NEW_SERVICE_ACCOUNT="false"
if [ "$NEW_SERVICE_ACCOUNT" = "true" ]
then
    create_service_account
fi
set_service_account_permission
export_properties
setup_network
create_bastion_instance
create_presto_instances
create_es_instances
create_gke_setup
setup_loadbalancer
setup_presto
setup_external_elasticsearch
install_apm
echo
echo "-------------------------------------------------------------------------"
echo "Completed On-Premise SnappyFlow Installation on GKE Cluster"
echo
echo "SnappyFlow Portal: https://$LB_IP"
echo
echo "-------------------------------------------------------------------------"

exit 0
