#!/bin/bash
#  * Copyright(c)2021 MapleLabs Inc
#  *
#  * This Shell script uninstalls snappyflow from Google Kubenetes Engine
#  *
ENV_FILE=$1
if [ ! -f $1 ]
then
    echo "SnappyFlow installation properties file $1 not found"
    exit 0
fi
source $1
LOG_FILE=$UNIQUE_NAME_PREFIX-cleanup.log
exec > >(tee $LOG_FILE) 2>&1
exec 2> >(tee $LOG_FILE) 2>&1

gcloud config set project $PROJECT_ID
gcloud config set compute/region $REGION
gcloud config set compute/zone $ZONE

uninstall_snappyflow() {
    echo "Uninstall SnappyFlow Components"
cat > ./$UNIQUE_NAME_PREFIX-apm-cleanup.sh << 'EOF'
#!/bin/bash
helm delete apm -n apm
helm delete -n kafka kafka archival sf-datapath
if [ "$ES_TYPE" = "internal" ]
then
    helm delete -n es es
else
    helm delete esnginx
fi
helm delete -n apm postgres
helm delete ingress
#kubectl delete -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
EOF

    chmod +x ./$UNIQUE_NAME_PREFIX-apm-cleanup.sh
    gcloud compute instances start $BASTION_INSTANCE
    sleep 30
    gcloud compute config-ssh --quiet
    gcloud compute scp ./$UNIQUE_NAME_PREFIX-apm-cleanup.sh ubuntu@$BASTION_INSTANCE:~/apm-cleanup.sh
    gcloud compute ssh ubuntu@$BASTION_INSTANCE --command "ES_TYPE=$ES_TYPE ./apm-cleanup.sh"
}

delete_lb()
{
    echo "Delete Load Balancer Components"
    gcloud compute forwarding-rules delete $LB_HTTPS_FORWARDING_RULE --quiet --global
    gcloud compute target-https-proxies delete $LB_HTTPS_PROXY --global --quiet
    gcloud compute url-maps delete $LB_NAME --global --quiet
    gcloud compute backend-services delete $LB_BACKEND_SERVICE --global --quiet
    gcloud compute health-checks delete $HEALTHCHECK_NAME --quiet
    gcloud compute ssl-certificates delete $LB_SSL_CERT_NAME --quiet --global
    gcloud compute addresses delete $LB_IP_NAME --quiet --global
}

delete_setup()
{
    echo "Delete GKE, BASTION and networks setup"
    gcloud container clusters delete $CLUSTER --zone=$ZONE --quiet
    gcloud compute instances delete $BASTION_INSTANCE --quiet
    gcloud compute firewall-rules delete $SFAPM_FIREWALL --quiet 
    gcloud compute firewall-rules delete $SSH_FIREWALL --quiet
    gcloud compute firewall-rules delete $HEALTHCHECK_FIREWALL --quiet
    gcloud compute firewall-rules delete $K8S_MASTER_FIREWALL --quiet
    gcloud compute routers nats delete $NAT --router $NAT_ROUTER --quiet
    gcloud compute routers delete $NAT_ROUTER --quiet
    gcloud compute networks subnets delete $SUBNET --quiet
    gcloud compute networks delete $NETWORK --quiet
    disknames=$(gcloud compute disks list --filter="name~'gke-'" --zones $ZONE --uri | grep $CLUSTER)
    if [[ $disknames ]]
    then
        gcloud compute disks delete $disknames --zone $ZONE --quiet
    fi
}

delete_external_es()
{
    echo "Delete external Elasticsearch"
    gcloud compute firewall-rules delete $ES_FIREWALL --quiet 
    gcloud compute instances delete $ES_INSTANCE_1 --quiet
    gcloud compute instances delete $ES_INSTANCE_2 --quiet
    gcloud compute instances delete $ES_INSTANCE_3 --quiet
}

delete_presto_setup()
{
    echo "Delete presto setup"
    gcloud iam service-accounts keys delete $SERVICE_ACCOUNT_KEY_ID --iam-account=$SERVICE_ACCOUNT --quiet
    gcloud compute firewall-rules delete $PRESTO_FIREWALL --quiet 
    gcloud compute firewall-rules delete $PRESTO_CLUSTER_FIREWALL --quiet 
    gcloud compute instances delete $PRESTO_COORDINATOR --quiet
    gcloud compute instances delete $PRESTO_WORKER_1 --quiet
    gcloud compute instances delete $PRESTO_WORKER_2 --quiet
}

echo "Cleanup starts"
uninstall_snappyflow
if [ "$ES_TYPE" = "external" ]
then
    delete_external_es
fi
delete_presto_setup
delete_lb
delete_setup
