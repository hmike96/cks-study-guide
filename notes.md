# CKS Study Guide

### 1. Network Policies
   
   1. Default Deny all Egress
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny-egress
   spec:
     podSelector: {}
     policyTypes:
     - Egress 
   ```
   
   2. Default Allow all Egress and Ingress
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: allow-all-egress
   spec:
     podSelector: {}
     egress:
     - {}
     ingress:
     - {}
     policyTypes:
     - Egress
   ```
   3. Commands to run
   ```bash
   $ k explain NetworkPolicy.spec.egress;
   $ k explain NetworkPolicy.spec.ingress;
   ```

### 2. Verify Platform Binaries
   
   1. Command to get sha of binary 
   ```bash
   $ sha512sum ${BINARY_NAME};
   ```
   2. Compare lines in a text file seperated by new lines
   ```bash 
   $ cat ${FILE} | uniq; 
   ```
   3. Kubernetes binaries located in ```kubernetes/server/bin```
   4. Compare sha512 of binaries located in ```kubernetes/server/bin``` and docker images binary
   5. Run the following to copy docker image file system locally
   ```bash
   $ docker cp ${IMAGE_HASH}:/ ${LOCAL_DIR_NAME}
   ``` 
### 3. RBAC 
   1. Create a role imperatively
   ```bash
   $ k create role secret-manager --verb=get --resources=secrets -n red -oyaml --dry-run=client > role.yaml
   ```
   2. Create roleBinding imperatively
   ```bash
   k create rolebinding secret-manager --role=secret-manager --user=jane -n red -oyaml --dry-run=client > role_binding.yaml
   ``` 
   3. RoleBinding can bind a subject to a role in another namespace
   4. Check if user has role
   ```bash
   k -n red auth can-i get secrets --as jane
   ```
   5. Create cluster role
   ```bash
   k create clusterrole --verb=delete --resource=deployments
   ```
   6. Can not assign ClusterRoleBinding to a Role but can assigned ClusterRole a RoleBinding
   7. Users in Kubernetes must have a certificate signed by Kubernetes CA with cert CN equal to the Users username in K8S.
   8. No way to remove a Kubernetes certificate; would have to do one of three things
      1. Remove all access via RBAC
      2. Username cannot be used until cert expired
      3. Create new CA; reissue certs
   9. Certificate Signing request for kube user
   ```yaml
   apiVersion: certificates.k8s.io/v1
   kind: CertificateSigningRequest
   metadata:
     name: john
   spec:
     groups:
     - system:authenticated
     request: ${BASE64_ENCODED_CLIENT_CERT}
     signerName: kubernetes.io/kube-apiserver-client
     usages:
     - client auth 
   ```
   10. Approve a certificate with the following command
   ```bash
   k certificate approve ${CERTIFICATE_NAME} 
   ```
   11. Test auth for service accounts 
   ```bash
   k auth can-i delete secrets --as system:serviceaccount:default:accessor
   ```
   12. Turn of automount of service account token with po.spec.automountServiceAccountToken or sa.spec.automountServiceAccountToken
### 4. Restrict API Access
   1. To configure this on kube-api server configure the following arguement in the pod. 
   ```bash
   --anonymous-auth=true|false
   ```
   2. Anonymous user is known as system:anonymous
   3. Needed for liveness probe ^^
   4. Kube API server ```--insecure-port=8080``` (deprecated in 1.20)
   5. Admission Controller plugin for Node Restrictions
      1. prevents secure labels from being set on nodes from kubelet 
      2. kubelet cant set ```node-restriction.kubernetes.io/{text}``` node label key
      ```bash 
      --enable-admission-plugins=NodeRestrictions 
      ```
### 5. Node Upgrades
TBC
### 6. Creating and Mounting Secrets 
   1. Hack secrets in Docker by running the following command then checking for env vars
   ```bash
   docker inspect ${CONTAINER_ID} 
   ```  
   2. Hack etcd to get unencrypted secrets
   ```bash
   ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/apiserver-etcd-client.crt --key /etc/kubernetes/pki/apiserver-etcd-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/default/secret2
   ```
   3. Command to rewrite all secrets
   ```bash
   k get secrets -A -o json | k replace -f -
   ```
   4. For Kubernetes EncryptianConfiguration resource, the first provider in resources.resources[].providers is the algorithm to encrypt new secrets. The rest are for read enablement.
   5. If the provider for and existing secrets encryptian is not in the EncryptianConfigurations list of providers, it cannot be read.
   6. Unencrypted secrets are under the ```identity: {}``` provider
   7. Example of EncryptianConfiguration resources
   ```yaml
   apiVersion: apiserver.config.k8s.io/v1
   kind: EncryptionConfiguration
   resources:
   - resources:
      - secrets
      providers:
      - identity: {}
      - aescbc:
         keys:
         - name: key1
            secret: <BASE 64 ENCODED SECRET>
   ```
   8. To enable the EncryptianConfiguration resource in the Kube API server add following config
   ```bash
   encryptian-provider-config=/etc/kubernetes/etcd/ec.yaml
   ```
   9. Make sure to also mount EncryptianConfiguration yaml in API Server from master node with the following snippets of manifest
   
   ```yaml
   ...
   volumeMounts:
   - mountPath: /etc/kubernetes/etcd
     name: etcd
     readOnly: true
   ...
   volumes:
   - hostPath:
       path: /etc/kubernetes/etcd
       type: DirectoryOrCreate
     name: etcd
   ...
   ```
   10. Best practice is to encrypt using aescbc.
### 7. Container Runtime Sandboxes 
   1. Linux Commands
      1. The follow command prints out syscalls made in linux command
      ```bash
      $ strace ${LINUX_COMMAND}
      ```
   2. Runtime Class Resources
   ```yaml
   apiVersion: node.k8s.io/v1  # RuntimeClass is defined in the node.k8s.io API group
   kind: RuntimeClass
   metadata:
     name: myclass  # The name the RuntimeClass will be referenced by
   # RuntimeClass is a non-namespaced resource
   handler: myconfiguration  # The name of the corresponding CRI configuration ex. runsc for gvisor
   ```
   3. Specify Runtime Class in a Pod manifests as follows
   ```yaml
   ...
   spec:
     runtimeClassName: myclass
     ...
   ```
### 8. Security Contexts
   1. 