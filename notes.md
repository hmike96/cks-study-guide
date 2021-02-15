# CKS Study Guide

## Cluster Setup

### Network Policies
   
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
### Secure Ingress
   1. Create a tls secret for ingress
   ```bash
   $ k create secret tls secure-ingress --cert=cert.pem --key=key.pem
   ``` 
   2. Secure ingress with tls specifying secret
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: tls-example-ingress
   spec:
     tls:
       - hosts:
         - https-example.foo.com
         secretName: testsecret-tls
     rules:
       - host: https-example.foo.com
         http:
           paths:
             - path: /
               pathType: Prefix
               backend:
                 service:
                   name: service1
                   port:
                     number: 80
   ```
### Verify Platform Binaries
   
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
## Cluster Hardening

### RBAC 
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
   6. Can not assign ClusterRoleBinding to a Role but a ClusterRole can be assigned through a RoleBinding
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
### Restrict API Access
   1. To configure this on kube-api server configure the following arguement in the pod. (Needed for liveness probe)
   ```bash
   --anonymous-auth=true|false
   ```
   2. Anonymous user is known as system:anonymous 
   3. Kube API server ```--insecure-port=8080``` (deprecated in 1.20)
   4. Admission Controller plugin for Node Restrictions
      1. prevents kubelet from setting secure labels on nodes 
      2. kubelet cant set ```node-restriction.kubernetes.io/{text}``` node label key
   5. Enable setting in Kube Api Server
   ```yaml
   ...
   containers:
     - command:
       - kube-apiserver
       - --enable-admission-plugins=NodeRestrictions
       ... 
   ```
### Node Upgrades
TBC

## Microservice Vulnerabilities 

### Manage Kubernetes Secrets

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
   ```yaml
   ...
   containers:
     - command:
       - kube-apiserver
       - --encryptian-provider-config=/etc/kubernetes/etcd/ec.yaml
       ... 
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
   10.  Best practice is to encrypt using aescbc.
   
### Container Runtime Sandboxes 

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
   1. Specify Runtime Class in a Pod manifests as follows
   ```yaml
   ...
   spec:
     runtimeClassName: myclass
     ...
   ```
### OS Level Security Domains
   1. Check uid, gid, and groups of current user 
   ```bash
   $ id
   ```
   2. disable run as root from container (will cause bug if container needs to run as root)
   ```yaml
   ...
   spec:
     containers:
       - 
       :
           runAsNonRoot: true
         ...  
   ```
   3. Privileged Container: container user 0 (root) is mapped to host user 0 (root)
   4. run kubernetes pods container as privileged
   ```yaml
   ...
   spec:
     containers:
       - 
       :
           privileged: true
         ...  
   ```
   5. PrivilegedEscalation: process can gain more privileges than its parents process
   6. Disable privileged escalation in pods container
   ```yaml
   ...
   spec:
     containers:
       - 
       :
           allowPrivilegeEscalation: true
         ...  
   ```
   7. Enable PodSecurityPolicy kubernetes admission webhook in Kube API Server
   ```yaml
   ...
   containers:
     - command:
       - kube-apiserver
       - --enable-admission-plugins=NodeRestrictions
       ... 
   ```
   8. Example PodSecurityPolicy
   ```yaml
   apiVersion: policy/v1beta1
   kind: PodSecurityPolicy
   metadata:
     name: example
   spec:
     allowPrivilegedEscalation: false
     privileged: false  # Don't allow privileged pods!
     # The rest fills in some required fields.
     seLinux:
       rule: RunAsAny
     supplementalGroups:
       rule: RunAsAny
     runAsUser:
       rule: RunAsAny
     fsGroup:
       rule: RunAsAny
     volumes:
       - '*'
   ```
   9. PodSecurityPolicy does nothing by default. To enable a target pods service account must have role to use the podsecuritypolicy resources
### mTLS 
   1. You must configure iptables to forward app containers traffic to the side car proxy container to handle tls
   2. Require security context capability to manipulate ip tables.
   ```yaml 
   ...
   spec:
   containers:
      - 
      :
         capabilities:
            add: ["NET_ADMIN"]
         ...
   ```
## OPA
   1. OPA Gatekeeper uses ConstraintTemplate K8S custom resources to create k8s Constraint resources.
   2. When enabling OPA gatekeeper only api server admission plugin enabled should be NodeRestriction.
   3. Constraints wont remove existing violating resources just mark them as violating when you describe the constraint.
   4. Example of a ConstraintTemplate Custom Resources. Policy Requires set of labels on resources.
   ```yaml 
   apiVersion: templates.gatekeeper.sh/v1beta1
   kind: ConstraintTemplate
   metadata:
     name: k8srequiredlabels
   spec:
     crd:
       spec:
         names:
           kind: K8sRequiredLabels
         validation:
           # Schema for the `parameters` field
           openAPIV3Schema:
             properties:
               labels:
                 type: array
                 items: string
      targets:
        - target: admission.k8s.gatekeeper.sh
          rego: |
            package k8srequiredlabels

            violation[{"msg": msg, "details": {"missing_labels": missing}}] {
              provided := {label | input.review.object.metadata.labels[label]}
              required := {label | label := input.parameters.labels[_]}
              missing := required - provided
              count(missing) > 0
            msg := sprintf("you must provide labels: %v", [missing])
            }
   ```
   5. Example of a Constraint create based on ConstraintTemplate above. Validates namespaces have cks label.
   ```yaml
   apiVersion: constraints.gatekeeper.sh/v1beta1
   kind: K8sRequiredLabels
   metadata:
     name: ns-must-have-cks
   spec:
     match:
       kinds:
         - apiGroups: [""]
           kinds: ["Namespace"]
     parameters:
       labels: ["cks"]
   ```
   6. Notice ConstraintTemplate properties defines parameters you must enter in the Constraint
   
## Supply Chain Security

### Image Footprint (Multi-Stage builds)
   1. To reference previous stage in dockerfile that is not aliased use the following. (example using COPY)
   ```Dockerfile
   FROM ubuntu
   ...
   FROM alpine 
   COPY --from=0 /app .
   ...
   ```
   2. Install and use proper(specific) versions of dependencies and base images.
   3. Do not run as root in Dockerfile, here is an example of avoiding this.
   ```dockerfile
   RUN addgroup -S appgroup && adduser -S appuser -G appgroup -h /home/appuser
   COPY --from=0 /app /home/appuser/
   USER appuser
   ```
   4. Make filesystem as readonly as possible
   ```dockerfile
   RUN chmod a-w /etc
   ```
   5. Remove shell access
   ```dockerfile
   RUN rm -rf /bin/*
   ```
### Static Analysis
   1. Can execute in various pieces of CI/CD pipeline.
      * Git webhook before code commit
      * Right before build
      * Right before testing
      * Live using things like OPA or PSP
   2. Kubesec: static analysis for K8S 
      * Can run as the following 
        * Binary
        * Docker Container
        * Kubectl plugin
        * Admission Controller(kubesec-webhook)
   3. Example of using Kubesec through docker 
   ```bash
   docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < pod.yaml
   ```
   4. OPA conftest for static analysis of K8S manifest and docker files.
### Scanning Images for Known Vulnerabilites
   1. Clair: Preforms static analysis of vulnerabilities in app containers
      * Provides API (not one command run)
      * Ingest vulnerability metadata from configured set of sources
   2. Trivy: simple vulnerability scanner for containers and other artifacts, suitable in CI
### Secure Supply Chain
   1. Use Docker image digest as image identity
   2. ImagePolicyWebhooks use CR called ImageReview to validate image is from a valid registry in k8s.
   3. To enable Image Policy Webhook add to Kube API Server manifest
   ```yaml
   ...
   containers:
     - command:
       - kube-apiserver
       - --enable-admission-plugins=ImagePolicyWebhook
       - --admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
       ... 
   ```
   4. The configuration file for the admission policy webhook (make sure pki is absolute dir in the kubeconf file) Make sure to mount this to api-server
   ```yaml
   apiVersion: apiserver.config.k8s.io/v1
   kind: AdmissionConfiguration
   plugins:
     - name: ImagePolicyWebhook
       configuration:
         imagePolicy:
           kubeConfigFile: /etc/kubernetes/admission/kubeconf
           allowTTL: 50
           denyTTL: 50
           retryBackoff: 500
           defaultAllow: false
   ```
   kubeconf file
   ```yaml
   apiVersion: v1
   kind: Config

   # clusters refers to the remote service.
   clusters:
   - cluster:
      certificate-authority: /etc/kubernetes/admission/external-cert.pem  # CA for verifying the remote service.
      server: https://external-service:1234/check-image                   # URL of remote service to query. Must use 'https'.
     name: image-checker

   contexts:
   - context:
       cluster: image-checker
       user: api-server
     name: image-checker
   current-context: image-checker
   preferences: {}

   # users refers to the API server's webhook configuration.
   users:
   - name: api-server
       user:
         client-certificate: /etc/kubernetes/admission/apiserver-client-cert.pem     # cert for the webhook admission controller to use
         client-key:  /etc/kubernetes/admission/apiserver-client-key.pem             # key matching the cert
   ```
## Runtime Security 

### Behavioral Analytics at host and container level

1. /proc directory is a secure directory in linux with info on processes
   * Info and connection to processes and kernal
   * configuration and administrative tasks
   * contains files that dont exist yet you access
2. find etcd process with ```ps aux | grep etcd```
3. Use strace to find a process with ```strace -p ${PROCESS_ID}``` (-f to follow, forks as well)
4. use /proc to find processes info with the following path /proc/${PROCESS_ID} (cd fd then ls -lh)
5. ```tail -f 7``` to follow the /proc/${PROCESS_ID}/fd files, find a secret using ```cat ${fd} | grep ${SECRET}```
6. /proc has environ file with environment variables

### Falco

1. Find configuration for Falco in ```/etc/falco``` directory
2. default output logs is to ```/var/log/syslog```
3. falco .local rules override the nodes general falco_rules
4. rules files contain two main properties a list of rules,  ```rule```, and a list of macros, ```macro```
5. macro can be called in a rule condition.
6. ```grep -r "rule describe" .``` in /etc/falco directory to find location of rule fast

### Immutability 

1. Use startup probes to modify container state only 
2. Use to set readOnlyFileSystem (emptyDir are writable)
   ```yaml
   ...
   containers:
   - ...
     securityContext:
       readOnlyRootFilesystem: true
   ``` 

### Auditing 

1. Different stages in Kubernetes logging: (Comes from property omitStages)
   * RequestRecieved
   * ResponseStarted
   * ResponseComplete 
   * Panic
2. Levels of data in each logging stage:
   * None
   * Metadata
   * Request
   * RequestResponse
3. Event Content consists of Kubernetes resources to be audited.
4. Enable auditing in Kube API Server (Remember to mount /etc/kubernetes/audit as host path volume)
   ```yaml 
   spec:
     containers:
     - command:
       - kube-apiserver
       - --audit-policy-file=/etc/kubernetes/audit/policy.yaml       # add
       - --audit-log-path=/etc/kubernetes/audit/logs/audit.log       # add
       - --audit-log-maxsize=500                                     # add
       - --audit-log-maxbackup=5                                     # add
   ```
5. Steps to change audit policy in Kubernetes Cluster
   * Change policy yaml configuration file
   * Disable Auditing in Kube API Server (Comment out ```audit-policy-file``` config)
   * Enable auditing in Kube API Server (if doesnt restart check logs in /var/log/pods/kube-system_kube-apiserver)
   * Test changes
### Kernal Hardening Tools
#### AppArmor
1. App armor is a tool that monitors and restricts kernal calls for process through profiles
2. Types of Profiles
   * Unconfined: Process can escape the restrictions
   * Complain: Process can escape but is logged
   * Enforce: Process cannot escape
3. App Armor commands:
   * Show all profiles: ```aa-status```
   * Generate new Profile: ```aa-genprof ${SHELL_COMMAND}```
   * Put a Profile: ```aa-complain```
   * Put profile in Enforce mode: ```aa-enforce```
   * Update Profile based on application needs: ```aa-logprof```
4. Profiles located in ```/etc/apparmor.d```
5. Run ```aa-logprod``` after generating a Profile and running a command
6. Run ```aa-parser``` on new Profile file added to ```/etc/apparmor.d```
7. Specify apparmor with docker
   ```bash
   docker run --security-opt apparmor=docker-default nginx
   ```
8. How to run app armor on K8S
   * Container Runtime must support app armor
   * AppArmor needs to be installed on every node
   * profile must be on every node.
   * profiles specified per container using annotations

#### Seccomp 

1. Restricts the use of specific sys calls and will sig kill attempted to use.
2. Specify seccomp with docker
   ```bash
   docker run --security-opt seccomp=default.json nginx
   ```
3. Setting seccomp profile location for kubelet ```--secomp-profile-root=DIR```
4. Can specify in annotations or in securityContext
### Reduce Attack Surface

1. Find a service running ```systemctl list-units --type=service --state=running | grep SERVICE```
2. Find services network intefaces are using ```netstat -plnt | grep PORT|SERVICE```
3. Check linux users ```whoami```
4. switch users with ```su USER```
   