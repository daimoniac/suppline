{{/*
Expand the name of the chart.
*/}}
{{- define "suppline.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "suppline.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "suppline.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "suppline.labels" -}}
helm.sh/chart: {{ include "suppline.chart" . }}
{{ include "suppline.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "suppline.selectorLabels" -}}
app.kubernetes.io/name: {{ include "suppline.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "suppline.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "suppline.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "suppline.frontend.labels" -}}
helm.sh/chart: {{ include "suppline.chart" . }}
{{ include "suppline.frontend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: web-ui
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "suppline.frontend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "suppline.name" . }}-ui
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Generate registry URL based on release name
*/}}
{{- define "suppline.registryURL" -}}
{{- printf "%s-registry:%d" .Release.Name (.Values.registry.service.port | int) }}
{{- end }}

{{/*
Generate or use registry username
*/}}
{{- define "suppline.registryUsername" -}}
{{- if and .Values.registry.credentials .Values.registry.credentials.username }}
{{- .Values.registry.credentials.username }}
{{- else }}
{{- "suppline" }}
{{- end }}
{{- end }}

{{/*
Generate or use registry password
*/}}
{{- define "suppline.registryPassword" -}}
{{- if and .Values.registry.credentials .Values.registry.credentials.password }}
{{- .Values.registry.credentials.password }}
{{- else }}
{{- randAlphaNum 32 }}
{{- end }}
{{- end }}

{{/*
Fetch registry certificate init container
Fetches TLS certificate from the registry and creates a CA bundle
Used by both backend (statefulset) and regsync (deployment)
*/}}
{{- define "suppline.registryCertInitContainer" -}}
- name: fetch-registry-cert
  image: alpine/openssl:latest
  imagePullPolicy: IfNotPresent
  command:
    - /bin/sh
    - -c
    - |
      echo "Waiting for registry to be ready and fetching certificate..."
      
      # Try to fetch certificate, retry until success
      retry_count=0
      max_retries=60
      while [ $retry_count -lt $max_retries ]; do
        echo "Attempt $((retry_count + 1))/$max_retries: Fetching registry certificate..."
        
        # Use openssl to get the server certificate (first cert only)
        if echo | timeout 5 openssl s_client -connect {{ include "suppline.fullname" . }}-registry:{{ .Values.registry.service.port }} -showcerts 2>/dev/null | \
          awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print; if (/END CERTIFICATE/) exit}' > /certs/registry.crt && \
          [ -s /certs/registry.crt ]; then
          echo "Registry certificate fetched successfully"
          break
        fi
        
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
          echo "Failed to fetch certificate, retrying in 2 seconds..."
          sleep 2
        fi
      done
      
      # Verify we got the certificate
      if [ ! -s /certs/registry.crt ]; then
        echo "ERROR: Failed to fetch registry certificate after $max_retries attempts"
        exit 1
      fi
      
      echo "Certificate content:"
      cat /certs/registry.crt
      
      # Create CA bundle with system certs + registry cert
      if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
        cat /etc/ssl/certs/ca-certificates.crt > /certs/ca-bundle.crt
      elif [ -f /etc/ssl/cert.pem ]; then
        cat /etc/ssl/cert.pem > /certs/ca-bundle.crt
      elif [ -d /etc/ssl/certs ]; then
        cat /etc/ssl/certs/*.pem > /certs/ca-bundle.crt 2>/dev/null || cat /etc/ssl/certs/*.crt > /certs/ca-bundle.crt 2>/dev/null || touch /certs/ca-bundle.crt
      else
        touch /certs/ca-bundle.crt
      fi
      
      # Append registry cert
      cat /certs/registry.crt >> /certs/ca-bundle.crt
      
      echo "CA bundle created successfully with $(wc -l < /certs/ca-bundle.crt) lines"
  volumeMounts:
    - name: registry-cert
      mountPath: /certs
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: false
    capabilities:
      drop:
        - ALL
{{- end }}
